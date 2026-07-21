"""shadow/pr_action.py: orchestrates the Muninn Context Receipt GitHub
Action end to end for one `pull_request` event.

THIS IS THE PUBLIC, SERVER-MODE-ONLY CLIENT. It contains no scoring engine
and cannot score anything locally. It only assembles a REDACTED, SIGNED
fingerprint bundle from the repo and hands scoring to a configured server
(MUNINN_SERVER_URL). If MUNINN_SERVER_URL is not configured, run() exits
with an error instead of attempting to score anything in this job.

    1. detect_ai_authored()   pure decision function: is this PR AI-authored,
                              per a CONFIGURABLE signal (a label, an author
                              glob, or a commit-trailer marker)? No I/O.
    2. build_server_receipt() assemble + sign a redacted fingerprint bundle
                              (shadow.bundle / shadow.signing) over the
                              repo's context surfaces and hand scoring to
                              the configured server (shadow.server_client);
                              it renders only what a VERIFIED server-signed
                              receipt returned, never scores anything
                              in-process.
    3. shadow.gh_client       the ONE module that talks to GitHub. main()
                              below is the only caller that constructs a
                              real GitHubClient; every other function here
                              takes a client as a parameter so a test can
                              hand it a fake and assert zero network calls.

A non-AI-authored PR returns before build_server_receipt() or the GitHub
client is even touched -- no comment, no API call, matching the Action's
design goal that nothing about a human-authored PR's review changes.

SERVER MODE ONLY: run() requires MUNINN_SERVER_URL. The client generates or
loads its own signing keypair (shadow.signing), assembles + signs a bundle
(shadow.bundle, shadow.signing), and calls shadow.server_client, which
verifies the server's own signature on the returned receipt before handing
it back. Two distinct failure postures, both required by the wedge running
unattended in a customer's CI (see shadow.server_client's module docstring
for the full reasoning):
  - server unreachable/timeout/non-2xx/malformed response (shadow.
    server_client.NoReceipt): log it, post no comment, return 0 -- the
    customer's CI job must never fail because the scoring server had a bad
    moment.
  - a receipt-shaped response whose signature does NOT verify (shadow.
    server_client.ServerSignatureError): refuse to post anything, return 1
    -- this is a security event (a forged/corrupted receipt, or a
    misconfigured pinned key), never a soft skip.
"""
from __future__ import annotations

import fnmatch
import json
import os
import pathlib
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple

_HERE = pathlib.Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from shadow._bundle_primitives import resolve_now  # noqa: E402
from shadow import receipt as receipt_mod  # noqa: E402
from shadow import server_client        # noqa: E402
from shadow import signing              # noqa: E402
from shadow.gh_client import GitHubClient, upsert_comment  # noqa: E402

# NOTE: shadow.bundle is intentionally NOT imported at module level here --
# shadow/bundle.py itself imports DEFAULT_AI_AUTHOR_GLOB/DEFAULT_AI_LABEL/
# DEFAULT_AI_TRAILER/detect_ai_authored FROM this module, so a top-level
# `from shadow import bundle` here would be a circular import. It is
# imported lazily inside build_server_receipt() instead, the only function
# that needs it.
#
# This public client never imports a scoring engine at all, at module level
# or otherwise: it has no local scoring mode. `import shadow.pr_action`
# always succeeds with only the files that ship in this repo present -- see
# the module docstring.

# Defaults for the three CONFIGURABLE AI-authorship signals. Any of the
# three may be turned off by passing an empty string; label detection is on
# by default (matches action.yml's own default input), the other two are
# off by default until a caller opts in.
DEFAULT_AI_LABEL = "ai-authored"
DEFAULT_AI_AUTHOR_GLOB = ""
DEFAULT_AI_TRAILER = ""


def detect_ai_authored(pr: Dict[str, Any], commit_message: str, *,
                       label: str = DEFAULT_AI_LABEL,
                       author_glob: str = DEFAULT_AI_AUTHOR_GLOB,
                       trailer: str = DEFAULT_AI_TRAILER,
                       ) -> Tuple[bool, str]:
    """Pure, no I/O. `pr` is the pull_request object from the GitHub
    webhook event payload. Checks, in order, whichever signals are
    non-empty; the first match wins and is named in the reason string.

    - label: exact, case-insensitive match against the PR's label names
      (never a substring match -- a PR labeled "ai-authored-experiment"
      must NOT match a configured label of "ai-authored").
    - author_glob: comma-separated fnmatch pattern(s) matched against the PR
      author's login (e.g. "*-bot,claude[bot]").
    - trailer: substring match against the PR head commit's full message
      (e.g. a "Co-Authored-By: Claude" trailer some agentic workflows add).
    """
    if label:
        wanted = label.strip().lower()
        names = {(entry.get("name") or "").strip().lower()
                for entry in (pr.get("labels") or [])}
        if wanted in names:
            return True, f"label '{label}' present on the PR"
    if author_glob:
        login = ((pr.get("user") or {}).get("login") or "")
        for pattern in (g.strip() for g in author_glob.split(",")):
            if pattern and fnmatch.fnmatchcase(login, pattern):
                return True, f"author '{login}' matches glob '{pattern}'"
    if trailer:
        if trailer in (commit_message or ""):
            return True, f"head commit message contains trailer '{trailer}'"
    return False, "no configured AI-authored signal matched"


def read_head_commit_message(sha: str, cwd: str) -> str:
    """Local `git log`, not a GitHub API call: the Action always runs on a
    real checkout of the PR head (actions/checkout), so the commit message
    is already on disk. Returns "" (never raises) if the sha or repo is not
    resolvable, so a caller with no trailer configured never pays this cost
    and a caller that DOES configure one fails safe (no match) rather than
    aborting the run."""
    if not sha:
        return ""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%B", sha],
            check=True, capture_output=True, text=True, cwd=cwd)
        return result.stdout
    except Exception:
        return ""


def build_server_receipt(
    vault: pathlib.Path, *,
    pr: Dict[str, Any], commit_message: str,
    ai_label: str, ai_author_glob: str, ai_trailer: str,
    server_url: str, server_public_key_pem: bytes,
    client_key_id: str = "", client_private_key_pem: bytes = b"",
    now: Optional[str] = None,
) -> Optional[str]:
    """SERVER MODE's build step: assemble + sign a redacted fingerprint
    bundle over `vault`, then hand scoring to the configured server
    (shadow.server_client). This client never scores anything itself.
    Local reads only to ASSEMBLE the bundle; the one network call is
    inside shadow.server_client.submit_envelope().

    Returns the rendered receipt Markdown on success, or None if no receipt
    is available this run (shadow.server_client.NoReceipt -- server
    unreachable, timed out, returned a non-2xx, or returned a malformed
    body). Raises shadow.server_client.ServerSignatureError if the server
    responded but its signature does not verify -- a caller MUST NOT catch
    that and post anyway; see run()'s server-mode branch below, which lets
    it propagate.

    `client_key_id`/`client_private_key_pem`, if both given, are the
    customer's own PERSISTED signing key (meant to be a CI secret set once
    -- see shadow.signing.generate_keypair's own docstring -- and whose
    public half is separately registered with the server out of band). If
    either is missing, this function falls back to generating a fresh
    EPHEMERAL keypair for this run only: that keeps this function from ever
    crashing for want of a configured key, but an ephemeral key is
    UNREGISTERED with the server by construction, so a real server will
    almost always come back as 'no receipt' for it (a 401 from the D1 key
    lookup, surfaced here as NoReceipt, not a crash). A real deployment
    always configures MUNINN_CLIENT_KEY_ID + MUNINN_CLIENT_PRIVATE_KEY_PEM."""
    from shadow import bundle as bundle_mod  # noqa: E402 -- see module docstring

    now = resolve_now(now)
    if client_key_id and client_private_key_pem:
        key_id, private_pem = client_key_id, client_private_key_pem
    else:
        kp = signing.generate_keypair()
        key_id, private_pem = kp.key_id, kp.private_pem

    pointer_key = signing.derive_pointer_key(private_pem)
    bundle = bundle_mod.assemble_bundle(
        vault, pointer_key=pointer_key, now=now, pr=pr,
        commit_message=commit_message, ai_label=ai_label,
        ai_author_glob=ai_author_glob, ai_trailer=ai_trailer)
    envelope = signing.sign_bundle(bundle, private_pem, key_id)

    result = server_client.submit_envelope(
        server_url, envelope,
        server_public_pem=server_public_key_pem or None)
    if isinstance(result, server_client.NoReceipt):
        return None
    # result is a verified SignedReceipt dict past this point --
    # server_client.submit_envelope() already raised ServerSignatureError
    # instead of returning anything that failed verification.
    return receipt_mod.render_server_receipt(result)


def load_event(event_path: str) -> Dict[str, Any]:
    with open(event_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run(event: Dict[str, Any], *, workspace: str, repo: str, token: str,
       api_base: str, scan_path: str, label: str, author_glob: str,
       trailer: str,
       server_url: str = "", server_public_key_pem: bytes = b"",
       client_key_id: str = "", client_private_key_pem: bytes = b"",
       client_factory=GitHubClient,
       stdout=None) -> int:
    """The testable core: everything main() does, minus reading process
    env/argv. `client_factory` is injectable so tests never construct a
    real GitHubClient (and therefore never touch urllib) -- a fake factory
    can hand back a recording stub and assert it was (or was not) called.

    SERVER MODE ONLY: `server_url` is required. If it is empty, run() exits
    immediately with a clear error rather than attempting any local
    scoring -- this public client has no scoring engine to fall back to.
    See the module docstring for the two failure postures server mode can
    hit once a server is configured."""
    out = stdout or sys.stdout
    if not server_url:
        out.write("muninn-context-receipt: ERROR: server-url is required; "
                  "the public client only runs in server mode. Set "
                  "MUNINN_SERVER_URL (see PROVISIONING.md).\n")
        return 1

    pr = event.get("pull_request")
    if not pr:
        out.write("muninn-context-receipt: no pull_request in event payload; "
                  "not a pull_request-triggered run, exiting cleanly.\n")
        return 0

    head_sha = (pr.get("head") or {}).get("sha", "")
    commit_message = read_head_commit_message(head_sha, workspace) if trailer else ""
    is_ai, reason = detect_ai_authored(
        pr, commit_message, label=label, author_glob=author_glob, trailer=trailer)
    out.write(f"muninn-context-receipt: ai_authored={is_ai} ({reason})\n")
    if not is_ai:
        out.write("muninn-context-receipt: PR is not AI-authored per the "
                  "configured signal(s); no comment posted.\n")
        return 0

    vault = pathlib.Path(workspace) / scan_path
    if not vault.is_dir():
        out.write(f"muninn-context-receipt: scan path not found: {vault}; "
                  "no comment posted.\n")
        return 0

    out.write("muninn-context-receipt: server mode (MUNINN_SERVER_URL "
              f"configured: {server_url}); scoring runs server-side.\n")
    if not (client_key_id and client_private_key_pem):
        out.write("muninn-context-receipt: NOTICE: MUNINN_CLIENT_KEY_ID / "
                  "MUNINN_CLIENT_PRIVATE_KEY_PEM not configured; using a "
                  "fresh EPHEMERAL, UNREGISTERED signing key for this run "
                  "only -- the server will reject it until its public key "
                  "is registered (run `python3 -m shadow.keygen` and see "
                  "PROVISIONING.md), so expect 'no receipt available' "
                  "below rather than a mystery failure.\n")
    try:
        body = build_server_receipt(
            vault, pr=pr, commit_message=commit_message,
            ai_label=label, ai_author_glob=author_glob, ai_trailer=trailer,
            server_url=server_url,
            server_public_key_pem=server_public_key_pem,
            client_key_id=client_key_id,
            client_private_key_pem=client_private_key_pem)
    except server_client.ServerSignatureError as exc:
        out.write(f"muninn-context-receipt: SECURITY EVENT: {exc}\n")
        out.write("muninn-context-receipt: refusing to post any "
                  "comment; failing this step.\n")
        return 1
    if body is None:
        out.write("muninn-context-receipt: no receipt available this "
                  "run (server unreachable, timed out, or rejected the "
                  "request); no comment posted, exiting clean.\n")
        return 0

    issue_number = pr.get("number")
    if not issue_number:
        out.write("muninn-context-receipt: PR has no number in the event "
                  "payload; cannot post a comment.\n")
        return 1
    if not token:
        out.write("muninn-context-receipt: no GitHub token available; "
                  "cannot post a comment.\n")
        return 1

    client = client_factory(token, repo, api_base)
    upsert_comment(client, issue_number, body, receipt_mod.HIDDEN_MARKER)
    out.write(f"muninn-context-receipt: receipt posted/updated on "
              f"{repo}#{issue_number}\n")
    return 0


def main(argv: Optional[list] = None) -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not os.path.isfile(event_path):
        print("muninn-context-receipt: GITHUB_EVENT_PATH not set or not a "
             "file; this action must run on a pull_request event, exiting "
             "cleanly.")
        return 0
    event = load_event(event_path)
    return run(
        event,
        workspace=os.environ.get("GITHUB_WORKSPACE", "."),
        repo=os.environ.get("GITHUB_REPOSITORY", ""),
        token=(os.environ.get("MUNINN_GITHUB_TOKEN")
              or os.environ.get("GITHUB_TOKEN", "")),
        api_base=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        scan_path=os.environ.get("MUNINN_SCAN_PATH", "."),
        label=os.environ.get("MUNINN_AI_LABEL", DEFAULT_AI_LABEL),
        author_glob=os.environ.get("MUNINN_AI_AUTHOR_GLOB", DEFAULT_AI_AUTHOR_GLOB),
        trailer=os.environ.get("MUNINN_AI_TRAILER", DEFAULT_AI_TRAILER),
        # SERVER MODE ONLY: MUNINN_SERVER_URL is required. If unset/empty,
        # run() exits with an error instead of attempting any local
        # scoring -- see the module docstring and run()'s own docstring.
        server_url=os.environ.get("MUNINN_SERVER_URL", ""),
        server_public_key_pem=os.environ.get(
            "MUNINN_SERVER_PUBKEY", "").encode("utf-8"),
        client_key_id=os.environ.get("MUNINN_CLIENT_KEY_ID", ""),
        client_private_key_pem=os.environ.get(
            "MUNINN_CLIENT_PRIVATE_KEY_PEM", "").encode("utf-8"),
    )


if __name__ == "__main__":
    sys.exit(main())
