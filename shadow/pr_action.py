"""shadow/pr_action.py: orchestrates the Muninn Context Receipt GitHub
Action end to end for one `pull_request` event.

    0. resolve_action_ref() / supply-chain self-check, runs FIRST, before
       check_pinned_ref()     anything else in run(): is THIS invocation
                              pinned to an immutable commit SHA, not a
                              mutable `@main`/tag? resolve_action_ref()
                              works out the ref robustly (the composite
                              action threads `github.action_ref` in as
                              MUNINN_ACTION_REF via action.yml's step env,
                              because the runner leaves GITHUB_ACTION_REF
                              empty for a composite's inner steps -- see
                              actions/runner#2473 -- with GITHUB_ACTION_REF
                              then a SHA parsed from GITHUB_ACTION_PATH as
                              fallbacks); check_pinned_ref() then fails the
                              job on an unpinned ref unless
                              MUNINN_ALLOW_UNPINNED=true is set. This job
                              runs with the customer's raw files and repo
                              secrets BEFORE Muninn's own redaction step
                              ever fires, so a mutable ref would let a
                              compromised muninn-client `main` swap in
                              different, unreviewed code for that window.
    1. detect_ai_authored()   pure decision function: is this PR AI-authored,
                              per a CONFIGURABLE signal (a label, an author
                              glob, or a commit-trailer marker)? No I/O.
    2. build_server_receipt() score the repo's context surfaces at the PR
                              head and render the Markdown receipt. This
                              public client is SERVER MODE ONLY: assemble +
                              sign a redacted fingerprint bundle
                              (shadow.bundle / shadow.signing) and hand
                              scoring to a configured server
                              (shadow.server_client); it renders only what a
                              VERIFIED server-signed receipt returned, never
                              scoring in this job.
    3. shadow.gh_client       the ONE module that talks to GitHub. main()
                              below is the only caller that constructs a
                              real GitHubClient; every other function here
                              takes a client as a parameter so a test can
                              hand it a fake and assert zero network calls.

A non-AI-authored PR returns before the build_server_receipt() function or the
GitHub client is even touched -- no comment, no API call, matching the
Action's design goal that nothing about a human-authored PR's review
changes.

SERVER MODE (Phase 5): run() requires MUNINN_SERVER_URL to be configured.
This public client is SERVER MODE ONLY and has no local scoring path. SERVER
MODE offloads scoring to the configured server: the client generates
or loads its own signing keypair (shadow.signing), assembles + signs a
bundle (shadow.bundle, shadow.signing), and calls shadow.server_client,
which verifies the server's own signature on the returned receipt before
handing it back. Two distinct failure postures, both required by the wedge
running unattended in a customer's CI (see shadow.server_client's module
docstring for the full reasoning):
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
import re
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
# This public client is SERVER MODE ONLY: it ships shadow/ WITHOUT any
# scoring modules physically present, yet must still be able to
# `import shadow.pr_action` and run SERVER MODE (build_server_receipt())
# end to end -- see tests/test_client_severance.py.

# Defaults for the three CONFIGURABLE AI-authorship signals. Any of the
# three may be turned off by passing an empty string; label detection is on
# by default (matches action.yml's own default input), the other two are
# off by default until a caller opts in.
DEFAULT_AI_LABEL = "ai-authored"
DEFAULT_AI_AUTHOR_GLOB = ""
DEFAULT_AI_TRAILER = ""

# This client's own version, printed by the pinned-ref self-check below so a
# customer's job log always says which build actually ran -- independent of
# whatever `uses:` ref they configured.
MUNINN_VERSION = "0.1.0"

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


def resolve_action_ref(muninn_action_ref: str, github_action_ref: str,
                       github_action_path: str) -> Tuple[str, str]:
    """Work out the ref THIS action invocation was actually pinned at,
    robust to a real GitHub Actions quirk: for the inner steps of a
    COMPOSITE action the runner leaves the GITHUB_ACTION_REF env var (and
    the `${{ github.action_ref }}` expression evaluated inside a `run:`)
    EMPTY, even when the caller pinned `uses:` to a correct commit SHA. See
    actions/runner#2473 / #2525. That empty value is exactly why the old
    check forced every real consumer to set MUNINN_ALLOW_UNPINNED=true,
    which defeats the whole supply-chain control this check exists for.

    Precedence (first non-empty wins):
      1. MUNINN_ACTION_REF -- `github.action_ref` threaded in explicitly by
         action.yml via the step's `env:` block. Evaluating the context in
         the `env:` field (rather than reading the raw env var or using the
         expression inside `run:`) IS reliably populated in the composite
         inner step -- the accepted real-runner workaround for #2473. This
         is the primary, correct source.
      2. GITHUB_ACTION_REF -- the runner's own env var. Correct for a
         top-level (non-composite) invocation; empty inside composite inner
         steps, hence not sufficient on its own.
      3. a 40-hex commit SHA parsed out of GITHUB_ACTION_PATH -- a
         defense-in-depth fallback. For a SHA-pinned action the runner
         checks the action out under
         `.../_actions/<owner>/<repo>/<sha>/...`, so the SHA appears as a
         path segment; a branch/tag checkout has the branch/tag NAME in
         that segment instead, never a 40-hex string, so this only ever
         yields a value when the action was genuinely SHA-pinned.

    Returns (ref, source). `ref` is "" only when none of the three yielded
    anything -- in which case the caller keeps failing closed (see
    check_pinned_ref); a missing ref is never silently treated as pinned.
    `source` names which input the ref came from, for an honest job log."""
    ref = (muninn_action_ref or "").strip()
    if ref:
        return ref, "MUNINN_ACTION_REF (github.action_ref, threaded via action.yml env)"
    ref = (github_action_ref or "").strip()
    if ref:
        return ref, "GITHUB_ACTION_REF"
    for segment in re.split(r"[\\/]+", github_action_path or ""):
        if _SHA40_RE.match(segment):
            return segment, "GITHUB_ACTION_PATH (resolved commit-SHA checkout dir)"
    return "", "none (no ref resolvable from MUNINN_ACTION_REF, GITHUB_ACTION_REF, or GITHUB_ACTION_PATH)"


def check_pinned_ref(action_ref: str, *, allow_unpinned: bool
                     ) -> Tuple[bool, str]:
    """The supply-chain self-check (see the HARDENING BACKLOG / stack audit
    item this closes): a customer's workflow MUST invoke this Action by an
    immutable commit SHA (`uses: bronsonaber/muninn-client@<40-hex-sha>`),
    never a mutable branch or tag like `@main`. This job runs with access to
    the customer's raw files and repo secrets BEFORE Muninn's own redaction
    step ever fires; a mutable ref means a compromised muninn-client `main`
    could swap in different, unreviewed code for that window with no change
    to the customer's own workflow file at all.

    `action_ref` is the ALREADY-RESOLVED ref for THIS invocation of the
    action, as worked out by resolve_action_ref() from the three env
    sources (see that function for the composite-action quirk it defends
    against). Set by the runner, not configurable by the action's inputs,
    so it can't be spoofed by anything short of a compromised runner. Pure,
    no I/O, so it is trivially testable without faking the environment:
    main() below is the only caller that resolves it from the real
    environment (via resolve_action_ref) and reads MUNINN_ALLOW_UNPINNED.

    Returns (ok, message). `ok` is False (the run must fail) whenever
    `action_ref` is not a 40-character lowercase-hex commit SHA, UNLESS the
    caller has explicitly set MUNINN_ALLOW_UNPINNED=true -- an escape hatch
    for local/dev use only, never recommended for a real CI run, which is
    why it still prints the warning even when it lets the run continue."""
    ref_label = action_ref or ("(empty -- no ref could be resolved from "
                               "MUNINN_ACTION_REF, GITHUB_ACTION_REF, or "
                               "GITHUB_ACTION_PATH)")
    lines = [f"muninn-context-receipt: client version {MUNINN_VERSION}, "
            f"invoked at ref '{ref_label}'"]
    if action_ref and _SHA40_RE.match(action_ref):
        lines.append("muninn-context-receipt: ref is a pinned 40-character "
                     "commit SHA; supply-chain control satisfied.")
        return True, "\n".join(lines)

    lines.append(
        "muninn-context-receipt: SECURITY WARNING: this workflow invokes "
        f"muninn-client at an UNPINNED ref ('{ref_label}'), not a 40-character "
        "commit SHA. A branch or tag can be moved -- accidentally, or by a "
        "compromised maintainer account -- to point at different, "
        "unreviewed code, which would then run in this job with access to "
        "this repo's raw files and secrets BEFORE Muninn's redaction step "
        "ever runs. Pin this input to a commit SHA instead, e.g. "
        "'uses: bronsonaber/muninn-client@<40-char-sha>  # pinned: vX.Y' -- "
        "see PROVISIONING.md for the current recommended SHA "
        "and our security-bulletin/version-rotation policy.")
    if allow_unpinned:
        lines.append(
            "muninn-context-receipt: MUNINN_ALLOW_UNPINNED=true is set; "
            "continuing despite the unpinned ref. This is NOT recommended "
            "for a real CI run.")
        return True, "\n".join(lines)
    lines.append(
        "muninn-context-receipt: refusing to run further. Set "
        "MUNINN_ALLOW_UNPINNED=true to override (not recommended) or, "
        "correctly, pin `uses:` to a commit SHA.")
    return False, "\n".join(lines)


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
    """SERVER MODE's build step (Phase 5): assemble + sign a redacted
    fingerprint bundle over `vault`, then hand scoring to the configured
    server (shadow.server_client) rather than scoring in this
    job. Local reads only to ASSEMBLE the bundle; the one network call is
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

    # v2 crypto-core: HKDF-separated pointer key + a v2 (128-bit pointer)
    # bundle. assemble_bundle defaults to bundle_version=2, so new clients
    # emit v2; the server still accepts v1 from already-deployed clients.
    pointer_key = signing.derive_pointer_key_v2(private_pem)
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
       action_ref: str = "", allow_unpinned: bool = False,
       ref_source: str = "",
       client_factory=GitHubClient,
       stdout=None) -> int:
    """The testable core: everything main() does, minus reading process
    env/argv. `client_factory` is injectable so tests never construct a
    real GitHubClient (and therefore never touch urllib) -- a fake factory
    can hand back a recording stub and assert it was (or was not) called.

    This public client is SERVER MODE ONLY: `server_url` (MUNINN_SERVER_URL)
    is required and drives build_server_receipt(), whose one network call is
    inside shadow.server_client; an empty `server_url` is a hard error. See
    the module docstring for the two failure postures server mode can hit.

    The pinned-ref self-check (see check_pinned_ref()) runs FIRST, before
    anything else -- including the non-AI-authored early-return below -- so
    an unpinned `uses:` fails the job (or at least warns) on every PR, not
    only the ones this Action would otherwise have acted on."""
    out = stdout or sys.stdout
    if ref_source:
        out.write(f"muninn-context-receipt: pinned-ref source: {ref_source}\n")
    ref_ok, ref_message = check_pinned_ref(action_ref, allow_unpinned=allow_unpinned)
    out.write(ref_message + "\n")
    if not ref_ok:
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

    if server_url:
        out.write("muninn-context-receipt: server mode (MUNINN_SERVER_URL "
                  f"configured: {server_url}); scoring runs server-side.\n")
        if not (client_key_id and client_private_key_pem):
            out.write("muninn-context-receipt: NOTICE: MUNINN_CLIENT_KEY_ID / "
                      "MUNINN_CLIENT_PRIVATE_KEY_PEM not configured; using a "
                      "fresh EPHEMERAL, UNREGISTERED signing key for this run "
                      "only -- the server will reject it until its public key "
                      "is registered (run `python3 -m shadow.keygen` and see "
                      "PROVISIONING.md), so expect 'no receipt "
                      "available' below rather than a mystery failure.\n")
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
    else:
        out.write("muninn-context-receipt: ERROR: MUNINN_SERVER_URL is "
                  "required; this public client runs in SERVER MODE ONLY "
                  "and has no local scoring engine (see PROVISIONING.md).\n")
        return 1

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
    # Resolve the ref THIS invocation was pinned at, robust to the composite
    # -action quirk where GITHUB_ACTION_REF is empty for a composite's inner
    # steps even on a correct SHA pin (actions/runner#2473). action.yml
    # threads `github.action_ref` in via the step's env: block as
    # MUNINN_ACTION_REF -- the reliable source in that context. See
    # resolve_action_ref() for the full precedence and the fallbacks.
    resolved_ref, ref_source = resolve_action_ref(
        os.environ.get("MUNINN_ACTION_REF", ""),
        os.environ.get("GITHUB_ACTION_REF", ""),
        os.environ.get("GITHUB_ACTION_PATH", ""),
    )
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
        # Phase 5: MUNINN_SERVER_URL selects the configured scoring server
        # in run() -- see the module docstring. This public client is SERVER
        # MODE ONLY; all four are "" / b"" (falsy) by default until a caller
        # explicitly configures a server.
        server_url=os.environ.get("MUNINN_SERVER_URL", ""),
        server_public_key_pem=os.environ.get(
            "MUNINN_SERVER_PUBKEY", "").encode("utf-8"),
        client_key_id=os.environ.get("MUNINN_CLIENT_KEY_ID", ""),
        client_private_key_pem=os.environ.get(
            "MUNINN_CLIENT_PRIVATE_KEY_PEM", "").encode("utf-8"),
        # The ref is resolved above (resolve_action_ref) from three env
        # sources set by the runner itself -- not inputs the calling
        # workflow's `with:` block can spoof. MUNINN_ALLOW_UNPINNED is the
        # documented, not-recommended escape hatch; see check_pinned_ref().
        action_ref=resolved_ref,
        ref_source=ref_source,
        allow_unpinned=os.environ.get(
            "MUNINN_ALLOW_UNPINNED", "").strip().lower() == "true",
    )


if __name__ == "__main__":
    sys.exit(main())
