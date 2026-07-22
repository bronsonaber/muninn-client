"""shadow/init.py, `muninn init`: one-command customer onboarding.

`muninn init --invite <INVITE_TOKEN>` is the single-command installer: it
generates a client signing keypair, self-registers it against a Muninn scoring
server (POST /register), wires this repo's GitHub Actions secrets/variables via
`gh`, writes the Context Receipt workflow, and opens the PR that adds it. See
`_build_parser`, `run_onboard`, and `main` below.

  muninn init --invite <INVITE_TOKEN> [--server-url URL] [--repo OWNER/REPO]
              [--branch NAME] [--no-pr]

The private key is generated locally and is sent nowhere except into a GitHub
secret (over stdin, via `gh secret set`) -- never in the /register payload,
never in subprocess argv, never printed to stdout -- and is deleted from disk
before this command returns, on every path past its own creation (success or
failure).

This module used to also answer to `muninn init` for a second, unrelated
feature: the evidence-faucet CDR-capture installer (`--assistant/--vault/
--check`). The two shared no flag name and no code beyond stdlib imports and
`shadow.signing.generate_keypair`; `main()` used to peek argv for `--invite`
to tell them apart. That collision is resolved: the evidence faucet is now
`muninn faucet` (see shadow/faucet.py), and `muninn init` means onboarding
only.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence

_here = pathlib.Path(__file__).parent
if str(_here.parent) not in sys.path:
    sys.path.insert(0, str(_here.parent))

from shadow import signing  # noqa: E402


# ── customer onboarding (`muninn init --invite <token>`) ───────────────────────

DEFAULT_SERVER_URL = "https://muninn-edge.bronson-aber.workers.dev"
DEFAULT_ONBOARD_BRANCH = "muninn-setup"

# Pinned to an immutable commit SHA, not the floating `main` branch: a
# customer's workflow runs this action with access to their raw files and
# secrets BEFORE Muninn's own redaction step ever fires. A mutable ref
# (`@main`, `@v1`, etc.) means a compromised muninn-client `main` could run
# changed, unreviewed code in that window with no change to this file at
# all. THE ONE PLACE to bump on a future muninn-client release: update
# MUNINN_CLIENT_REF (and its version comment) here, nowhere else -- both
# CLIENT_ACTION_REF and the generated workflow derive from it.
MUNINN_CLIENT_REF = "29d5e153e6cd9296fa5adcebd985f2a3ea15bf63"  # muninn-client v0.1.1 (receipt names finding + pin self-check fix)
MUNINN_CLIENT_VERSION_LABEL = "v0.1.1"
CLIENT_ACTION_REF = f"bronsonaber/muninn-client@{MUNINN_CLIENT_REF}"
WORKFLOW_RELPATH = ".github/workflows/muninn.yml"
PRIVATE_KEY_FILENAME = ".muninn_client_key.pem"  # local only; deleted before exit
ONBOARD_USER_AGENT = "muninn-init/1.0"
ONBOARD_TIMEOUT_SECONDS = 15.0
COMMIT_MESSAGE = "Add Muninn Context Receipt workflow"
PR_TITLE = "Add Muninn Context Receipt"


class OnboardError(Exception):
    """A user-facing, already-actionable onboarding failure. `run_onboard`
    catches this exactly once, prints str(exc) verbatim (already
    plain-English, already says what to do about it), and returns 1. A
    first-run failure must read as a fixable config issue, never a raw
    traceback -- every raise site below writes the fix, not just the
    symptom."""


def _run(cmd: List[str], *, cwd: Optional[str] = None,
        input_text: Optional[str] = None,
        timeout: float = 30.0) -> "subprocess.CompletedProcess[str]":
    """The one subprocess seam `git`/`gh` calls funnel through, so a test can
    intercept ALL of them by monkeypatching `subprocess.run` alone. Never
    raises for a nonzero exit (the caller decides what that means); a
    transport-level failure (binary not found, timeout) is folded into a
    synthetic nonzero CompletedProcess instead, so every call site has one
    shape to check."""
    try:
        return subprocess.run(cmd, cwd=cwd, input=input_text,
                             capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def _gh_detail(proc: "subprocess.CompletedProcess[str]") -> str:
    return (proc.stderr or proc.stdout or "").strip()


def _gh_error(detail: str, generic: str) -> OnboardError:
    """One SSO-aware error path shared by every `gh` call site below. A
    GitHub org that requires SSO authorization for a token produces a
    distinct, greppable message from `gh` itself; surfaced as its own fix
    rather than folded into a generic auth failure, since the fix (visit
    github.com/settings/tokens, click 'Enable SSO') is different from
    `gh auth login`."""
    if "sso" in detail.lower():
        return OnboardError(
            "GitHub rejected this because your organization requires SSO "
            "authorization for this token.\n"
            "  fix: open https://github.com/settings/tokens, click 'Enable "
            "SSO' next to the token gh is using, authorize it for the "
            "organization, then re-run.\n"
            f"  (gh said: {detail})")
    return OnboardError(f"{generic}\n  (gh said: {detail})" if detail else generic)


def _check_git_repo(cwd: str) -> None:
    proc = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=cwd)
    if proc.returncode != 0 or proc.stdout.strip() != "true":
        raise OnboardError(
            "not inside a git repository.\n"
            "  fix: cd into your project's git repo (or run `git init`), "
            "then re-run `muninn init --invite <token>`.")


def _check_gh_installed() -> None:
    if shutil.which("gh") is None:
        raise OnboardError(
            "the GitHub CLI ('gh') is not installed.\n"
            "  fix: install it from https://cli.github.com/ and re-run.")


def _check_gh_authed(cwd: str) -> None:
    proc = _run(["gh", "auth", "status"], cwd=cwd)
    if proc.returncode != 0:
        detail = _gh_detail(proc)
        raise _gh_error(detail, "gh is not authenticated.\n"
                                "  fix: run `gh auth login` and re-run.")


def _resolve_repo(cwd: str, repo_override: Optional[str]) -> str:
    if repo_override:
        slug = repo_override.strip()
    else:
        proc = _run(["gh", "repo", "view", "--json", "nameWithOwner",
                     "-q", ".nameWithOwner"], cwd=cwd)
        if proc.returncode != 0:
            remote_proc = _run(["git", "remote", "-v"], cwd=cwd)
            if not (remote_proc.stdout or "").strip():
                raise OnboardError(
                    "this repo has no GitHub remote configured.\n"
                    "  fix: add one, e.g. `git remote add origin "
                    "git@github.com:<owner>/<repo>.git`, then re-run. Or "
                    "pass --repo <owner>/<repo> explicitly.")
            raise _gh_error(
                _gh_detail(proc),
                "could not determine which GitHub repo this checkout maps "
                "to (ambiguous remote, or part of a monorepo with multiple "
                "GitHub remotes).\n"
                "  fix: pass --repo <owner>/<repo> explicitly.")
        slug = proc.stdout.strip()
    if "/" not in slug or slug.startswith("/") or slug.endswith("/"):
        raise OnboardError(
            f"'--repo {slug}' is not a valid OWNER/REPO slug.\n"
            "  fix: pass --repo in the form <owner>/<repo>.")
    return slug


def _check_push_access(cwd: str, repo_slug: str) -> None:
    proc = _run(["gh", "repo", "view", repo_slug, "--json", "viewerPermission",
                "-q", ".viewerPermission"], cwd=cwd)
    if proc.returncode != 0:
        raise _gh_error(_gh_detail(proc),
                        f"could not look up your permissions on "
                        f"'{repo_slug}'.")
    perm = proc.stdout.strip().upper()
    if perm not in ("WRITE", "MAINTAIN", "ADMIN"):
        raise OnboardError(
            f"you do not have push access to '{repo_slug}' (permission: "
            f"{perm or 'NONE'}).\n"
            "  fix: ask a repo admin to grant you write access, or run "
            "this against a repository you can push to.")


def _default_branch(cwd: str, repo_slug: str) -> str:
    proc = _run(["gh", "repo", "view", repo_slug, "--json", "defaultBranchRef",
                "-q", ".defaultBranchRef.name"], cwd=cwd)
    if proc.returncode != 0:
        raise _gh_error(_gh_detail(proc),
                        f"could not determine the default branch for "
                        f"'{repo_slug}'.")
    return proc.stdout.strip()


def _register(server_url: str, invite: str, key_id: str, public_pem: str,
              timeout: float = ONBOARD_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """POST {enrollment_token, key_id, public_key_pem} to <server>/register.
    Only the PUBLIC key ever leaves this machine -- the caller passes
    public_pem, never private_pem, and nothing here has a private key to
    leak. Returns the parsed 200 response
    (server_url/server_pubkey/dashboard_url/dashboard_token). Raises
    OnboardError, with the server's own rejection message surfaced, for
    anything else: an unreachable server, a non-200 response (invalid,
    expired, or already-used invite; duplicate key_id; malformed pubkey),
    or a 200 response missing an expected field."""
    url = server_url.rstrip("/") + "/register"
    body = json.dumps({
        "enrollment_token": invite,
        "key_id": key_id,
        "public_key_pem": public_pem,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                "User-Agent": ONBOARD_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read()
        except Exception:
            raw = b""
    except Exception as exc:
        raise OnboardError(
            f"could not reach the Muninn server at {server_url}: {exc}\n"
            "  fix: check your network connection and the --server-url / "
            "MUNINN_SERVER_URL value, then re-run. Nothing was registered, "
            "committed, or pushed.")

    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, ValueError):
        parsed = {}

    if status != 200:
        message = parsed.get("error") if isinstance(parsed, dict) else None
        message = message or f"server returned HTTP {status}"
        raise OnboardError(
            f"registration failed: {message}.\n"
            "  fix: if the invite token is invalid, expired, or already "
            "used, ask us for a fresh one and re-run with --invite <new "
            "token>. Nothing was committed or pushed; re-running is safe.")

    if not isinstance(parsed, dict):
        raise OnboardError(
            "registration succeeded but the server's response was not a "
            "JSON object; this looks like a server-side problem, not "
            "something to fix locally. Contact us with this message.")
    for field in ("server_url", "server_pubkey", "dashboard_url", "dashboard_token"):
        if field not in parsed:
            raise OnboardError(
                "registration succeeded but the server's response was "
                f"missing '{field}'; this looks like a server-side problem, "
                "not something to fix locally. Contact us with this "
                "message.")
    return parsed


def _gh_secret_set(name: str, value: str, repo_slug: str, cwd: str) -> None:
    """Sets a repo secret by piping `value` on stdin (never as a CLI
    argument) so it never appears in this process's own argv/`ps` output --
    the same discipline the private key file already gets (never printed,
    never logged)."""
    proc = _run(["gh", "secret", "set", name, "--repo", repo_slug], cwd=cwd,
               input_text=value)
    if proc.returncode != 0:
        raise _gh_error(_gh_detail(proc), f"failed to set repo secret '{name}'.")


def _gh_variable_set(name: str, value: str, repo_slug: str, cwd: str) -> None:
    proc = _run(["gh", "variable", "set", name, "--repo", repo_slug], cwd=cwd,
               input_text=value)
    if proc.returncode != 0:
        raise _gh_error(_gh_detail(proc), f"failed to set repo variable '{name}'.")


def _render_workflow(server_url: str) -> str:
    return (
        "name: Muninn Context Receipt\n"
        "\n"
        "on: pull_request\n"
        "\n"
        "permissions:\n"
        "  pull-requests: write\n"
        "  contents: read\n"
        "\n"
        "jobs:\n"
        "  context-receipt:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      # Pinned to an immutable commit SHA, not @main: this job runs\n"
        "      # with access to this repo's raw files and secrets BEFORE\n"
        "      # Muninn's own redaction step ever fires, so a mutable ref\n"
        "      # would let a compromised muninn-client `main` run changed,\n"
        "      # unreviewed code in that window. Bump only on a Muninn\n"
        "      # security bulletin / release advisory -- see\n"
        "      # PROVISIONING.md.\n"
        f"      - uses: {CLIENT_ACTION_REF}  # pinned: {MUNINN_CLIENT_VERSION_LABEL}\n"
        "        with:\n"
        f"          server-url: '{server_url}'\n"
        "          server-pubkey: ${{ vars.MUNINN_SERVER_PUBKEY }}\n"
        "          client-key-id: ${{ vars.MUNINN_CLIENT_KEY_ID }}\n"
        "          client-private-key: ${{ secrets.MUNINN_CLIENT_PRIVATE_KEY_PEM }}\n"
    )


def _pr_body(dashboard_url: str) -> str:
    return (
        "Adds the Muninn Context Receipt GitHub Action to this repo.\n\n"
        "On every pull request, Muninn posts a redacted context audit as a "
        "PR comment (never a code-quality or security approval). This PR "
        "is itself the first thing Muninn will comment on.\n\n"
        f"Context Health dashboard: {dashboard_url}\n"
    )


def _git_create_branch(cwd: str, branch: str) -> None:
    proc = _run(["git", "checkout", "-b", branch], cwd=cwd)
    if proc.returncode == 0:
        return
    # branch may already exist locally from a prior --no-pr run; reuse it.
    proc2 = _run(["git", "checkout", branch], cwd=cwd)
    if proc2.returncode != 0:
        raise OnboardError(
            f"failed to create or check out branch '{branch}'.\n"
            f"  (git said: {(proc.stderr or proc.stdout or '').strip()})")


def _git_commit(cwd: str, paths: List[str], message: str) -> None:
    proc = _run(["git", "add", *paths], cwd=cwd)
    if proc.returncode != 0:
        raise OnboardError(
            f"failed to stage {paths}.\n"
            f"  (git said: {(proc.stderr or proc.stdout or '').strip()})")
    proc2 = _run(["git", "commit", "-m", message], cwd=cwd)
    if proc2.returncode != 0:
        raise OnboardError(
            "failed to commit the Muninn workflow.\n"
            f"  (git said: {(proc2.stderr or proc2.stdout or '').strip()})")


def _git_push(cwd: str, branch: str) -> None:
    proc = _run(["git", "push", "-u", "origin", branch], cwd=cwd)
    if proc.returncode != 0:
        raise OnboardError(
            f"failed to push branch '{branch}'.\n"
            f"  (git said: {(proc.stderr or proc.stdout or '').strip()})")


def _gh_pr_create(cwd: str, repo_slug: str, branch: str, title: str,
                  body: str) -> str:
    proc = _run(["gh", "pr", "create", "--repo", repo_slug, "--head", branch,
                "--title", title, "--body", body], cwd=cwd)
    if proc.returncode != 0:
        raise _gh_error(_gh_detail(proc), "failed to open the pull request.")
    return proc.stdout.strip()


def _render_onboard_success(repo_slug: str, key_id: str, reg: Dict[str, Any],
                            pr_url: Optional[str], no_pr: bool,
                            branch: str) -> str:
    L = [
        "=" * 64,
        "  muninn init: onboarding complete",
        "=" * 64,
        f"  repo             : {repo_slug}",
        f"  key_id           : {key_id}",
        f"  server url       : {reg['server_url']}",
        f"  dashboard        : {reg['dashboard_url']}",
        f"  dashboard token  : {reg['dashboard_token']}",
        "                     (shown once, save it now -- use it as "
        "'Authorization: Bearer <token>' against the dashboard URL above)",
    ]
    if no_pr:
        L += [
            "",
            f"  branch '{branch}' committed locally; no PR opened (--no-pr).",
            "  next steps:",
            f"    git push -u origin {branch}",
            f"    gh pr create --repo {repo_slug} --head {branch} "
            f"--title \"{PR_TITLE}\"",
        ]
    else:
        L += ["", f"  pull request     : {pr_url}"]
    L.append("=" * 64)
    return "\n".join(L) + "\n"


def run_onboard(*, invite: str, server_url: Optional[str] = None,
                repo_override: Optional[str] = None,
                branch: str = DEFAULT_ONBOARD_BRANCH, no_pr: bool = False,
                cwd: Optional[str] = None, stdout=None,
                env: Optional[Dict[str, str]] = None) -> int:
    """The testable core of `muninn init --invite <token>`. Runs preflight,
    generates a keypair locally, registers the PUBLIC key with the server,
    wires this repo's GitHub secret/variables via `gh`, writes the workflow,
    and commits (+ pushes + opens a PR, unless no_pr). The private key file
    is always deleted before returning, on every path past its own creation
    (success or failure) -- see the `finally` block below.

    Returns 0 on success, 1 on any OnboardError (already-actionable message
    written to `stdout`, no raw traceback). Any other exception is a real
    bug and is allowed to propagate."""
    out = stdout or sys.stdout
    cwd = cwd or os.getcwd()
    env = env if env is not None else os.environ
    server_url = server_url or env.get("MUNINN_SERVER_URL") or DEFAULT_SERVER_URL

    private_key_path: Optional[pathlib.Path] = None
    try:
        # 1. PREFLIGHT -- fail early, before anything is generated or sent.
        _check_git_repo(cwd)
        _check_gh_installed()
        _check_gh_authed(cwd)
        repo_slug = _resolve_repo(cwd, repo_override)
        _check_push_access(cwd, repo_slug)
        default_branch = _default_branch(cwd, repo_slug)
        if branch == default_branch:
            raise OnboardError(
                f"--branch must not be the repository's default branch "
                f"('{default_branch}').\n"
                "  fix: choose a different branch name, e.g. --branch "
                f"{DEFAULT_ONBOARD_BRANCH}.")

        # 2. GENERATE KEYPAIR locally. The private key never leaves this
        # function except as a GitHub secret (step 4, over stdin, via gh);
        # it is never logged, never printed, never part of the /register
        # payload (step 3 sends only kp.public_pem).
        kp = signing.generate_keypair()
        private_key_path = pathlib.Path(cwd) / PRIVATE_KEY_FILENAME
        if private_key_path.exists():
            raise OnboardError(
                f"refusing to overwrite existing file '{private_key_path}'.\n"
                "  fix: move or delete it, then re-run.")
        private_key_path.write_bytes(kp.private_pem)
        try:
            private_key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        # 3. REGISTER the PUBLIC key only.
        reg = _register(server_url, invite, kp.key_id,
                        kp.public_pem.decode("ascii"))

        # 4. WIRE GITHUB: private key -> secret (stdin only), key_id +
        # server pubkey -> plain repo variables (not sensitive).
        _gh_secret_set("MUNINN_CLIENT_PRIVATE_KEY_PEM",
                       private_key_path.read_text(encoding="ascii"),
                       repo_slug, cwd)
        _gh_variable_set("MUNINN_CLIENT_KEY_ID", kp.key_id, repo_slug, cwd)
        _gh_variable_set("MUNINN_SERVER_PUBKEY", reg["server_pubkey"],
                         repo_slug, cwd)

        # 5. WRITE the workflow.
        workflow_path = pathlib.Path(cwd) / WORKFLOW_RELPATH
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(_render_workflow(reg["server_url"]),
                                 encoding="utf-8")

        # 6. COMMIT + PR (or --no-pr: local branch only).
        _git_create_branch(cwd, branch)
        _git_commit(cwd, [WORKFLOW_RELPATH], COMMIT_MESSAGE)
        pr_url: Optional[str] = None
        if not no_pr:
            _git_push(cwd, branch)
            pr_url = _gh_pr_create(cwd, repo_slug, branch, PR_TITLE,
                                   _pr_body(reg["dashboard_url"]))

    except OnboardError as exc:
        out.write(f"muninn init: {exc}\n")
        return 1
    finally:
        # 7. FINISH: the private key file has served its only purpose (being
        # read into a GitHub secret) or the run failed after it was written;
        # either way it must not linger on disk as plaintext.
        if private_key_path is not None:
            try:
                if private_key_path.exists():
                    private_key_path.unlink()
            except OSError:
                pass

    out.write(_render_onboard_success(repo_slug, kp.key_id, reg, pr_url,
                                      no_pr, branch))
    return 0


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="muninn init",
        description="One-command Muninn onboarding: generate a client "
                    "signing keypair, self-register it with a Muninn "
                    "scoring server, wire this repo's GitHub Actions "
                    "secrets/variables, write the Context Receipt "
                    "workflow, and open the PR that adds it.")
    p.add_argument("--invite", required=True,
                   help="one-time enrollment invite token")
    p.add_argument("--server-url", default=None,
                   help=f"Muninn server origin (default: {DEFAULT_SERVER_URL}, "
                        "or $MUNINN_SERVER_URL)")
    p.add_argument("--repo", default=None,
                   help="explicit GitHub OWNER/REPO, for monorepos or when "
                        "this checkout's remote is ambiguous")
    p.add_argument("--branch", default=DEFAULT_ONBOARD_BRANCH,
                   help=f"branch name for the setup commit (default: "
                        f"{DEFAULT_ONBOARD_BRANCH})")
    p.add_argument("--no-pr", action="store_true",
                   help="commit the workflow to a local branch only; do "
                        "not push or open a PR")
    return p


def main(argv: Optional[Sequence[str]] = None, stdout=None) -> int:
    args = _build_parser().parse_args(argv)
    return run_onboard(invite=args.invite, server_url=args.server_url,
                       repo_override=args.repo, branch=args.branch,
                       no_pr=args.no_pr, stdout=stdout)


if __name__ == "__main__":
    raise SystemExit(main())
