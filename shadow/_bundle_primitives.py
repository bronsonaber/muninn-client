"""shadow/_bundle_primitives.py: the client/engine severance seam.

This module holds the small set of pure-stdlib functions, dataclasses, and
constants that BOTH the public GitHub Action client (shadow/pr_action.py,
shadow/bundle.py, shadow/signing.py, shadow/receipt.py, shadow/keygen.py,
shadow/server_client.py, shadow/gh_client.py, and the muninn init/faucet path:
shadow/init.py, shadow/faucet.py, shadow/capture.py, shadow/cdr.py,
shadow/context_inventory.py)
AND the private scoring engine (shadow/doctor.py, shadow/admission.py,
shadow/truthrot.py, shadow/repair_plan.py) need. Every symbol here was MOVED
(not copied) out of its original private home so there is exactly one source
of truth: the private module imports it back, the public client imports it
directly, and neither can drift from the other.

WHY THIS FILE EXISTS: the client never calls scoring-engine code (server mode
hands scoring to a configured server, see shadow/pr_action.py's module
docstring), but before this seam existed it could not even IMPORT without the
scoring engine physically present, because shadow/pr_action.py, shadow/
bundle.py, shadow/signing.py, and shadow/receipt.py each had a top-of-file
`from shadow import doctor` (or admission / truthrot / dryrun / repair_plan)
whose OWN top-of-file imports reach into engine/core/*. A public client repo
that ships shadow/ WITHOUT engine/, the server component, doctor.py, admission.py,
truthrot.py, supersession.py, surface_audit.py, repair_plan.py, and dryrun.py
now imports cleanly: every client module imports only from this module, the
stdlib, and `cryptography` (shadow/signing.py, shadow/server_client.py only).

HARD RULE FOR THIS FILE: no import of engine.*, no import of shadow.doctor,
shadow.admission, shadow.truthrot, shadow.dryrun, shadow.supersession,
shadow.surface_audit, or shadow.repair_plan. shadow.scan_scope is the one
shadow import here (read_vault's scan-scope filter) and is itself pure
stdlib with no further private coupling. Every function below is verified
side-effect-free apart from filesystem reads (read_vault, probe_path).

tests/test_client_severance.py is the guarantee test: it copies only the
public-manifest files into a temp dir with the private modules and engine/
physically absent and asserts `import shadow.pr_action` still succeeds and
build_server_receipt() still runs end to end.
"""
from __future__ import annotations

import hashlib
import math
import os
import pathlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from shadow import scan_scope  # noqa: E402 -- pure stdlib, no private coupling

# ═════════════════════════════════════════════════════════════════════════
# From shadow/doctor.py (moved, not copied)
# ═════════════════════════════════════════════════════════════════════════

# NO-APPROVAL LAW (disconfirmation audit, 2026-07): Muninn is a context
# audit, never a code-quality/security approval, and must never render a
# verdict a reviewer could mistake for a blessing. This disclaimer must
# appear on every user-facing surface. See shadow/doctor.py's own module
# docstring for the full rule; duplicated nowhere else, doctor.py imports
# this constant back.
NOT_A_CODE_REVIEW_DISCLAIMER = (
    "This is a context audit, not a code review. It is not a code-quality "
    "or security approval of the change."
)

# Scoped, neutral status vocabulary. Never pass/fail, never approved.
STATUS_NO_RISKS_FOUND = "no-risks-found-in-scanned-surfaces"

# Token-cost proxy, same proxy as the eval harness (eval/run.py, ledger row
# 12): ceil(len/4). See shadow/doctor.py's own module docstring for the full
# "estimate, not a measurement" caveat.
CHARS_PER_TOKEN = 4

# Resource guards (fail-safe on huge / hostile vaults), see shadow/doctor.py's
# own module docstring for the full rationale.
DEFAULT_MAX_FILES = 20000            # scan ceiling; beyond this the scan is capped
DEFAULT_MAX_FILE_BYTES = 2_000_000   # per-file read cap (2 MB); larger = body dropped


def resolve_now(explicit: Optional[str]) -> str:
    """Injected ISO-8601 stamp: --now, then MUNINN_DOCTOR_NOW, then UTC now.

    The deterministic suite ALWAYS injects; the wall-clock default exists only
    for real operator runs (mirrors shadow/sleep.resolve_now)."""
    now = explicit or os.environ.get("MUNINN_DOCTOR_NOW")
    if now:
        return now
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def est_tokens(text: str) -> int:
    """ceil(len/4), the eval harness's deterministic token-cost proxy."""
    n = len(text or "")
    return 0 if n == 0 else max(1, math.ceil(n / CHARS_PER_TOKEN))


# ═════════════════════════════════════════════════════════════════════════
# From shadow/admission.py (moved, not copied)
# ═════════════════════════════════════════════════════════════════════════

# A secret-shaped literal in a memory body is a hard Reject (never in context).
_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|passwd|password|token|bearer)\s*[:=]\s*\S{6,}"
    r"|AKIA[0-9A-Z]{16}"                       # AWS access key id
    r"|sk-[A-Za-z0-9]{20,}"                    # OpenAI-style secret key
    r"|ghp_[A-Za-z0-9]{20,}"                   # GitHub PAT
    r"|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
)

# Prompt-injection-shaped imperative in a memory body is a hard Reject.
_INJECTION_RE = re.compile(
    r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions)"
    r"|you\s+are\s+now\s+(?:a\s+|an\s+)?\w+\s+(?:with\s+no\s+|without\s+)"
    r"|override\s+your\s+(?:safety|guardrails|instructions)"
)


# ═════════════════════════════════════════════════════════════════════════
# From shadow/dryrun.py (moved, not copied) -- VaultEntry / read_vault /
# _parse_frontmatter do NOT need engine.core; only shadow/dryrun.py's own
# run_shadow()/main() CLI does, and those stay in shadow/dryrun.py.
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class VaultEntry:
    memory_id: str       # from name: frontmatter, filename-stem fallback, or
                          # a detection_incomplete sentinel (see identity_ok)
    description: str     # from description: frontmatter
    file_path: str       # absolute path to .md file
    mem_type: str        # from metadata.type: frontmatter
    body: str            # text body (after closing ---)
    identity_ok: bool = True  # False = corrupt identity; never guess, never
                              # score, caller must classify detection_incomplete
    body_truncated: bool = False  # True = file exceeded the read-size cap; its
                              # body was NOT loaded (identity read from the head
                              # only). Downstream body checks must treat it as
                              # unmeasured, never as empty/clean. See read_vault.


# YAML null literals. A frontmatter `name: null` (or `~`) parses here as the
# truthy literal string "null"/"~", the same class of bug as the quoted-empty
# name in #11: every such file would collapse onto one shared id. Normalised
# to empty during NAME resolution only (a file legitimately NAMED "null" via
# its filename stem keeps working).
_YAML_NULL_LITERALS: frozenset = frozenset({"null", "Null", "NULL", "~"})


def _strip_quotes(v: str) -> str:
    """Strip a single matching pair of surrounding quotes from a YAML scalar.

    Without this, a frontmatter value written as an explicit empty string
    (`name: ""`) is stored as the literal two-character string '""' instead
    of "", which then passes every "is this blank" truthiness check
    downstream. See #11.
    """
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return v


def _parse_frontmatter(text: str) -> Tuple[Dict[str, str], str]:
    """Return (flat_kv, body) for a --- ... --- frontmatter block."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("---", 3)
    if end == -1:
        return {}, text
    fm_block = text[3:end]
    body = text[end + 3:].strip()
    kv: Dict[str, str] = {}
    parent: Optional[str] = None
    for raw in fm_block.splitlines():
        if not raw.strip():
            continue
        if raw.startswith((" ", "\t")):
            if parent and ":" in raw:
                k, _, v = raw.strip().partition(":")
                v = _strip_quotes(v.strip())
                if v:
                    kv[f"{parent}.{k.strip()}"] = v
        elif ":" in raw:
            k, _, v = raw.partition(":")
            k, v = k.strip(), _strip_quotes(v.strip())
            if v:
                kv[k] = v
                parent = None
            else:
                parent = k
    return kv, body


def read_vault(vault_dir: pathlib.Path, *,
               max_files: Optional[int] = None,
               max_file_bytes: Optional[int] = None,
               limits: Optional[Dict[str, int]] = None,
               include_ignored: bool = False,
               scan_scope_out: Optional[Dict[str, object]] = None,
               ) -> List[VaultEntry]:
    """Read every *.md file under vault_dir.

    SCAN SCOPE (default ON): a file git would ignore (vault is a git repo and
    the path matches .gitignore / .git/info/exclude / core.excludesFile) is
    excluded, so git-ignored scratch (e.g. a `.claude/worktrees/` agent
    worktree copy) is never counted as canonical memory. A `.muninnignore` at
    vault_dir's root (gitignore-style globs) is applied on top for explicit
    vault-owner excludes. If vault_dir is not inside a git repo there is
    nothing to honor, so every file is scanned (a .muninnignore still
    applies). Nothing is ever silently dropped: pass ``scan_scope_out`` to
    receive the full honest count (included / excluded / excluding rule).
    ``include_ignored=True`` is the escape hatch: scan everything, exactly
    the pre-scan-scope-correction behavior. See shadow/scan_scope.py.

    Name resolution order (never guess, never score corrupt identity, #11):
      1. frontmatter name: field (YAML null literals, null / Null / NULL /
         ~ are treated as absent, post quote-strip)
      2. filename stem (sans extension), when the frontmatter name is
         missing or blank
      3. if the stem is ALSO blank/whitespace-only, the file has no usable
         identity at all. Rather than let it fall through to an empty or
         quoted-empty string (which silently collapses every such file onto
         the same shared "" id and lets them all get scored as identical
         earners), the entry is kept out of normal scoring: identity_ok is
         set False and memory_id becomes a per-file sentinel so downstream
         aggregation classifies it detection_incomplete instead of guessing.

    Resource guards (all opt-in; defaults preserve the original behaviour so
    every existing caller is unchanged):
      * max_files      - stop after this many *.md files (in sorted order);
                         the remainder are counted, never read. A capped scan
                         is a PARTIAL scan and the caller MUST label it so.
      * max_file_bytes - a file larger than this is NOT slurped into memory;
                         only its head (max_file_bytes) is read for identity,
                         its body is dropped and body_truncated is set True so
                         no body check silently treats a giant file as clean.
      * limits         - an optional dict this fills with counts:
                         files_seen, files_read, files_skipped_over_max,
                         files_truncated. Counts only, never paths (a path is
                         sensitive; the caller redacts what it chooses to show).
    """
    entries: List[VaultEntry] = []
    try:
        vault_root = pathlib.Path(vault_dir).resolve()
    except OSError:
        vault_root = pathlib.Path(vault_dir)
    seen = read = skipped_over_max = truncated = 0
    scope = scan_scope.compute_scan_scope(
        vault_dir, sorted(vault_dir.rglob("*.md")), include_ignored=include_ignored)
    if scan_scope_out is not None:
        scan_scope_out.update(scope.as_report_dict(vault_root))
    for md in scope.included:
        # Symlink-escape guard: a symlinked *.md whose real target sits outside
        # the vault root is skipped, never read. Otherwise a crafted link could
        # pull external file content (and its real filename) into the report.
        try:
            real = md.resolve()
            real.relative_to(vault_root)
        except (OSError, ValueError):
            continue
        seen += 1
        if max_files is not None and read >= max_files:
            skipped_over_max += 1
            continue

        body_truncated = False
        if max_file_bytes is not None:
            try:
                size = md.stat().st_size
            except OSError:
                size = 0
            if size > max_file_bytes:
                # Read only the head (enough for the frontmatter identity);
                # never pull a multi-megabyte body into memory or the report.
                try:
                    with md.open("rb") as fh:
                        text = fh.read(max_file_bytes).decode("utf-8", "replace")
                except OSError:
                    text = ""
                body_truncated = True
                truncated += 1
            else:
                text = md.read_text(encoding="utf-8", errors="replace")
        else:
            text = md.read_text(encoding="utf-8", errors="replace")
        read += 1

        fm, body = _parse_frontmatter(text)
        if body_truncated:
            body = ""   # a truncated giant body must never flow downstream
        resolved_path = str(md.resolve())
        memory_id = fm.get("name", "").strip()
        if memory_id in _YAML_NULL_LITERALS:
            memory_id = ""
        if not memory_id:
            memory_id = md.stem.strip()
        if not memory_id:
            entries.append(VaultEntry(
                memory_id=f"__detection_incomplete__:{resolved_path}",
                description=fm.get("description", ""),
                file_path=resolved_path,
                mem_type=fm.get("metadata.type", ""),
                body=body,
                identity_ok=False,
                body_truncated=body_truncated,
            ))
            continue
        entries.append(VaultEntry(
            memory_id=memory_id,
            description=fm.get("description", ""),
            file_path=resolved_path,
            mem_type=fm.get("metadata.type", ""),
            body=body,
            body_truncated=body_truncated,
        ))
    if limits is not None:
        limits["files_seen"] = seen
        limits["files_read"] = read
        limits["files_skipped_over_max"] = skipped_over_max
        limits["files_truncated"] = truncated
    return entries


# ═════════════════════════════════════════════════════════════════════════
# From shadow/truthrot.py (moved, not copied) -- the stale-path slice the
# client (shadow/bundle.py) uses: claim extraction for the offline path
# class, plus the nullipotent path-exists probe. The scoring/similarity/
# decay/CDR-emission logic (verify_claim, build_memory_report, run(), the
# commit/branch/repo probes) is NOT moved and stays in shadow/truthrot.py,
# which imports these symbols back (see that module's own import block).
# ═════════════════════════════════════════════════════════════════════════

# ── Verdicts (design §3). UNREACHABLE is first-class: "could not check,"
# never "check failed." truthrot.py keeps its own INAPPLICABLE (PR refs,
# not probed by anything moved here) alongside these three.
VERIFIED = "VERIFIED"
ROTTED = "ROTTED"
UNREACHABLE = "UNREACHABLE"


@dataclass
class MemoryUnit:
    """One memory unit: an atomic .md file, or one ## entry in a log file
    (truthrot design §2)."""
    unit_id: str            # atomic: frontmatter name / stem; log: "<stem>#<slug>"
    rel_path: str           # path relative to the vault root (a pointer)
    tier: str               # frontmatter `tier`, else "on_demand"
    text: str               # body text used for extraction -- NEVER emitted to a CDR


@dataclass
class Claim:
    """One machine-checkable anchor extracted from a memory unit."""
    unit_id: str
    claim_class: str        # path | commit | branch | repo | pr
    anchor: str              # the extracted token (path / sha / ref) -- reporting only
    from_backtick: bool     # True if extracted from a backtick span (trusted whole)

    @property
    def claim_id(self) -> str:
        h = hashlib.sha256()
        h.update(self.unit_id.encode("utf-8"))
        h.update(b"\x1f")
        h.update(self.claim_class.encode("utf-8"))
        h.update(b"\x1f")
        h.update(self.anchor.encode("utf-8"))
        return h.hexdigest()[:12]


# A path-like backtick/inline token: starts at ~ , / or ./
_BACKTICK_SPAN = re.compile(r"`([^`\n]+)`")
# bare absolute / home path, stops at whitespace or markdown/closer punctuation.
_BARE_PATH = re.compile(r"(?<![\w`])((?:~|\.)?/[^\s`)\]\}<>|'\"]+)")
# hex SHA token not embedded in a longer word/path
_HEX_TOKEN = re.compile(r"(?<![\w/.\-])([0-9a-f]{7,40})(?![\w/.\-])")
_ORIGIN_BRANCH = re.compile(r"\borigin/([A-Za-z0-9._][A-Za-z0-9._/\-]*)")
_OWNER_REPO = re.compile(r"\b([A-Za-z0-9][\w.\-]*)/([A-Za-z0-9][\w.\-]*)\b")
_PR_REF = re.compile(r"(?<![\w])#(\d{1,6})\b")

_TRAILING_PUNCT = ".,;:!?)]}>\"'"

# Glob / template metacharacters. A token carrying any of these is a PATTERN or a
# placeholder (`~/projects/*`, `{build,ops}-pane`, `<session>.jsonl`), not a
# concrete falsifiable anchor -- probing it manufactures false rot, so it is never
# extracted as a path claim. On posix a backslash is an escape/glob metachar and
# stays in this set; on Windows it is THE path separator, so a native Windows
# path (C:\Users\...\file) must not be rejected for containing one.
_ON_WINDOWS = os.sep == "\\"
_PATH_META = set("*?[]{}<>") | (set() if _ON_WINDOWS else {"\\"})

# A Windows absolute path (drive letter + separator): C:\... or C:/... . Only
# treated as a path on Windows, so posix extraction behavior is unchanged.
_WIN_ABS_PATH = re.compile(r"^[A-Za-z]:[\\/]")

# Hex tokens that look like SHAs but are not commit references (SSH key type, …).
_HEX_STOPLIST: frozenset = frozenset({"ed25519"})
# Non-git contexts that mint hex tokens (Make.com executionIds, API keys, …).
_NON_COMMIT_CONTEXT = re.compile(r"(execution|token|apikey|api[- ]?key|uuid)",
                                 re.IGNORECASE)


def _looks_like_path(tok: str) -> bool:
    tok = tok.strip()
    if len(tok) < 2:
        return False
    if tok.startswith(("/", "~/", "./")):
        return True
    # Native Windows absolute path (only recognized when running on Windows, so
    # posix vaults that mention a "C:\..." string in prose are unaffected).
    return _ON_WINDOWS and bool(_WIN_ABS_PATH.match(tok))


def _is_concrete_path(tok: str) -> bool:
    """A path is a concrete anchor only if it carries no glob/template metachar."""
    return _looks_like_path(tok) and not (set(tok) & _PATH_META)


def _commit_context_ok(text: str, start: int) -> bool:
    """False if the hex token is preceded by a non-git label (executionId, …)."""
    window = text[max(0, start - 24):start]
    return not _NON_COMMIT_CONTEXT.search(window)


def _clean_path(tok: str) -> str:
    tok = tok.strip()
    # strip trailing sentence punctuation (e.g. "/root." -> "/root"); keep
    # internal dots (server.js.bak) and a legitimate trailing slash.
    while tok and tok[-1] in _TRAILING_PUNCT:
        tok = tok[:-1]
    return tok


def _is_sha(tok: str) -> bool:
    """A plausible commit SHA: 7-40 hex with at least one digit AND one a-f letter.

    The dual requirement drops pure-numeric tokens (dates like 20260628) and
    English hex-words (decade, facade, deadbeef) -- both of which would otherwise
    manufacture false rot when probed in a scoped repo.
    """
    if not re.fullmatch(r"[0-9a-f]{7,40}", tok):
        return False
    return bool(re.search(r"\d", tok)) and bool(re.search(r"[a-f]", tok))


def extract_claims(unit: MemoryUnit, repo_names: Sequence[str]) -> List[Claim]:
    """Extract the two offline classes (path + VCS) plus PR-ref inventory.

    Deduplicated per (class, anchor). Backtick spans are parsed first so paths
    containing spaces (e.g. `~/Downloads/vault/Project Alpha/`) survive whole
    -- the §9 whitespace-truncation artifact is avoided at the source.
    """
    text = unit.text
    seen: set = set()
    claims: List[Claim] = []

    def add(claim_class: str, anchor: str, from_backtick: bool) -> None:
        anchor = anchor.strip()
        if not anchor:
            return
        key = (claim_class, anchor)
        if key in seen:
            return
        seen.add(key)
        claims.append(Claim(unit.unit_id, claim_class, anchor, from_backtick))

    # 1) backtick spans first (trusted whole)
    for m in _BACKTICK_SPAN.finditer(text):
        span = m.group(1).strip()
        if _looks_like_path(span):
            if _is_concrete_path(span):
                add("path", span, True)
        elif _is_sha(span) and span not in _HEX_STOPLIST \
                and _commit_context_ok(text, m.start(1)):
            add("commit", span, True)
        else:
            bm = _ORIGIN_BRANCH.match(span)
            if bm:
                add("branch", "origin/" + bm.group(1).rstrip("/"), True)

    # 2) bare inline paths. A token truncated by a following template/glob
    # metachar (e.g. `/.claude/projects/` before `<id>`) is a pattern PREFIX, not a
    # concrete anchor -- the next source char reveals it.
    for m in _BARE_PATH.finditer(text):
        nxt = text[m.end():m.end() + 1]
        if nxt in _PATH_META:
            continue
        tok = _clean_path(m.group(1))
        if _is_concrete_path(tok):
            add("path", tok, False)

    # 3) bare commit SHAs
    for m in _HEX_TOKEN.finditer(text):
        tok = m.group(1)
        if _is_sha(tok) and tok not in _HEX_STOPLIST \
                and _commit_context_ok(text, m.start(1)):
            add("commit", tok, False)

    # 4) origin/<branch> refs
    for m in _ORIGIN_BRANCH.finditer(text):
        add("branch", "origin/" + m.group(1).rstrip("/" + _TRAILING_PUNCT), False)

    # 5) repo refs -- owner/repo where repo basename is a known local clone
    repo_set = {r.lower() for r in repo_names}
    for m in _OWNER_REPO.finditer(text):
        repo = m.group(2)
        if repo.lower() in repo_set:
            add("repo", f"{m.group(1)}/{repo}", False)

    # 6) PR/issue refs -- inventory only (network probe deferred to v0.4)
    for m in _PR_REF.finditer(text):
        add("pr", "#" + m.group(1), False)

    return claims


def _local_roots(vault_dir: pathlib.Path, extra: Sequence[str]) -> List[str]:
    roots = [os.path.abspath(os.path.expanduser(str(pathlib.Path.home()))),
             os.path.abspath(str(pathlib.Path(vault_dir).expanduser()))]
    for r in extra:
        roots.append(os.path.abspath(os.path.expanduser(r)))
    # dedupe, keep order
    out: List[str] = []
    for r in roots:
        if r not in out:
            out.append(r)
    return out


def _under_local_root(abspath: str, roots: Sequence[str]) -> Optional[str]:
    for root in roots:
        if abspath == root or abspath.startswith(root + os.sep):
            return root
    return None


def probe_path(
    claim: Claim,
    local_roots: Sequence[str],
) -> Tuple[str, str, Optional[str]]:
    """Path-exists probe (nullipotent stat), host-scoped.

    Returns (verdict, signal, scope). A path outside the local roots (remote host,
    HTTP route, system root) is UNREACHABLE -- never ROTTED (design §6 guard (a)).
    A bare token whose miss is explained by a whitespace-truncated sibling is
    UNREACHABLE (the §9 `~/Downloads/vault/Project` precision caveat).
    """
    raw = claim.anchor
    expanded = os.path.abspath(os.path.expanduser(raw))
    root = _under_local_root(expanded, local_roots)
    if root is None:
        return UNREACHABLE, "probe_unreachable", None
    if os.path.exists(expanded):
        return VERIFIED, "path_verified", root
    # Missing under a local root. Guard the bare-token whitespace-truncation case.
    if not claim.from_backtick:
        parent = os.path.dirname(expanded)
        base = os.path.basename(expanded)
        if base and os.path.isdir(parent):
            try:
                siblings = os.listdir(parent)
            except OSError:
                siblings = []
            if any(s != base and s.startswith(base) for s in siblings):
                return UNREACHABLE, "probe_unreachable", root
    return ROTTED, "path_rotted", root


# ═════════════════════════════════════════════════════════════════════════
# From shadow/repair_plan.py (moved, not copied)
# ═════════════════════════════════════════════════════════════════════════

def _looks_like_secret_or_inject(finding: Dict[str, Any]) -> bool:
    fid = (finding.get("finding_id") or "").upper()
    return "SECRET" in fid or "INJECT" in fid
