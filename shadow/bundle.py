"""shadow/bundle.py: the client-side fingerprint-bundle assembler (Phase 2).

Phase 1 (shadow/scoring_engine.py) drew the internal seam between the
scan/redact/post flow and Muninn's scoring engine, so a later phase could
move scoring to a server without touching scan/redact/post. THIS phase
builds the object that would eventually cross that wire: a REDACTED
FINGERPRINT BUNDLE made only of structural pointers (path#<hash>,
mem#<hash>) and typed signal detections -- never a raw file body, never a
raw memory body, never a raw filename, never a matched secret/injection
substring.

Still fully local, still fully offline: no network, no `cryptography`
dependency (pointer hashing is HMAC-SHA256, stdlib hashlib/hmac -- keyed
under a per-customer secret, see _keyed_tok() below, not the same unsalted
tokenizer shadow/redact.py uses for its own shareable-report callers), no
server, and no serialization-to-send. assemble_bundle() only returns a
plain dict; a later phase decides how (and whether, and to whom) it ever
travels anywhere.

THE ACTUAL GUARANTEE (stated precisely, not overclaimed): assert_no_forbidden_keys()
runs two independent checks over the finished bundle, and both must pass.
(1) KEY-NAME check (ported from shadow/cdr.py's _scan_forbidden /
_FORBIDDEN_TEXT_KEYS pattern): a "body"/"content"/"text"/... key anywhere in
the structure is structurally impossible -- assemble_bundle() cannot return
a bundle carrying one of these keys, full stop. (2) VALUE-SHAPE check: every
string VALUE in the bundle (not just ones under a forbidden key) is scanned
for a known secret- or injection-shaped pattern (shadow/_bundle_primitives.py's
_SECRET_RE / _INJECTION_RE, moved out of shadow/admission.py so the client
never has to import the private admission module to reuse the patterns) and
rejected if one matches. Check (1) is a
structural proof; check (2) is a pattern match and therefore NOT a proof of
absence -- a secret or injection payload in a shape neither regex
recognizes could still pass. The two checks together close the gap the
key-only guard alone left open (a raw value living under an allowed key
name, e.g. a free-text "reason" field), but "structurally impossible" is
only ever true of check (1).

POINTERS ARE KEYED, NOT SHARED WITH shadow/redact.py: a bundle leaves the
machine (a server eventually receives it); shadow/redact.py's shareable
doctor report does not (a human forwards it, but no server fingerprints it
looking to enumerate or confirm a candidate path/id). An unsalted,
deterministic hash is fine for the doctor report and wrong for a bundle: it
lets a receiving server brute-force a low-entropy pointer's plaintext or
confirm-by-guess whether a suspected path/id produced it. So this module
defines its OWN tokenizer, _keyed_tok() (HMAC-SHA256 under a per-customer
pointer_key, 64-bit truncation), used for every pointer/foldkey/vault
pointer in a bundle. shadow/redact.py's own _tok() is untouched and still
used exactly as before by every one of its existing callers.

REUSED, NOT REINVENTED. Every symbol below is imported from
shadow/_bundle_primitives.py, the client/engine severance seam -- each was
MOVED (not copied) out of the private module named, which imports it back,
so there is exactly one source of truth and this module never needs to
import the private module itself:
  _SECRET_RE / _INJECTION_RE       originally shadow/admission.py: detect a
                                                secret- or injection-shaped
                                                literal in a memory body;
                                                only the FACT of a match is
                                                kept here, never the matched
                                                text.
  VaultEntry / read_vault()        originally shadow/dryrun.py: the
                                                memory-vault file list (+
                                                resource-limit counts).
  shadow/scan_scope.py   (via read_vault's scan_scope_out) excluded_count.
  shadow/context_inventory.py  detect_surfaces()   the non-md context-surface
                                                list (CLAUDE.md, .cursor/
                                                rules, .claude/settings*.json,
                                                Codex config); context_inventory
                                                itself ships in the public
                                                client (no private coupling),
                                                so this module imports it
                                                directly.
  MemoryUnit / extract_claims() /  originally shadow/truthrot.py: the
  probe_path() / _local_roots() /              existing local-path-claim
  ROTTED                                        extractor and nullipotent
                                                stat-probe, reused here to
                                                produce ONLY a boolean
                                                stale_path_local signal; the
                                                extracted anchor string (a
                                                raw path pulled out of a
                                                memory body) is used to probe
                                                locally and is NEVER placed
                                                anywhere in the bundle.
  est_tokens() / CHARS_PER_TOKEN /  originally shadow/doctor.py: the same
  resolve_now()                                deterministic token-cost
                                                proxy and --now/env/UTC-now
                                                resolution order used
                                                everywhere else.
  shadow/pr_action.py    detect_ai_authored()  the same pure, no-I/O
                                                AI-authored decision function
                                                the GitHub Action already
                                                uses.
  shadow/cdr.py          _FORBIDDEN_TEXT_KEYS  unioned into this module's own
                                                forbidden-key set (a bundle
                                                must reject everything a CDR
                                                rejects, plus the task's own
                                                minimum list).

WHAT THIS PHASE DOES NOT DO (future phase, not now): compute real
supersedes_candidate / contradicts_candidate edges (that needs
shadow/supersession.py's and shadow/surface_audit.py's similarity/
contradiction scoring, which is scoring-engine territory, not scan/redact
territory); serialize the bundle to send anywhere; sign or encrypt it. The
two "candidate" edge kinds are RESERVED in the schema now (closed enum,
present from line one, same "reserve now, fill later, no migration" pattern
shadow/cdr.py already uses for its truth_rot block) so a later phase adds no
new edge shape to the wire format.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import math
import pathlib
import re
import unicodedata
from typing import Any, Dict, List, Optional, Sequence, Set

from shadow import cdr                  # noqa: E402
from shadow import context_inventory    # noqa: E402
from shadow._bundle_primitives import (  # noqa: E402
    VaultEntry, read_vault, MemoryUnit,
    est_tokens, CHARS_PER_TOKEN, resolve_now,
    DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES,
    _SECRET_RE, _INJECTION_RE,
    extract_claims, probe_path, _local_roots, ROTTED,
)
from shadow.pr_action import (           # noqa: E402
    DEFAULT_AI_AUTHOR_GLOB, DEFAULT_AI_LABEL, DEFAULT_AI_TRAILER,
    detect_ai_authored,
)

SCHEMA_VERSION = "bundle-v0"

# ── Closed enums (reserve-now-fill-later, matches shadow/cdr.py's pattern) ──

KIND_MEMORY = "memory"
KIND_CONTEXT_SURFACE = "context_surface"
FILE_KINDS: frozenset = frozenset({KIND_MEMORY, KIND_CONTEXT_SURFACE})

SURFACE_TYPE_VAULT_MD = "vault_md"

SIGNAL_SECRET_SHAPED = "secret_shaped"
SIGNAL_INJECTION_SHAPED = "injection_shaped"
SIGNAL_STALE_PATH_LOCAL = "stale_path_local"
SIGNAL_DUPLICATE_ID = "duplicate_id"
SIGNAL_COLLISION_CASE_FOLD = "collision_case_fold"
SIGNAL_TYPES: frozenset = frozenset({
    SIGNAL_SECRET_SHAPED, SIGNAL_INJECTION_SHAPED, SIGNAL_STALE_PATH_LOCAL,
    SIGNAL_DUPLICATE_ID, SIGNAL_COLLISION_CASE_FOLD,
})

EDGE_SUPERSEDES_CANDIDATE = "supersedes_candidate"    # reserved, not computed yet
EDGE_CONTRADICTS_CANDIDATE = "contradicts_candidate"  # reserved, not computed yet
EDGE_DUPLICATE_ID = "duplicate_id"                    # computed this phase
EDGE_KINDS: frozenset = frozenset({
    EDGE_SUPERSEDES_CANDIDATE, EDGE_CONTRADICTS_CANDIDATE, EDGE_DUPLICATE_ID,
})

# ── policy_collision: a context-surface directive vs. the repo's own lockfile ──
#
# THE marquee contradiction case: a context surface (CLAUDE.md / AGENTS.md)
# tells the agent to use one package manager while the repo's OWN lockfile
# says a different one is actually in use. Unlike every signal above, this
# one is checked against a second, independent, already machine-readable
# ground truth (which lockfile is actually on disk), not a shape-only
# pattern match against a single string -- it is a provable structural
# fact, not a guess, which is why muninn_server.scoring treats it as a real,
# high-priority finding rather than folding it into the low-severity
# structural-hygiene bucket duplicate_id/collision_case_fold occupy.
#
# STRUCTURALLY DIFFERENT SIGNAL SHAPE, on purpose: _new_signal()'s base
# shape (pointer/type/detected/confidence_local) describes a fact about ONE
# pointer. A policy_collision is a fact about the relationship between TWO
# pointers (the directive-bearing surface and the lockfile that contradicts
# it), so it carries `other_pointer` and a closed-vocabulary `reason`
# instead of `confidence_local`. See _new_policy_collision_signal() below.
#
# DELIBERATELY SCOPED TO ONE CASE, SHIPPED WELL: only CLAUDE.md/AGENTS.md
# (both *.md, so read_vault() above already reads their body -- no new
# file-reading surface is introduced) are scanned, against the three
# well-known JS/Node lockfiles at the SAME root. A directive living in a
# non-.md rules file (.cursor/rules/*.mdc, .cursorrules) is not read by
# read_vault today (the non-md context-surfaces loop below records only
# size/pointer for those, never a body) and is out of scope for this phase.

SIGNAL_POLICY_COLLISION = "policy_collision"

PKG_MANAGER_NPM = "npm"
PKG_MANAGER_PNPM = "pnpm"
PKG_MANAGER_YARN = "yarn"

# filename -> the package manager whose lockfile it is. Root-level only: the
# collision this closes is a directive at the repo root versus that SAME
# root's own install ground truth; a lockfile several directories away in an
# unrelated subpackage is not this signal's concern.
LOCKFILE_TO_PKG_MANAGER: Dict[str, str] = {
    "package-lock.json": PKG_MANAGER_NPM,
    "pnpm-lock.yaml": PKG_MANAGER_PNPM,
    "yarn.lock": PKG_MANAGER_YARN,
}

POLICY_COLLISION_REASON_PKG_MANAGER_MISMATCH = "pkg_manager_mismatch"
POLICY_COLLISION_REASONS: frozenset = frozenset({
    POLICY_COLLISION_REASON_PKG_MANAGER_MISMATCH,
})

# A closed, 3-token vocabulary (npm/pnpm/yarn) only -- unlike
# shadow/surface_audit.py's generic subject capture (any 2-40 char token),
# this cannot false-positive on an unrelated word. That is exactly what a
# content-free bundle signal needs: a FACT, not a guess.
_PKG_MANAGER_TOKEN = r"(npm|pnpm|yarn)"
# A directive's tool name is routinely wrapped in markdown emphasis/code
# formatting ("use `pnpm`", "use **pnpm**") -- tolerate up to 3 leading
# markers, same allowance shadow/surface_audit.py's own _MD_MARK makes.
_MD_MARK = r"[*_`]{0,3}"
_PKG_ASSERT_VERBS = (
    r"(?:always\s+)?(?:use|uses|using|prefer|prefers|run|runs|"
    r"install\s+with|choose|chooses|standardi[sz]e\s+on|default\s+to)"
)
_PKG_PROHIBIT_CUE = (
    r"(?:never(?:\s+use|\s+run)?|do\s+not(?:\s+use|\s+run)?|"
    r"don't(?:\s+use|\s+run)?|avoid|no\s+longer\s+use|stop\s+using|"
    r"not\s+allowed\s+to\s+use)"
)
_PKG_ASSERT_RE = re.compile(
    r"(?i)\b" + _PKG_ASSERT_VERBS + r"\s+" + _MD_MARK + _PKG_MANAGER_TOKEN + r"\b")
_PKG_PROHIBIT_RE = re.compile(
    r"(?i)\b" + _PKG_PROHIBIT_CUE + r"\s+" + _MD_MARK + _PKG_MANAGER_TOKEN + r"\b")
# A bare "<manager> install" mention (e.g. "always npm install", "Run `pnpm
# install`") reads as an instruction to run that command, independent of the
# assert-verb list above.
_PKG_INSTALL_SUFFIX_RE = re.compile(
    r"(?i)\b" + _MD_MARK + _PKG_MANAGER_TOKEN + r"\s+install\b")


def _pkg_clauses(text: str) -> List[str]:
    """Split a surface body into short clauses on sentence/line/comma
    boundaries, same split shadow/surface_audit.py's own _clauses() uses,
    so a prohibition and an assertion for two DIFFERENT tokens in the same
    sentence ("Never use npm, always use pnpm") are examined independently
    rather than letting one contaminate the other's match."""
    parts = re.split(r"[.\n;,]", text or "")
    return [p.strip() for p in parts if p.strip()]


def _detect_pkg_manager_directive(text: str) -> Optional[str]:
    """The single package manager a context-surface body directs the agent
    toward, or None if no clause makes an unambiguous assertion.

    Clause-scoped (see _pkg_clauses): a clause that PROHIBITS a manager
    ("never use npm") is skipped outright, so a prohibition naming a
    manager is never mistaken for a directive toward it, regardless of
    where in the text it falls relative to the real assertion. The first
    clause (reading order) that asserts a manager -- either via an assert
    verb ("use pnpm") or a bare "<manager> install" mention -- wins;
    deterministic, first-match order.

    Heuristic, not semantic understanding, same honest limitation
    shadow/surface_audit.py's own lexical detectors carry: a lexical
    pattern match, not an LLM judgement of intent.
    """
    if not text:
        return None
    for clause in _pkg_clauses(text):
        if _PKG_PROHIBIT_RE.search(clause):
            continue
        m = _PKG_ASSERT_RE.search(clause) or _PKG_INSTALL_SUFFIX_RE.search(clause)
        if not m:
            continue
        tok = m.group(1).lower()
        if tok in LOCKFILE_TO_PKG_MANAGER.values():
            return tok
    return None


def _detect_present_lockfiles(vault_root: pathlib.Path) -> Dict[str, str]:
    """Root-level lockfile presence: filename -> package manager, for the
    three known JS/Node lockfiles. Never raises (a permission error or a
    race against a deleted file reads as "not present", never fatal)."""
    found: Dict[str, str] = {}
    for name, manager in LOCKFILE_TO_PKG_MANAGER.items():
        try:
            if (vault_root / name).is_file():
                found[name] = manager
        except OSError:
            continue
    return found


def _new_policy_collision_signal(pointer: str, other_pointer: str,
                                 reason: str) -> Dict[str, Any]:
    """One policy_collision signal: the directive-bearing surface's
    pointer, the contradicting lockfile's pointer, and a closed-vocabulary
    reason code. See the module-level note above SIGNAL_POLICY_COLLISION
    for why this shape deliberately differs from _new_signal()'s. No
    free-text field exists here either, on purpose."""
    assert reason in POLICY_COLLISION_REASONS, \
        f"unknown policy_collision reason: {reason!r}"
    return {
        "pointer": pointer,
        "other_pointer": other_pointer,
        "type": SIGNAL_POLICY_COLLISION,
        "detected": True,
        "reason": reason,
    }

CONFIDENCE_LEVELS: frozenset = frozenset({"high", "medium", "low"})

# ai_authored.reason closed vocabulary. detect_ai_authored() (shadow/pr_action.py)
# returns a free-text reason for a human-readable Action log line, and that
# free text interpolates caller-configured values (the label name is not
# secret, but the PR author's login and the configured author-glob pattern
# are the kind of raw, un-tokenized text a bundle must never carry). A
# bundle stores only WHICH signal category matched, never the matched text.
AI_REASON_LABEL_MATCHED = "label_matched"
AI_REASON_AUTHOR_GLOB_MATCHED = "author_glob_matched"
AI_REASON_TRAILER_MATCHED = "trailer_matched"
AI_REASON_NO_SIGNAL_MATCHED = "no_signal_matched"
AI_REASON_CODES: frozenset = frozenset({
    AI_REASON_LABEL_MATCHED, AI_REASON_AUTHOR_GLOB_MATCHED,
    AI_REASON_TRAILER_MATCHED, AI_REASON_NO_SIGNAL_MATCHED,
})


def _coded_ai_authored_reason(pr: Dict[str, Any], commit_message: str, *,
                              label: str, author_glob: str, trailer: str) -> str:
    """The bundle's own closed-vocabulary version of
    shadow.pr_action.detect_ai_authored()'s reason: same three signals,
    same precedence order (label, then author_glob, then trailer), but
    returns a fixed CODE naming which category matched rather than a
    free-text string interpolating the label/login/glob/trailer value
    itself. Kept deliberately independent of detect_ai_authored()'s return
    string (which is fine for a human-readable local log line but not for a
    bundle's wire format) rather than string-classifying that free text --
    parsing a message meant for humans to recover a machine fact is exactly
    the fragile pattern this function avoids. Any change to
    detect_ai_authored()'s matching rules must be mirrored here."""
    if label:
        wanted = label.strip().lower()
        names = {(entry.get("name") or "").strip().lower()
                for entry in (pr.get("labels") or [])}
        if wanted in names:
            return AI_REASON_LABEL_MATCHED
    if author_glob:
        login = ((pr.get("user") or {}).get("login") or "")
        for pattern in (g.strip() for g in author_glob.split(",")):
            if pattern and fnmatch.fnmatchcase(login, pattern):
                return AI_REASON_AUTHOR_GLOB_MATCHED
    if trailer:
        if trailer in (commit_message or ""):
            return AI_REASON_TRAILER_MATCHED
    return AI_REASON_NO_SIGNAL_MATCHED


# ── Bundle pointer tokenizer (keyed, bundle-only; see module docstring) ─────────

POINTER_HMAC_HEX_LEN = 16  # 64 bits (widened from shadow/redact.py's 32-bit sha256[:8])


def _keyed_tok(prefix: str, s: str, pointer_key: bytes) -> str:
    """The bundle's own pointer tokenizer: HMAC-SHA256 keyed under
    ``pointer_key`` (see shadow.signing.derive_pointer_key), truncated to
    POINTER_HMAC_HEX_LEN hex chars (64 bits, up from shadow/redact.py's
    unsalted 32-bit sha256[:8]). Deterministic WITHIN one key -- the same
    input always maps to the same token for a given customer, so
    duplicate_id / collision_case_fold detection across a customer's own
    bundles still works -- but unguessable and non-correlatable to anyone
    without that customer's key: unlike an unsalted hash, neither a
    preimage-recovery brute force nor a confirm-by-guess check against a
    suspected path/id succeeds without the key. shadow/redact.py's own
    _tok() is untouched; this is a separate primitive for the bundle only,
    not a change to that shared function's other callers."""
    mac = hmac.new(pointer_key, s.encode("utf-8", "surrogatepass"), hashlib.sha256)
    return f"{prefix}#{mac.hexdigest()[:POINTER_HMAC_HEX_LEN]}"


# The bundle's own raw-content tripwire. Ported from shadow/cdr.py's
# _FORBIDDEN_TEXT_KEYS pattern, unioned with the task's own minimum list: a
# bundle must reject everything a CDR rejects, plus the additional keys named
# for this phase. The union is a strict superset, so nothing gets easier to
# leak by reusing cdr.py's set here.
FORBIDDEN_BUNDLE_KEYS: frozenset = frozenset({
    "body", "content", "text", "raw", "secret_value", "match", "line",
    "snippet",
}) | cdr._FORBIDDEN_TEXT_KEYS


# ── Forbidden-key scanner (ported from shadow/cdr.py _scan_forbidden) ──────────

class ForbiddenBundleKeyError(ValueError):
    """Raised by assert_no_forbidden_keys when an assembled bundle carries a
    raw-content key anywhere in its structure. This must never be caught and
    suppressed by a caller: an unredacted bundle must fail loudly, never
    silently ship."""


def _scan_forbidden(obj: Any, path: str, errors: List[str]) -> None:
    """Recursively assert no raw-content key leaked into the bundle. Same
    walk shape as shadow/cdr.py's _scan_forbidden, this module's own key set."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN_BUNDLE_KEYS:
                errors.append(f"{path}.{k}: forbidden raw-content key in a bundle")
            _scan_forbidden(v, f"{path}.{k}", errors)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_forbidden(v, f"{path}[{i}]", errors)


def _scan_forbidden_values(obj: Any, path: str, errors: List[str]) -> None:
    """Recursively scan every STRING VALUE in the bundle (regardless of the
    key it sits under) for a known secret- or injection-shaped pattern
    (shadow._bundle_primitives._SECRET_RE / _INJECTION_RE -- the same
    patterns the memory-admission gate uses to hard-reject a memory body).
    This is the channel _scan_forbidden above cannot see: a raw secret or injection
    payload living as the VALUE of an allowed key name (e.g. a free-text
    "reason" field) has no forbidden key to trip, but its shape still
    matches. Pattern-based, therefore NOT a proof of absence -- see the
    module docstring's "actual guarantee" note."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            _scan_forbidden_values(v, f"{path}.{k}", errors)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_forbidden_values(v, f"{path}[{i}]", errors)
    elif isinstance(obj, str):
        if _SECRET_RE.search(obj):
            errors.append(f"{path}: value matches a secret-shaped pattern")
        if _INJECTION_RE.search(obj):
            errors.append(f"{path}: value matches an injection-shaped pattern")


def scan_forbidden_bundle_keys(obj: Any, path: str = "bundle") -> List[str]:
    """Return every violation string found anywhere in ``obj`` ([] means
    clean): every forbidden KEY name (_scan_forbidden) plus every string
    VALUE that matches a secret- or injection-shaped pattern
    (_scan_forbidden_values). Pure, side-effect-free, never raises."""
    errors: List[str] = []
    _scan_forbidden(obj, path, errors)
    _scan_forbidden_values(obj, path, errors)
    return errors


def assert_no_forbidden_keys(bundle: Dict[str, Any]) -> None:
    """The last assembly step: raise ForbiddenBundleKeyError if any forbidden
    key OR any secret-/injection-shaped value appears anywhere in
    ``bundle``. The key-name half of this check is a structural guarantee;
    the value-shape half is a pattern match, not a proof of absence (see the
    module docstring). Name kept as assert_no_forbidden_keys for API
    stability even though it now also asserts on values."""
    errors = scan_forbidden_bundle_keys(bundle)
    if errors:
        raise ForbiddenBundleKeyError(
            "assembled bundle carries forbidden raw-content key(s) or a "
            "secret-/injection-shaped value: " + "; ".join(errors))


# ── Small local helpers ─────────────────────────────────────────────────────────

def _rel(file_path: str, vault_root: pathlib.Path) -> str:
    """Vault-relative path string, falling back to the bare filename. Never
    returned to a caller of assemble_bundle() -- used only as the INPUT to
    this module's own _keyed_tok() one-way keyed hash, exactly like
    shadow/redact.py's own collect_terms()/shadow/doctor.py's own _rel()."""
    try:
        return str(pathlib.Path(file_path).resolve().relative_to(vault_root))
    except (OSError, ValueError):
        return pathlib.Path(file_path).name


def _est_tokens_from_bytes(n: int) -> int:
    """The same deterministic len/CHARS_PER_TOKEN proxy as
    shadow.doctor.est_tokens, applied to a byte count instead of decoded
    text -- used only for non-md context surfaces, so this module never has
    to read their raw content just to size them."""
    return 0 if n <= 0 else max(1, math.ceil(n / CHARS_PER_TOKEN))


def _new_signal(pointer: str, type_: str, confidence_local: str) -> Dict[str, Any]:
    """One typed detection: the FACT of a match plus a pointer, nothing else.
    No free-text field exists on this shape, on purpose -- there is nowhere
    for a matched secret, an extracted path, or an injection string to hide."""
    assert type_ in SIGNAL_TYPES, f"unknown signal type: {type_!r}"
    assert confidence_local in CONFIDENCE_LEVELS, \
        f"unknown confidence level: {confidence_local!r}"
    return {
        "pointer": pointer,
        "type": type_,
        "detected": True,
        "confidence_local": confidence_local,
    }


# ── Assembly ─────────────────────────────────────────────────────────────────────

def assemble_bundle(
    vault_dir: pathlib.Path,
    *,
    pointer_key: bytes,
    now: Optional[str] = None,
    pr: Optional[Dict[str, Any]] = None,
    commit_message: str = "",
    ai_label: str = DEFAULT_AI_LABEL,
    ai_author_glob: str = DEFAULT_AI_AUTHOR_GLOB,
    ai_trailer: str = DEFAULT_AI_TRAILER,
    include_ignored: bool = False,
    max_files: Optional[int] = DEFAULT_MAX_FILES,
    max_file_bytes: Optional[int] = DEFAULT_MAX_FILE_BYTES,
) -> Dict[str, Any]:
    """Build the REDACTED FINGERPRINT BUNDLE for ``vault_dir``.

    ``pointer_key`` is required, no insecure default: the per-customer
    HMAC key every pointer in this bundle is tokenized under (see
    shadow.signing.derive_pointer_key -- typically derived once from the
    same private signing key a caller already holds to sign the envelope).
    Callers that do not yet have a persisted signing key can mint an
    ephemeral one with secrets.token_bytes(32); pointers just will not be
    comparable across separately-keyed bundles.

    ``max_files``/``max_file_bytes`` cap the vault read exactly like
    shadow.doctor's own scan ceilings (same defaults); pass None to disable
    a cap. resource_stats below reports the REAL skip/truncation counts
    read_vault() observed under these caps, never a number that implies a
    cap no call actually enforced.

    Local reads only, no network. Every string that ever named a real file,
    a real memory id, a real secret, or a real injection payload is either
    (a) tokenized via this module's own keyed _keyed_tok() before it is
    stored anywhere in the returned dict, or (b) reduced to a boolean
    "detected" fact with no accompanying text. The final assembly step runs
    assert_no_forbidden_keys() over the whole bundle; a bug that somehow
    attached a raw-content key, or a secret-/injection-shaped value, raises
    ForbiddenBundleKeyError instead of returning silently.
    """
    vault_dir = pathlib.Path(vault_dir)
    try:
        vault_root = vault_dir.resolve()
    except OSError:
        vault_root = vault_dir

    now = resolve_now(now)

    scan_scope_out: Dict[str, Any] = {}
    limits: Dict[str, int] = {}
    entries: List[VaultEntry] = read_vault(
        vault_dir, max_files=max_files, max_file_bytes=max_file_bytes,
        limits=limits, include_ignored=include_ignored,
        scan_scope_out=scan_scope_out)

    files: List[Dict[str, Any]] = []
    signals: List[Dict[str, Any]] = []
    influence_edges: List[Dict[str, Any]] = []
    collision_pairs: List[Dict[str, Any]] = []

    total_size = 0
    total_tokens = 0

    # ── memory-vault file entries + per-entry secret/injection/stale signals ──
    local_roots = _local_roots(vault_dir, [])
    for e in entries:
        rel = _rel(e.file_path, vault_root)
        path_ptr = _keyed_tok("path", rel, pointer_key)
        mem_ptr = _keyed_tok("mem", e.memory_id, pointer_key)
        try:
            size_bytes = pathlib.Path(e.file_path).stat().st_size
        except OSError:
            size_bytes = 0
        est_tok = est_tokens(e.body)
        files.append({
            "path_pointer": path_ptr,
            "mem_pointer": mem_ptr,
            "kind": KIND_MEMORY,
            "surface_type": SURFACE_TYPE_VAULT_MD,
            "size_bytes": size_bytes,
            "est_tokens": est_tok,
        })
        total_size += size_bytes
        total_tokens += est_tok

        if e.body:
            if _SECRET_RE.search(e.body):
                signals.append(_new_signal(path_ptr, SIGNAL_SECRET_SHAPED, "high"))
            if _INJECTION_RE.search(e.body):
                signals.append(_new_signal(path_ptr, SIGNAL_INJECTION_SHAPED, "high"))

        if e.identity_ok and not e.body_truncated and e.body:
            unit = MemoryUnit(unit_id=e.memory_id, rel_path=rel,
                                       tier="on_demand", text=e.body)
            rotted = False
            for claim in extract_claims(unit, repo_names=[]):
                if claim.claim_class != "path":
                    continue
                verdict, _sig, _scope = probe_path(claim, local_roots)
                if verdict == ROTTED:
                    rotted = True
                    break
            if rotted:
                signals.append(_new_signal(path_ptr, SIGNAL_STALE_PATH_LOCAL, "high"))

    # ── duplicate_id (exact memory-id collision across files) ──
    by_id: Dict[str, List[VaultEntry]] = {}
    for e in entries:
        if not e.identity_ok:
            continue
        by_id.setdefault(e.memory_id, []).append(e)

    for mid, group in sorted(by_id.items()):
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda x: _rel(x.file_path, vault_root))
        ptrs = [_keyed_tok("path", _rel(g.file_path, vault_root), pointer_key)
               for g in ordered]
        hub, spokes = ptrs[0], ptrs[1:]
        for spoke in spokes:
            influence_edges.append({"from": hub, "to": spoke,
                                    "kind": EDGE_DUPLICATE_ID})
        for p in ptrs:
            signals.append(_new_signal(p, SIGNAL_DUPLICATE_ID, "high"))

    # ── collision_case_fold (distinct ids that fold to the same NFKC+casefold key) ──
    norm_groups: Dict[str, Set[str]] = {}
    for mid in by_id:
        key = unicodedata.normalize("NFKC", mid).casefold()
        norm_groups.setdefault(key, set()).add(mid)

    for key, ids in sorted(norm_groups.items()):
        if len(ids) < 2:
            continue
        sorted_ids = sorted(ids)
        collision_pairs.append({
            "fold_key_pointer": _keyed_tok("foldkey", key, pointer_key),
            "fingerprints": [_keyed_tok("mem", i, pointer_key) for i in sorted_ids],
        })
        for i in sorted_ids:
            rep = min(by_id[i], key=lambda x: _rel(x.file_path, vault_root))
            rep_ptr = _keyed_tok("path", _rel(rep.file_path, vault_root), pointer_key)
            signals.append(_new_signal(rep_ptr, SIGNAL_COLLISION_CASE_FOLD, "high"))

    # ── policy_collision (CLAUDE.md/AGENTS.md package-manager directive vs.
    # the repo's own lockfile; see the module-level note above
    # SIGNAL_POLICY_COLLISION) ──
    present_lockfiles = _detect_present_lockfiles(vault_root)
    if present_lockfiles:
        present_managers = set(present_lockfiles.values())
        # Deterministic pick when more than one lockfile is present: the
        # lexicographically-first filename names the "other side" of the
        # collision evidence.
        other_lockfile_name = sorted(present_lockfiles)[0]
        for e in entries:
            if pathlib.Path(e.file_path).name not in ("CLAUDE.md", "AGENTS.md"):
                continue
            directive = _detect_pkg_manager_directive(e.body)
            if directive is None or directive in present_managers:
                continue
            rel = _rel(e.file_path, vault_root)
            surface_ptr = _keyed_tok("path", rel, pointer_key)
            lock_ptr = _keyed_tok("path", other_lockfile_name, pointer_key)
            signals.append(_new_policy_collision_signal(
                surface_ptr, lock_ptr, POLICY_COLLISION_REASON_PKG_MANAGER_MISMATCH))

    # ── non-md context surfaces (CLAUDE.md, .cursor/rules, .claude/settings*, Codex) ──
    scanned_paths = {e.file_path for e in entries if e.file_path}
    for s in context_inventory.detect_surfaces(vault_root, scanned_paths):
        if s.classification == context_inventory.UNKNOWN:
            continue  # server-side / non-local: no path to fingerprint
        path_ptr = _keyed_tok("path", s.pointer, pointer_key)
        try:
            size_bytes = (vault_root / s.pointer).stat().st_size
        except OSError:
            size_bytes = 0
        est_tok = _est_tokens_from_bytes(size_bytes)
        files.append({
            "path_pointer": path_ptr,
            "mem_pointer": None,
            "kind": KIND_CONTEXT_SURFACE,
            "surface_type": s.surface_type,
            "size_bytes": size_bytes,
            "est_tokens": est_tok,
        })
        total_size += size_bytes
        total_tokens += est_tok

    # ── ai_authored / pr_ref (public PR metadata only: label/number/sha) ──
    pr = pr or {}
    is_ai, _free_text_reason = detect_ai_authored(
        pr, commit_message, label=ai_label, author_glob=ai_author_glob,
        trailer=ai_trailer)
    coded_reason = _coded_ai_authored_reason(
        pr, commit_message, label=ai_label, author_glob=ai_author_glob,
        trailer=ai_trailer)
    ai_authored = {"is_ai": is_ai, "reason": coded_reason}
    pr_ref: Optional[Dict[str, Any]] = None
    if pr:
        head = pr.get("head") or {}
        pr_ref = {"number": pr.get("number"), "head_sha": head.get("sha", "")}

    bundle: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_now": now,
        "vault_pointer": _keyed_tok("vault", str(vault_root), pointer_key),
        "files": files,
        "influence_edges": influence_edges,
        "signals": signals,
        "collision_pairs": collision_pairs,
        "scan_scope": {"excluded_count": scan_scope_out.get("excluded_count", 0)},
        "ai_authored": ai_authored,
        "pr_ref": pr_ref,
        "resource_stats": {
            "files_seen": limits.get("files_seen", 0),
            "files_read": limits.get("files_read", 0),
            "files_skipped_over_max": limits.get("files_skipped_over_max", 0),
            "files_truncated": limits.get("files_truncated", 0),
            "total_size_bytes": total_size,
            "total_est_tokens": total_tokens,
        },
    }

    # THE invariant: an unredacted bundle must be structurally impossible to
    # return. This call is not a test -- it runs on every real assembly.
    assert_no_forbidden_keys(bundle)
    return bundle
