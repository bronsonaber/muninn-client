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
