"""shadow/cdr.py — the Context Decision Record (CDR), Muninn's atomic primitive.

A CDR is the training artifact a single context-selection decision leaves behind:
what candidate memories were considered, which were selected/rejected/blocked,
what each shadow policy WOULD have picked, the policy version and token budget in
force, and — accruing over time — the outcome events that decision earned. The
CDR is the substrate v0.1 exists to manufacture; it is NOT a claim that Muninn
selects context well. Value-per-token cannot be proven at current corpus volume
(see docs/context-governance-v0.md); the CDR is the ledger that COULD prove it
once enough of them accrue with memory joins and resolved outcomes.

This module is the schema-of-record and its validated loader. It is pure stdlib,
deterministic, and free of any I/O side effect beyond explicit load/dump helpers.
It reads nothing from the vault, writes nothing outside an explicit path argument,
and influences no live dispatch. Everything here is observe-only.

Design commitments encoded in the schema (each prevents a later rewrite):

  * candidates carry a `decision` from a CLOSED enum wide enough for v0.2/v0.3
    exploration (shadow_selected, exploration_selected, held_out, …) so adding an
    exploration slot needs no candidate-shape migration.
  * shadow_rankings is an ARRAY of policy verdicts, never a single baseline — the
    day a second or third shadow policy is added, it appends; it does not migrate.
  * outcomes is an ARRAY of outcome EVENTS, never one terminal object — a single
    decision accrues many outcomes over its life (test failed → patch revised →
    audit passed → PR merged), and the ledger must keep every one.
  * later-ready selection fields (selection_policy, selection_propensity,
    exploration_arm, random_seed) exist from line one so off-policy evaluation and
    contextual-bandit exploration in v0.2+ need no schema change.
  * per-candidate truth-rot fields are RESERVED (null in v0.1); the v0.3 engine
    fills them without a migration.
  * governance (retention_class, redaction_ref) is present from the first CDR —
    retention and redaction are not bolt-ons.
  * a top-level `extension` seam holds forward-compat keys no consumer may reject.

Nothing in a CDR may carry raw task text or raw memory body. task identity is a
hash; task shape is a feature vector; evidence is a POINTER (event id / file ref),
never a copied snippet. This is the "0 raw-text leakage" invariant, enforced by
`validate_cdr`.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any, Dict, List, Optional, Sequence

# ── Schema identity ────────────────────────────────────────────────────────────

SCHEMA_VERSION = "cdr-v0"

# ── Closed enums ───────────────────────────────────────────────────────────────

# A candidate's fate in THIS decision. Wide enough that v0.2 exploration slots and
# v0.3 policy learning append no new candidate shape — they only use more of these.
DECISION_VALUES: frozenset = frozenset({
    "selected",              # chosen by the live/observed policy
    "rejected",              # considered and dropped by the live/observed policy
    "blocked",               # withheld by a hard guard (tier/secret/injection)
    "deferred",              # eligible but not selected this turn (budget/rank)
    "shadow_selected",       # a shadow policy would have selected it
    "shadow_rejected",       # a shadow policy would have rejected it
    "exploration_selected",  # selected by an exploration arm (v0.2+)
    "required",              # forced in by policy (charter / standing rule)
    "held_out",              # deliberately withheld for evaluation (v0.2+)
    "unavailable",           # known candidate that could not be retrieved
})

# An outcome EVENT's resolution state. A CDR accrues many of these over time.
OUTCOME_STATUS_VALUES: frozenset = frozenset({
    "pending",       # observed, not yet resolved — UNKNOWN, never neutral
    "resolved_pos",  # resolved to a positive signal (STRONG or WEAK)
    "resolved_neg",  # resolved to a negative signal
    "neutral",       # resolved but signal is genuinely neutral (excluded from VPT)
    "abandoned",     # the task line was abandoned; no resolution will come
    "expired",       # a resolution window elapsed with no signal
    "censored",      # right-censored: outcome exists but is unobservable to us
})

# The states that count as a *resolved, VPT-eligible* outcome (pos/neg only).
RESOLVED_STATUSES: frozenset = frozenset({"resolved_pos", "resolved_neg"})

# What an outcome event attributes to. A CDR-level outcome (task) differs from a
# per-memory attribution; keeping this explicit is what lets v0.3 do credit
# assignment without re-deriving it from prose.
APPLIES_TO_VALUES: frozenset = frozenset({
    "selected",   # the selected set as a whole
    "candidate",  # a specific candidate (memory_id carried on the event)
    "policy",     # a specific shadow/live policy
    "memory",     # a specific memory across its exposures
    "task",       # the task/dispatch as a whole
})

POLARITY_VALUES: frozenset = frozenset({"POSITIVE", "NEGATIVE", "NEUTRAL"})

# Admission lanes (see shadow/admission.py). Reserved on candidates as `lifecycle`.
LANE_VALUES: frozenset = frozenset({
    "Reject", "Quarantine", "Probation", "Active", "Canonical", "Retired",
    "unknown",
})

# Retention classes (governance). Deliberately coarse in v0.1.
RETENTION_CLASS_VALUES: frozenset = frozenset({
    "standard", "extended", "ephemeral", "legal_hold",
})

# Truth-decay classes (schema-only in v0.1; v0.3 engine fills the values).
TRUTH_DECAY_CLASS_VALUES: frozenset = frozenset({
    "static", "slow", "moderate", "volatile", "unknown",
})


# ── Reserved sub-structures ────────────────────────────────────────────────────

def _empty_truth_rot() -> Dict[str, Any]:
    """Per-candidate truth-rot fields, reserved in v0.1 (all null / unknown).

    The v0.3 re-verification engine fills these; reserving them now means no
    per-candidate migration when it lands (design item 8).
    """
    return {
        "review_interval":     None,   # e.g. "P30D" ISO-8601 duration
        "last_verified_at":    None,   # ISO-8601; NOT derived from file mtime
        "verification_method": None,   # e.g. "human", "corroboration", "citation"
        "truth_decay_class":   "unknown",
        "staleness_risk":      None,   # float 0..1 once the engine computes it
    }


def new_candidate(
    memory_id: str,
    *,
    decision: str,
    relevance: Optional[float] = None,
    lifecycle: str = "unknown",
    source_tier: Optional[int] = None,
    risk_class: Optional[str] = None,
    vpt_estimate: Optional[float] = None,
    confidence: Optional[float] = None,
    sample_n: int = 0,
    reason: str = "",
    truth_rot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one schema-complete candidate record.

    `decision` must be in DECISION_VALUES. `reason` is a short machine-readable
    token (e.g. "tier_ok", "budget_exceeded"), never raw memory text.
    """
    return {
        "memory_id":    memory_id,
        "relevance":    relevance,
        "lifecycle":    lifecycle,
        "source_tier":  source_tier,
        "risk_class":   risk_class,
        "vpt_estimate": vpt_estimate,
        "confidence":   confidence,
        "sample_n":     sample_n,
        "decision":     decision,
        "reason":       reason,
        "truth_rot":    truth_rot if truth_rot is not None else _empty_truth_rot(),
    }


def new_shadow_ranking(
    policy_name: str,
    policy_version: str,
    *,
    selected_ids: Optional[Sequence[str]] = None,
    ranked_candidates: Optional[Sequence[str]] = None,
    scores: Optional[Dict[str, float]] = None,
    token_cost: Optional[int] = None,
    blocked_ids: Optional[Sequence[str]] = None,
    reason: str = "",
) -> Dict[str, Any]:
    """Build one shadow-policy verdict (one entry of the shadow_rankings array).

    Each shadow policy that would have ranked/selected this decision's candidates
    contributes one of these. The live/observed policy MAY also be represented
    here (so the backfill can record "what actually happened" as a policy row).
    """
    return {
        "policy_name":       policy_name,
        "policy_version":    policy_version,
        "selected_ids":      list(selected_ids or []),
        "ranked_candidates": list(ranked_candidates or []),
        "scores":            dict(scores or {}),
        "token_cost":        token_cost,
        "blocked_ids":       list(blocked_ids or []),
        "reason":            reason,
    }


def new_outcome(
    outcome_id: str,
    *,
    status: str,
    signal: str = "",
    polarity: str = "NEUTRAL",
    trust_tier: str = "NONE",
    evidence_ref: str = "",
    observed_at: str = "",
    resolved_at: Optional[str] = None,
    source: str = "shadow",
    confidence: Optional[float] = None,
    applies_to: str = "task",
    memory_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one outcome EVENT (one entry of the outcomes array).

    `evidence_ref` is a POINTER (event id, file ref) — never a copied snippet of
    transcript or memory body. `memory_id` is set only when applies_to indicates a
    per-candidate/per-memory attribution.
    """
    return {
        "outcome_id":   outcome_id,
        "status":       status,
        "signal":       signal,
        "polarity":     polarity,
        "trust_tier":   trust_tier,
        "evidence_ref": evidence_ref,
        "observed_at":  observed_at,
        "resolved_at":  resolved_at,
        "source":       source,
        "confidence":   confidence,
        "applies_to":   applies_to,
        "memory_id":    memory_id,
    }


def new_task_features(
    *,
    task_type: str = "unknown",
    risk_class: str = "unknown",
    repo_area: str = "unknown",
    language: str = "unknown",
    objective_class: str = "unknown",
    source_ref: str = "",
    redaction_level: str = "features_only",
) -> Dict[str, Any]:
    """Task SHAPE without any raw task text (features-only; item 2 invariant)."""
    return {
        "task_type":       task_type,
        "risk_class":      risk_class,
        "repo_area":       repo_area,
        "language":        language,
        "objective_class": objective_class,
        "source_ref":      source_ref,        # a pointer (session/dispatch id)
        "redaction_level": redaction_level,
    }


def new_governance(
    *,
    retention_class: str = "standard",
    redaction_ref: Optional[str] = None,
) -> Dict[str, Any]:
    """Governance block — present from line one (item 2)."""
    return {
        "retention_class": retention_class,
        "redaction_ref":   redaction_ref,
    }


def task_hash(*parts: str) -> str:
    """Stable content hash for task identity (NOT raw text stored anywhere).

    A dispatch's prompt/description are hashed to a fingerprint so two identical
    tasks share a task_hash without either task's text ever entering a CDR.
    """
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()[:16]


def new_cdr(
    cdr_id: str,
    *,
    timestamp: str,
    policy_version: str,
    token_budget: Optional[int],
    task_ref: Dict[str, Any],
    task_features: Optional[Dict[str, Any]] = None,
    candidates: Optional[Sequence[Dict[str, Any]]] = None,
    selected: Optional[Sequence[str]] = None,
    shadow_rankings: Optional[Sequence[Dict[str, Any]]] = None,
    outcomes: Optional[Sequence[Dict[str, Any]]] = None,
    governance: Optional[Dict[str, Any]] = None,
    selection_policy: Optional[str] = None,
    selection_propensity: Optional[float] = None,
    exploration_arm: Optional[str] = None,
    random_seed: Optional[int] = None,
    provenance: str = "backfill",
) -> Dict[str, Any]:
    """Assemble a schema-complete CDR dict.

    Every reserved seam is present (as null / empty), so no consumer has to guard
    for a missing key and no later phase has to migrate a stored CDR to add one.
    outcome_rollup is derived here from `outcomes`.
    """
    cdr: Dict[str, Any] = {
        "schema_version":       SCHEMA_VERSION,
        "id":                   cdr_id,
        "timestamp":            timestamp,
        "policy_version":       policy_version,
        "token_budget":         token_budget,
        "provenance":           provenance,
        "task_ref":             dict(task_ref),
        "task_features":        task_features if task_features is not None
                                else new_task_features(),
        "candidates":           [dict(c) for c in (candidates or [])],
        "selected":             list(selected or []),
        # Later-ready selection fields (item on shadow_rankings): exist from day 1.
        "selection_policy":     selection_policy,
        "selection_propensity": selection_propensity,
        "exploration_arm":      exploration_arm,
        "random_seed":          random_seed,
        "shadow_rankings":      [dict(s) for s in (shadow_rankings or [])],
        "outcomes":             [dict(o) for o in (outcomes or [])],
        "governance":           governance if governance is not None
                                else new_governance(),
        "extension":            {},   # forward-compat seam; consumers must ignore
    }
    cdr["outcome_rollup"] = compute_outcome_rollup(cdr)
    return cdr


# ── Derived rollup ─────────────────────────────────────────────────────────────

def compute_outcome_rollup(cdr: Dict[str, Any]) -> Dict[str, Any]:
    """Summarise a CDR's outcomes array into a derived rollup.

    UNKNOWN is not neutral: a CDR with only `pending` outcomes rolls up to
    resolution_state="unknown", NOT "neutral". This honesty is load-bearing —
    treating pending as neutral would silently manufacture evidence that does not
    exist (design thesis).
    """
    outcomes = cdr.get("outcomes") or []
    n = len(outcomes)
    resolved_pos = sum(1 for o in outcomes if o.get("status") == "resolved_pos")
    resolved_neg = sum(1 for o in outcomes if o.get("status") == "resolved_neg")
    neutral = sum(1 for o in outcomes if o.get("status") == "neutral")
    censored = sum(1 for o in outcomes if o.get("status") == "censored")
    pending = sum(1 for o in outcomes if o.get("status") == "pending")
    strong_resolved = sum(
        1 for o in outcomes
        if o.get("status") in RESOLVED_STATUSES
        and str(o.get("trust_tier", "")).upper() == "STRONG"
    )
    resolved = resolved_pos + resolved_neg

    if resolved > 0:
        # NEGATIVE beats POSITIVE (pessimistic, matches outcome_scorer resolution)
        state = "resolved_neg" if resolved_neg > 0 else "resolved_pos"
    elif n == 0 or pending > 0:
        state = "unknown"
    elif censored > 0:
        state = "censored"
    elif neutral > 0:
        state = "neutral"
    else:
        state = "unknown"

    return {
        "n_outcomes":       n,
        "resolved_pos":     resolved_pos,
        "resolved_neg":     resolved_neg,
        "neutral":          neutral,
        "censored":         censored,
        "pending":          pending,
        "strong_resolved":  strong_resolved,
        "resolution_state": state,
        "has_resolved":     resolved > 0,
    }


def is_resolved(cdr: Dict[str, Any]) -> bool:
    """True iff the CDR carries at least one VPT-eligible resolved outcome."""
    return any(o.get("status") in RESOLVED_STATUSES
               for o in (cdr.get("outcomes") or []))


def selected_memory_ids(cdr: Dict[str, Any]) -> List[str]:
    """The memory ids this CDR actually selected (its `selected` list)."""
    return list(cdr.get("selected") or [])


def has_memory_join(cdr: Dict[str, Any]) -> bool:
    """True iff the CDR selected at least one concrete memory id."""
    return len(selected_memory_ids(cdr)) > 0


# ── Validation ─────────────────────────────────────────────────────────────────

_TASK_REF_KEYS = ("agent_name", "role", "repo", "task_hash")
_TASK_FEATURE_KEYS = ("task_type", "risk_class", "repo_area", "language",
                      "objective_class", "source_ref", "redaction_level")

# Keys that must never appear anywhere in a CDR — raw-text leakage guards.
# A CDR carries hashes, feature tokens, and pointers, never prose.
_FORBIDDEN_TEXT_KEYS = frozenset({
    "prompt", "message", "raw_text", "body", "transcript_text",
    "assistant_text", "memory_body", "snippet", "clause",
})


def _add(errors: List[str], cond: bool, msg: str) -> None:
    if not cond:
        errors.append(msg)


def _scan_forbidden(obj: Any, path: str, errors: List[str]) -> None:
    """Recursively assert no raw-text key leaked into the CDR (item invariant)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _FORBIDDEN_TEXT_KEYS:
                errors.append(f"{path}.{k}: raw-text key is forbidden in a CDR")
            _scan_forbidden(v, f"{path}.{k}", errors)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_forbidden(v, f"{path}[{i}]", errors)


def validate_cdr(cdr: Any) -> List[str]:
    """Return a list of schema-violation strings for one CDR ([] == valid).

    Validation is total and side-effect-free. It enforces: presence of every
    required top-level field and reserved seam; closed-enum membership for every
    decision/status/applies_to/polarity/lane/retention value; array-shape for
    shadow_rankings and outcomes (never a bare object); features-only task shape;
    and the no-raw-text invariant across the whole document.
    """
    errors: List[str] = []
    if not isinstance(cdr, dict):
        return ["cdr is not a JSON object"]

    _add(errors, cdr.get("schema_version") == SCHEMA_VERSION,
         f"schema_version must be {SCHEMA_VERSION!r}, got {cdr.get('schema_version')!r}")
    for key in ("id", "timestamp", "policy_version"):
        _add(errors, bool(cdr.get(key)), f"missing/empty required field: {key}")
    _add(errors, "token_budget" in cdr, "missing required field: token_budget")
    _add(errors, "extension" in cdr and isinstance(cdr.get("extension"), dict),
         "missing/invalid extension seam (must be an object)")

    # task_ref
    tr = cdr.get("task_ref")
    if not isinstance(tr, dict):
        errors.append("task_ref must be an object")
    else:
        for k in _TASK_REF_KEYS:
            _add(errors, k in tr, f"task_ref missing key: {k}")

    # task_features (features-only)
    tf = cdr.get("task_features")
    if not isinstance(tf, dict):
        errors.append("task_features must be an object")
    else:
        for k in _TASK_FEATURE_KEYS:
            _add(errors, k in tf, f"task_features missing key: {k}")

    # candidates
    cands = cdr.get("candidates")
    if not isinstance(cands, list):
        errors.append("candidates must be an array")
    else:
        for i, c in enumerate(cands):
            if not isinstance(c, dict):
                errors.append(f"candidates[{i}] must be an object")
                continue
            _add(errors, bool(c.get("memory_id")),
                 f"candidates[{i}] missing memory_id")
            _add(errors, c.get("decision") in DECISION_VALUES,
                 f"candidates[{i}].decision {c.get('decision')!r} not in DECISION_VALUES")
            _add(errors, c.get("lifecycle") in LANE_VALUES,
                 f"candidates[{i}].lifecycle {c.get('lifecycle')!r} not in LANE_VALUES")
            _add(errors, "truth_rot" in c and isinstance(c["truth_rot"], dict),
                 f"candidates[{i}] missing reserved truth_rot block")

    # selected
    _add(errors, isinstance(cdr.get("selected"), list),
         "selected must be an array of memory ids")

    # shadow_rankings — MUST be an array (never a single baseline object)
    sr = cdr.get("shadow_rankings")
    if not isinstance(sr, list):
        errors.append("shadow_rankings must be an ARRAY (not a single object)")
    else:
        for i, s in enumerate(sr):
            if not isinstance(s, dict):
                errors.append(f"shadow_rankings[{i}] must be an object")
                continue
            for k in ("policy_name", "policy_version", "selected_ids",
                      "ranked_candidates", "scores", "blocked_ids"):
                _add(errors, k in s, f"shadow_rankings[{i}] missing key: {k}")

    # outcomes — MUST be an array (never a single terminal object)
    outs = cdr.get("outcomes")
    if not isinstance(outs, list):
        errors.append("outcomes must be an ARRAY (not a single object)")
    else:
        for i, o in enumerate(outs):
            if not isinstance(o, dict):
                errors.append(f"outcomes[{i}] must be an object")
                continue
            _add(errors, o.get("status") in OUTCOME_STATUS_VALUES,
                 f"outcomes[{i}].status {o.get('status')!r} not in OUTCOME_STATUS_VALUES")
            _add(errors, o.get("applies_to") in APPLIES_TO_VALUES,
                 f"outcomes[{i}].applies_to {o.get('applies_to')!r} not in APPLIES_TO_VALUES")
            _add(errors, o.get("polarity") in POLARITY_VALUES,
                 f"outcomes[{i}].polarity {o.get('polarity')!r} not in POLARITY_VALUES")
            _add(errors, bool(o.get("outcome_id")),
                 f"outcomes[{i}] missing outcome_id")

    # governance
    gov = cdr.get("governance")
    if not isinstance(gov, dict):
        errors.append("governance must be an object")
    else:
        _add(errors, gov.get("retention_class") in RETENTION_CLASS_VALUES,
             f"governance.retention_class {gov.get('retention_class')!r} invalid")
        _add(errors, "redaction_ref" in gov,
             "governance missing redaction_ref key")

    # outcome_rollup present and consistent
    _add(errors, "outcome_rollup" in cdr and isinstance(cdr["outcome_rollup"], dict),
         "missing derived outcome_rollup")

    # no-raw-text invariant across the whole document
    _scan_forbidden(cdr, "cdr", errors)

    return errors


def is_valid(cdr: Any) -> bool:
    return not validate_cdr(cdr)


# ── I/O helpers (explicit path only; observe-only) ─────────────────────────────

def load_cdrs(path: pathlib.Path) -> List[Dict[str, Any]]:
    """Tolerantly load a CDR JSONL file. utf-8; blank/malformed lines skipped;
    missing file → []. Read-only."""
    try:
        raw = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def dump_cdrs(cdrs: Sequence[Dict[str, Any]], path: pathlib.Path) -> pathlib.Path:
    """Write CDRs as JSONL to an explicit path. utf-8. Creates parent dirs."""
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cdrs),
        encoding="utf-8",
    )
    return p
