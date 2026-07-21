"""shadow/capture.py, the evidence faucet: a live context-decision event -> a CDR.

Wave 3 productizes passive capture. Until now the only way a CDR ledger accrued
was the maintainer's daily batch pipeline (shadow/cdr_backfill over a fleet report),
hardcoded to one laptop's layout. This module is the OTHER accrual path: a single
context-decision event captured live by an assistant hook, turned into one valid
Context Decision Record, appended idempotently to a ledger the user configured.

Three commitments make this a product a non-maintainer can run for 30 days untouched:

  1. ZERO hardcoded personal paths. Every path (repo, vault, corpus, ledger) is
     DERIVED from the user's own environment and the init flags. `resolve_config`
     never references the maintainer's home, repo, or Claude project slug. A user
     whose HOME, repo path, and assistant corpus differ accrues to THEIR paths.

  2. HONEST CDRs. A live capture is a context-selection decision with no resolved
     outcome yet, so its outcome is `pending` (UNKNOWN, never neutral), exactly
     the discipline shadow/cdr.py enforces. The CDR carries the selected memory
     ids and their candidates (a real memory join), and accrues resolved outcomes
     later; it never manufactures a signal it does not have.

  3. THE EVIDENCE ELIGIBILITY GATE. "Access is not influence" is Muninn's
     founding rule: merely LOOKING at the context surface (a Glob/Grep listing
     or search over the vault) is not the same act as READING one concrete
     memory. `_resolve_boundary` is the single seam between a raw capture event
     and a CDR's `selected` list, and it enforces that distinction as two hard
     rules:
       a. A `searched_context_surface` event (Grep/Glob/any listing or search)
          NEVER yields a selected id, full stop, regardless of what path or
          directory it named. It may still be recorded as a searched event; it
          is never `learning_eligible` or `vpt_eligible`.
       b. An `accessed_memory` event (a concrete Read) yields a selected id
          ONLY when its target is a real memory FILE (never a directory) whose
          resolved id is REGISTRY-CONFIRMED - currently enumerable under the
          configured vault. Anything that fails either check is quarantined as
          an `unresolved_pointer`: recorded for audit in the CDR's
          `extension.boundary`, never placed in `selected`, never eligible.
     This boundary state is written onto every CDR at `extension.boundary`
     (the seed of a future Context Boundary Observation Model / CBOM), so
     eligibility is explicit and auditable, not an implicit side effect of
     what happened to be in `selected`.

Pure stdlib, deterministic, utf-8. Reads nothing from the vault beyond a single
memory file's frontmatter to resolve its id (a pointer, never its body), plus a
head-only frontmatter scan of the vault's own *.md files to confirm registry
membership (same read discipline: identity only, never a body). Writes only the
configured ledger. Fail-safe by design in hook mode: a capture fault degrades
to a skipped event, never a broken assistant session.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

_here = pathlib.Path(__file__).parent
if str(_here.parent) not in sys.path:
    sys.path.insert(0, str(_here.parent))

from shadow import cdr as cdrlib  # noqa: E402

try:
    import fcntl  # POSIX only

    def _lock(f) -> None:
        fcntl.flock(f, fcntl.LOCK_EX)

    def _unlock(f) -> None:
        fcntl.flock(f, fcntl.LOCK_UN)
except ImportError:  # Windows: single-process fallback (documented, same as logger)
    def _lock(f) -> None:
        pass

    def _unlock(f) -> None:
        pass


POLICY_VERSION = "capture/live-hook-v1"

# Assistants whose live capture is wired today. Others are DETECTED and configured
# for surface inventory, but degrade with a clear "capture not yet supported" line
# rather than pretending to accrue.
SUPPORTED_ASSISTANTS = frozenset({"claude"})
KNOWN_ASSISTANTS = frozenset({"claude", "cursor", "codex"})

# Privacy modes. `standard` stores the resolved memory id (needed for the memory
# join). `strict` stores a hash of it instead, so no filename-derived token leaves
# the machine, the join still works across exposures, the label never does.
PRIVACY_MODES = frozenset({"standard", "strict"})

# ── The Evidence Eligibility Gate: boundary-state ladder ────────────────────────
#
# "Access is not influence" used to be enforced as a single cut: a search never
# selects, a read always does (and was always eligible the moment it selected).
# That collapsed two different claims into one flag. A Read PROVES access; it
# does not prove the model ever used what it read. The ladder below separates
# them into four honest rungs, cheapest evidence first:
#
#   searched_context_surface : observed the surface only. Never selects.
#   accessed_memory           : a concrete Read of one memory. Access, not
#                                influence - NOT eligible on its own.
#   rendered_to_model          : the memory's content demonstrably reached the
#                                model's context/output (e.g. join-integrity
#                                content-in-output evidence). Eligible for
#                                learning; still not proof it drove an action.
#   used_in_action /
#   outcome_linked              : tied to a decision artifact (join-integrity
#                                decision-tied evidence) or a RESOLVED outcome
#                                actually joined to this CDR. Eligible for both
#                                learning and VPT - this is the only rung that
#                                is real evidence of influence.
#
# A live hook capture (see `_resolve_boundary`) only ever OBSERVES the bottom
# two rungs - at capture time there is no transcript and no outcome yet (the
# module's HONEST CDRs commitment). The top two rungs are reached later, once
# real evidence exists, via `recompute_boundary_eligibility`.

# A concrete Read of one memory file: the only boundary state a live capture
# can ever yield a selected memory id from (and only when registry-confirmed;
# see `_resolve_boundary`). Access, not influence: NOT eligible by itself.
BOUNDARY_ACCESSED_MEMORY = "accessed_memory"

# A Glob/Grep/listing or search over the vault surface: observes WHICH memories
# exist, never WHICH one was used. Access is not influence - this boundary
# state can NEVER yield a selected memory id, full stop.
BOUNDARY_SEARCHED_SURFACE = "searched_context_surface"

# The memory's content was demonstrably rendered into the model's context or
# output (content-in-output evidence, e.g. join-integrity strength>=2). Real
# consumption, not yet tied to a decision or a resolved outcome.
BOUNDARY_RENDERED_TO_MODEL = "rendered_to_model"

# The memory is tied to a decision artifact (commit/PR/rationale - join-
# integrity decision-tied evidence, strength>=3). Influence evidence.
BOUNDARY_USED_IN_ACTION = "used_in_action"

# The CDR this memory was selected into now carries a RESOLVED outcome
# (`shadow.cdr.is_resolved`) - a real outcome join, not a pending guess.
# Influence evidence, same eligibility tier as `used_in_action`.
BOUNDARY_OUTCOME_LINKED = "outcome_linked"

BOUNDARY_STATES = frozenset({
    BOUNDARY_ACCESSED_MEMORY, BOUNDARY_SEARCHED_SURFACE,
    BOUNDARY_RENDERED_TO_MODEL, BOUNDARY_USED_IN_ACTION, BOUNDARY_OUTCOME_LINKED,
})

# Boundary states that may carry a selected memory id - every rung except a
# pure surface search, which can never select, full stop.
_SELECTABLE_BOUNDARY_STATES = BOUNDARY_STATES - {BOUNDARY_SEARCHED_SURFACE}

# The eligibility ladder itself: for each boundary state, whether it counts as
# learning_eligible / vpt_eligible. Access (searched_context_surface,
# accessed_memory) never qualifies for either. rendered_to_model qualifies for
# learning only (real consumption, not yet proven influence). used_in_action /
# outcome_linked qualify for both - the only rungs backed by evidence that the
# memory actually shaped an action or its outcome.
BOUNDARY_ELIGIBILITY: Dict[str, Dict[str, bool]] = {
    BOUNDARY_SEARCHED_SURFACE:  {"learning_eligible": False, "vpt_eligible": False},
    BOUNDARY_ACCESSED_MEMORY:   {"learning_eligible": False, "vpt_eligible": False},
    BOUNDARY_RENDERED_TO_MODEL: {"learning_eligible": True,  "vpt_eligible": False},
    BOUNDARY_USED_IN_ACTION:    {"learning_eligible": True,  "vpt_eligible": True},
    BOUNDARY_OUTCOME_LINKED:    {"learning_eligible": True,  "vpt_eligible": True},
}

# Claude Code tool names that constitute a concrete read of one file.
READ_TOOLS = frozenset({"Read", "read_file"})
# Claude Code tool names that constitute a search/listing over a surface, never
# a selection of one memory.
SEARCH_TOOLS = frozenset({"Grep", "Glob"})

# Vault memory-file extensions this registry recognizes. A path outside this
# set - including every directory - can never resolve to a memory id: this is
# the kill-shot fix (a Glob/Grep hit on a directory must never become a
# "selected" memory).
MEMORY_FILE_EXTENSIONS = frozenset({".md"})


# ── Path derivation (the de-hardcoding core) ───────────────────────────────────

def _env_home(env: Optional[Dict[str, str]] = None) -> pathlib.Path:
    env = env if env is not None else os.environ
    home = env.get("HOME") or env.get("USERPROFILE")
    if home:
        return pathlib.Path(home)
    return pathlib.Path("~").expanduser()


def claude_project_slug(path: pathlib.Path) -> str:
    """Claude Code's per-project transcript-dir encoding of an absolute path.

    Claude stores a project's transcripts under ``~/.claude/projects/<slug>`` where
    the slug is the absolute working directory with the path separators and dots
    replaced by ``-`` (e.g. ``/Users/jane/work/acme`` -> ``-Users-jane-work-acme``).
    Derived from the USER's own path, so it is correct for any home directory.

    Cross-platform: both separators (``/`` and ``\\``) and the Windows drive-letter
    colon are folded to ``-`` so no ``/``, ``\\``, ``.`` or ``:`` survives, and the
    slug always begins with a dash. POSIX output for a normal path is unchanged
    (a POSIX path carries no ``\\`` or ``:``); Windows ``C:\\Users\\jane`` becomes
    ``-C--Users-jane`` instead of leaking backslashes and the drive colon.
    """
    ap = str(pathlib.Path(path).expanduser().resolve())
    # Fold every path separator, the dot, and the Windows drive colon to a dash.
    slug = re.sub(r"[\\/.:]", "-", ap)
    # POSIX absolute paths already lead with the separator (now a dash); a Windows
    # path leads with a drive letter, so guarantee the leading dash either way.
    if not slug.startswith("-"):
        slug = "-" + slug
    return slug


@dataclass
class CaptureConfig:
    """A fully-derived, personal-path-free capture configuration."""
    assistant: str
    repo: str            # absolute path to the user's repo / working dir
    vault: str           # absolute path to the user's memory vault
    corpus: str          # absolute path to the assistant transcript corpus dir
    ledger_dir: str      # absolute path to the muninn state dir (holds cdrs.jsonl)
    cdrs_path: str       # absolute path to the CDR ledger file
    privacy_mode: str
    supported: bool      # True iff live capture is wired for this assistant

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _first_existing(candidates: Sequence[pathlib.Path]) -> Optional[pathlib.Path]:
    for c in candidates:
        try:
            if c.exists():
                return c
        except OSError:
            continue
    return None


def resolve_config(
    *,
    assistant: Optional[str] = None,
    repo: Optional[str] = None,
    vault: Optional[str] = None,
    corpus: Optional[str] = None,
    ledger_dir: Optional[str] = None,
    privacy_mode: str = "standard",
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> CaptureConfig:
    """Derive every path from the USER's environment + explicit flags only.

    Precedence for each path: explicit flag > matching env var > a default derived
    from the user's HOME / repo. Nothing here references the maintainer's layout.
    """
    env = env if env is not None else dict(os.environ)
    home = _env_home(env)
    cwd_path = pathlib.Path(cwd).expanduser() if cwd else pathlib.Path.cwd()

    # repo: flag > cwd. (`.` and relative flags resolve against cwd.)
    repo_p = pathlib.Path(repo).expanduser() if repo else cwd_path
    if not repo_p.is_absolute():
        repo_p = (cwd_path / repo_p)
    repo_p = _safe_resolve(repo_p)

    asst = (assistant or env.get("MUNINN_ASSISTANT") or _sniff_assistant(repo_p, home)
            or "claude").lower()

    # vault: flag > env > first existing of user-local candidates > repo.
    if vault:
        vault_p = _safe_resolve(pathlib.Path(vault).expanduser())
    elif env.get("MUNINN_VAULT"):
        vault_p = _safe_resolve(pathlib.Path(env["MUNINN_VAULT"]).expanduser())
    else:
        vault_p = _safe_resolve(_first_existing([
            home / "memory",
            repo_p / ".claude",
            home / ".claude",
        ]) or repo_p)

    # ledger dir: flag > env(LEDGER_DIR/MUNINN_LEDGER_DIR) > <home>/.muninn.
    if ledger_dir:
        ledger_p = pathlib.Path(ledger_dir).expanduser()
    elif env.get("MUNINN_LEDGER_DIR"):
        ledger_p = pathlib.Path(env["MUNINN_LEDGER_DIR"]).expanduser()
    elif env.get("LEDGER_DIR"):
        ledger_p = pathlib.Path(env["LEDGER_DIR"]).expanduser()
    else:
        ledger_p = home / ".muninn"
    ledger_p = _safe_resolve(ledger_p)

    # corpus: flag > env > per-assistant default derived from the user's paths.
    if corpus:
        corpus_p = _safe_resolve(pathlib.Path(corpus).expanduser())
    elif env.get("MUNINN_CORPUS"):
        corpus_p = _safe_resolve(pathlib.Path(env["MUNINN_CORPUS"]).expanduser())
    else:
        corpus_p = _default_corpus(asst, home, repo_p)

    pm = privacy_mode if privacy_mode in PRIVACY_MODES else "standard"

    return CaptureConfig(
        assistant=asst,
        repo=str(repo_p),
        vault=str(vault_p),
        corpus=str(corpus_p),
        ledger_dir=str(ledger_p),
        cdrs_path=str(ledger_p / "cdrs.jsonl"),
        privacy_mode=pm,
        supported=asst in SUPPORTED_ASSISTANTS,
    )


def _safe_resolve(p: pathlib.Path) -> pathlib.Path:
    try:
        return p.resolve()
    except OSError:
        return p.absolute()


def _default_corpus(assistant: str, home: pathlib.Path,
                    repo: pathlib.Path) -> pathlib.Path:
    """Per-assistant default transcript-corpus dir, derived from the user's paths."""
    if assistant == "claude":
        # Claude stores per-project transcripts under the slug of the working dir.
        return home / ".claude" / "projects" / claude_project_slug(repo)
    if assistant == "cursor":
        return home / ".cursor"
    if assistant == "codex":
        return repo / ".codex"
    return home / ".muninn" / "corpus"


def _sniff_assistant(repo: pathlib.Path, home: pathlib.Path) -> Optional[str]:
    """Best-effort assistant detection from surfaces present on disk."""
    try:
        if (repo / ".cursor").exists() or (repo / ".cursorrules").exists():
            return "cursor"
        if (repo / ".codex").exists():
            return "codex"
        if (repo / "CLAUDE.md").exists() or (repo / ".claude").exists() \
                or (home / ".claude").exists():
            return "claude"
    except OSError:
        pass
    return None


# ── memory-id resolution (a pointer, never the body) ───────────────────────────

_FM_NAME_RE = re.compile(r"^name:\s*(.+?)\s*$", re.MULTILINE)


def resolve_memory_id(file_path: str, privacy_mode: str = "standard") -> str:
    """Resolve a memory file's stable id: frontmatter ``name:`` else filename stem.

    Only the head of the file is read, and only to extract the id token, never the
    body. In ``strict`` privacy mode the id is hashed so no filename-derived label
    leaves the machine while the join across exposures still holds.
    """
    p = pathlib.Path(file_path)
    mem_id = p.stem
    try:
        head = p.read_text(encoding="utf-8", errors="replace")[:4096]
        if head.startswith("---"):
            end = head.find("---", 3)
            block = head[3:end] if end != -1 else head[3:]
            m = _FM_NAME_RE.search(block)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                if val and val.lower() not in ("null", "~", "none", ""):
                    mem_id = val
    except OSError:
        pass
    if privacy_mode == "strict":
        return "mem_" + cdrlib.task_hash(mem_id)
    return mem_id


def _is_concrete_memory_file(path: pathlib.Path) -> bool:
    """True iff `path` is a real FILE (never a directory, missing path, or
    anything else) with a recognized vault memory extension.

    This is a hard, unconditional gate: a directory can NEVER become a memory
    id, independent of privacy mode or registry membership. This is what
    closes the kill-shot (a Glob's directory hit resolving to a memory id via
    `pathlib.Path(dir).stem`).
    """
    try:
        if not path.is_file():
            return False
    except OSError:
        return False
    return path.suffix.lower() in MEMORY_FILE_EXTENSIONS


def _vault_registry(vault: str, privacy_mode: str) -> frozenset:
    """Enumerate the stable memory id of every *.md file under `vault` - the
    registry a `selected` id must confirm against.

    Mirrors `resolve_memory_id`'s own identity rule (frontmatter `name:` else
    filename stem), computed under the SAME privacy_mode, so registry
    membership is checked against the exact identity a concrete read would
    produce. Read-only, head-only per file (same discipline as
    resolve_memory_id: identity only, never a body). A missing/unreadable
    vault yields an empty registry rather than raising - capture is fail-safe
    by design.
    """
    ids: set = set()
    try:
        root = pathlib.Path(vault).expanduser().resolve()
    except OSError:
        return frozenset(ids)
    if not root.is_dir():
        return frozenset(ids)
    try:
        for md in root.rglob("*.md"):
            if not md.is_file():
                continue
            ids.add(resolve_memory_id(str(md), privacy_mode))
    except OSError:
        pass
    return frozenset(ids)


# ── event -> CDR ────────────────────────────────────────────────────────────────

def _resolve_boundary(event: Dict[str, Any], config: CaptureConfig) -> Dict[str, Any]:
    """The Evidence Eligibility Gate: the ONLY seam a raw capture event may cross
    to become a `selected` memory id. See the module docstring (commitment 3)
    and the boundary-state ladder comment above BOUNDARY_ACCESSED_MEMORY.

    A live capture event carries no transcript and no outcome (HONEST CDRs:
    the outcome is genuinely pending at capture time), so this function can
    only ever land on the bottom two rungs of the ladder -
    BOUNDARY_SEARCHED_SURFACE or BOUNDARY_ACCESSED_MEMORY - and NEITHER is
    learning/vpt eligible on its own. Elevating a memory to
    rendered_to_model/used_in_action/outcome_linked happens later, once real
    evidence exists, via `recompute_boundary_eligibility`.

    Returns a boundary block (written verbatim onto the CDR's
    `extension.boundary`, the CBOM seed):
      state:                the resolved boundary state (see BOUNDARY_STATES)
      selected:             registry-confirmed memory ids, safe for `selected`
      unresolved_pointers:  quarantined ids/paths - recorded, never selected
      learning_eligible:    True iff `selected` is non-empty AND this state's
                             rung in BOUNDARY_ELIGIBILITY grants learning
      vpt_eligible:         True iff `selected` is non-empty AND this state's
                             rung in BOUNDARY_ELIGIBILITY grants vpt
    """
    boundary_state = str(event.get("boundary_state") or BOUNDARY_ACCESSED_MEMORY)
    if boundary_state not in BOUNDARY_STATES:
        boundary_state = BOUNDARY_ACCESSED_MEMORY

    if boundary_state == BOUNDARY_SEARCHED_SURFACE:
        # A search/listing observes the surface; it selects nothing, full stop.
        # (requirement 2: access is not influence)
        return {
            "state": boundary_state,
            "selected": [],
            "unresolved_pointers": [],
            "learning_eligible": False,
            "vpt_eligible": False,
        }

    # BOUNDARY_ACCESSED_MEMORY: gather every candidate pointer the event
    # asserts, then gate each one through the file-vs-directory check and the
    # registry-confirmation check before it may enter `selected`.
    raw_ids: List[str] = []
    ids = event.get("memory_ids")
    if isinstance(ids, list) and ids:
        raw_ids = [str(x) for x in ids]
    elif event.get("memory_id"):
        raw_ids = [str(event["memory_id"])]

    fp = event.get("file_path")

    selected: List[str] = []
    unresolved: List[str] = []
    registry: Optional[frozenset] = None

    def _registry() -> frozenset:
        nonlocal registry
        if registry is None:
            registry = _vault_registry(config.vault, config.privacy_mode)
        return registry

    if raw_ids:
        # An explicit id assertion (CLI / backfill passthrough) still needs
        # registry confirmation - a gate a caller can name around is no gate.
        for mid in raw_ids:
            (selected if mid in _registry() else unresolved).append(mid)
    elif fp:
        p = pathlib.Path(str(fp)).expanduser()
        if not _is_concrete_memory_file(p):
            # A directory (or any non-memory-file path) can NEVER become a
            # memory id (requirement 3) - quarantined, never selected.
            unresolved.append(str(fp))
        else:
            mid = resolve_memory_id(str(fp), config.privacy_mode)
            (selected if mid in _registry() else unresolved).append(mid)

    # A live-hook event may only ever resolve to accessed_memory here (its
    # boundary_state input is always one of the two bottom rungs - see the
    # module docstring); a caller asserting a higher rung with no selected id
    # still gets nothing (eligibility always requires a real selection).
    eligibility = BOUNDARY_ELIGIBILITY.get(
        boundary_state, {"learning_eligible": False, "vpt_eligible": False})
    return {
        "state": boundary_state,
        "selected": selected,
        "unresolved_pointers": unresolved,
        "learning_eligible": bool(selected) and eligibility["learning_eligible"],
        "vpt_eligible": bool(selected) and eligibility["vpt_eligible"],
    }


def recompute_boundary_eligibility(
    cdr: Dict[str, Any], *, join_strength: Optional[int] = None,
) -> Dict[str, Any]:
    """Re-derive a captured CDR's boundary eligibility once real evidence exists.

    `_resolve_boundary` runs at live-capture time from one isolated event with
    no transcript and no outcome - by construction it can only ever land on
    `accessed_memory` or `searched_context_surface`. Elevating a memory past
    `accessed_memory` therefore has to happen LATER, from evidence that did
    not exist at capture time. This is the legitimate mechanism the safety
    constraint requires: demoting a bare Read must not dark out VPT for
    memories that were genuinely used, so a bare Read is left NOT eligible
    only until - and unless - one of these shows up:

      * a RESOLVED outcome now joined to this CDR (`cdrlib.is_resolved`, the
        same resolved_pos/resolved_neg check the rest of the pipeline uses -
        e.g. the GOLD-outcome-append pattern the eligibility-gate tests
        already exercise) -> elevated to `outcome_linked`.
      * a join-integrity strength score for this CDR's selection, computed by
        `shadow/join_integrity.py`'s adversarial grading (content-in-output or
        decision-tied evidence) and passed in by the caller as
        `join_strength` (that module's own 0-3 scale) -> `used_in_action` at
        strength>=3 (decision-tied), `rendered_to_model` at strength>=2
        (content-in-output).

    A resolved outcome outranks a join-integrity score - it is the strongest
    evidence this codebase has that a decision actually happened. Never
    mutates `cdr` in place; returns a NEW boundary block for the caller to
    persist however it likes (e.g. write back onto `cdr["extension"]
    ["boundary"]`, or record separately in a reconciliation pass). A CDR with
    no selected memory, or whose boundary is a pure surface search, comes back
    unchanged - there is nothing to elevate.
    """
    boundary = dict((cdr.get("extension") or {}).get("boundary") or {})
    state = boundary.get("state")
    selected = boundary.get("selected") or []
    if not selected or state not in _SELECTABLE_BOUNDARY_STATES:
        return boundary

    if cdrlib.is_resolved(cdr):
        new_state = BOUNDARY_OUTCOME_LINKED
    elif join_strength is not None and join_strength >= 3:
        new_state = BOUNDARY_USED_IN_ACTION
    elif join_strength is not None and join_strength >= 2:
        new_state = BOUNDARY_RENDERED_TO_MODEL
    else:
        new_state = state

    eligibility = BOUNDARY_ELIGIBILITY[new_state]
    boundary["state"] = new_state
    boundary["learning_eligible"] = eligibility["learning_eligible"]
    boundary["vpt_eligible"] = eligibility["vpt_eligible"]
    return boundary


def event_to_cdr(event: Dict[str, Any], config: CaptureConfig) -> Dict[str, Any]:
    """Build one schema-complete, honest CDR from a live context-decision event.

    The event is a small dict a hook assembles: at minimum a ``session_id``; plus
    any of ``memory_id`` / ``memory_ids`` / ``file_path`` (the selected memory),
    ``turn_id``, ``agent``, ``role``, ``repo``, ``ts``, ``event_type``, ``source``,
    ``boundary_state``. Nothing raw enters the CDR: task identity is a hash,
    evidence is a pointer. What may become a `selected` memory id is decided
    entirely by `_resolve_boundary` (the Evidence Eligibility Gate).
    """
    session_id = str(event.get("session_id") or "unknown")
    turn_id = str(event.get("turn_id") or "")
    # A live capture legitimately records WHEN it happened; when the hook payload
    # carries no timestamp we stamp UTC now (a real event time, not a fabricated
    # signal). Callers needing determinism pass an explicit `ts`.
    ts = str(event.get("ts") or datetime.now(timezone.utc).isoformat())
    source = str(event.get("source") or "hook")
    event_type = str(event.get("event_type") or "context_capture")
    agent = str(event.get("agent") or "assistant")
    role = str(event.get("role") or "assistant")
    repo = str(event.get("repo") or pathlib.Path(config.repo).name or "unknown")

    boundary = _resolve_boundary(event, config)
    selected = boundary["selected"]

    candidates = [
        cdrlib.new_candidate(
            mid,
            decision="selected",
            lifecycle="unknown",
            reason=source,   # machine token (the capture source), never memory text
        )
        for mid in selected
    ]
    for c in candidates:
        c["capture_source"] = source
        c["capture_confidence"] = "demonstrated"

    task_ref = {
        "agent_name": agent,
        "role":       role,
        "repo":       repo,
        "task_hash":  cdrlib.task_hash(session_id, turn_id, ",".join(selected)),
    }
    task_features = cdrlib.new_task_features(
        task_type="live_context_capture",
        risk_class="normal",
        repo_area=repo,
        language="unknown",
        objective_class="unknown",
        source_ref=f"{config.assistant}:{session_id}",  # a pointer, not text
        redaction_level="features_only",
    )
    shadow_rankings = [
        cdrlib.new_shadow_ranking(
            "observed_harness", POLICY_VERSION,
            selected_ids=selected, ranked_candidates=selected,
            token_cost=None, blocked_ids=[],
            reason="live capture from the assistant hook (as-observed)",
        )
    ]
    # Outcome is genuinely UNKNOWN at capture time -> pending (never neutral).
    outcome = cdrlib.new_outcome(
        f"cap-{session_id}-{turn_id or '0'}-o0",
        status="pending",
        signal="unknown",
        polarity="NEUTRAL",
        trust_tier="NONE",
        evidence_ref=f"capture:{config.assistant}:{session_id}:{turn_id}",
        observed_at=ts,
        resolved_at=None,
        source="capture",
        confidence=None,
        applies_to="task",
    )

    cdr_id = "cap-" + cdrlib.task_hash(session_id, turn_id, ",".join(selected), ts)
    cdr = cdrlib.new_cdr(
        cdr_id,
        timestamp=ts,
        policy_version=POLICY_VERSION,
        token_budget=None,
        task_ref=task_ref,
        task_features=task_features,
        candidates=candidates,
        selected=selected,
        shadow_rankings=shadow_rankings,
        outcomes=[outcome],
        governance=cdrlib.new_governance(retention_class="standard",
                                         redaction_ref=None),
        selection_policy="observed_harness",
        selection_propensity=None,
        exploration_arm=None,
        random_seed=None,
        provenance="capture",
    )
    cdr["extension"]["capture"] = {
        "assistant":  config.assistant,
        "event_type": event_type,
        "source":     source,
        "privacy_mode": config.privacy_mode,
    }
    cdr["extension"]["join_status"] = "live_capture"
    cdr["extension"]["boundary"] = boundary
    return cdr


# ── idempotent ledger append ───────────────────────────────────────────────────

def _existing_ids(cdrs_path: pathlib.Path) -> set:
    ids: set = set()
    if not cdrs_path.exists():
        return ids
    try:
        for line in cdrs_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("id"):
                ids.add(obj["id"])
    except OSError:
        pass
    return ids


def append_cdr(cdr: Dict[str, Any], cdrs_path: pathlib.Path) -> bool:
    """Append one CDR to the ledger, idempotent on its id. Returns True if written.

    Concurrency-safe on POSIX via flock on a dedicated lock file (same discipline
    as the event logger). Creates the ledger dir if missing.
    """
    cdrs_path = pathlib.Path(cdrs_path)
    cdrs_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = cdrs_path.parent / (cdrs_path.name + ".lock")
    with open(lock_path, "w") as lock_f:
        _lock(lock_f)
        try:
            if cdr.get("id") in _existing_ids(cdrs_path):
                return False
            with open(cdrs_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(cdr, ensure_ascii=False) + "\n")
            return True
        finally:
            _unlock(lock_f)


def capture_event(event: Dict[str, Any], config: CaptureConfig) -> Dict[str, Any]:
    """Turn a live event into a CDR, validate it, and append it to the ledger.

    A schema-invalid CDR is NEVER written (a malformed substrate is worse than
    none), validation failure raises. Returns a small result dict.
    """
    cdr = event_to_cdr(event, config)
    errs = cdrlib.validate_cdr(cdr)
    if errs:
        raise ValueError(f"refusing to write invalid CDR {cdr.get('id')}: {errs}")
    written = append_cdr(cdr, pathlib.Path(config.cdrs_path))
    return {
        "cdr_id":   cdr["id"],
        "written":  written,
        "cdrs_path": config.cdrs_path,
        "selected": cdr["selected"],
        "valid":    True,
    }


# ── Claude Code hook payload mapping ───────────────────────────────────────────

def event_from_claude_hook(payload: Dict[str, Any],
                           config: CaptureConfig) -> Optional[Dict[str, Any]]:
    """Map a Claude Code hook payload to a capture event, or None to skip.

    Claude Code delivers hook JSON on stdin. Two tool classes are captured, and
    they are tagged with DIFFERENT boundary states (the Evidence Eligibility
    Gate then enforces what each may become - see `_resolve_boundary`):
      * Read/read_file - a concrete access of ONE file -> `accessed_memory`.
      * Grep/Glob       - a search/listing over a surface -> `searched_context_
                           surface`; this can NEVER become a selected memory,
                           no matter what path or directory it named.
    Only events whose target lives under the configured vault are captured, so
    ordinary source reads/searches never inflate the ledger.
    """
    tool = str(payload.get("tool_name") or "")
    if tool in READ_TOOLS:
        boundary_state = BOUNDARY_ACCESSED_MEMORY
        event_type = "mem_read"
    elif tool in SEARCH_TOOLS:
        boundary_state = BOUNDARY_SEARCHED_SURFACE
        event_type = "context_search"
    else:
        return None
    tool_input = payload.get("tool_input") or {}
    fp = tool_input.get("file_path") or tool_input.get("path")
    if not fp:
        return None
    try:
        target = pathlib.Path(str(fp)).expanduser().resolve()
        vault = pathlib.Path(config.vault).resolve()
        if vault not in target.parents and target != vault:
            return None
    except OSError:
        return None
    return {
        "session_id": payload.get("session_id"),
        "turn_id":    payload.get("turn_id") or payload.get("uuid"),
        "file_path":  str(fp),
        "repo":       pathlib.Path(payload.get("cwd") or config.repo).name,
        "event_type": event_type,
        "source":     "claude_hook",
        "boundary_state": boundary_state,
    }


# ── CLI (invoked by the generated hook) ────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="muninn-capture",
        description="Append one CDR from a live context-decision event (the faucet).")
    p.add_argument("--assistant", default=None)
    p.add_argument("--repo", default=None)
    p.add_argument("--vault", default=None)
    p.add_argument("--corpus", default=None)
    p.add_argument("--ledger-dir", default=None)
    p.add_argument("--privacy", default="standard", choices=sorted(PRIVACY_MODES))
    p.add_argument("--from-hook", action="store_true",
                   help="read a Claude Code hook JSON payload on stdin and map it")
    p.add_argument("--event-json", default=None,
                   help="a capture event as JSON ('-' reads stdin)")
    p.add_argument("--session-id", default=None)
    p.add_argument("--file-path", default=None)
    p.add_argument("--memory-id", default=None)
    p.add_argument("--strict-exit", action="store_true",
                   help="exit nonzero on capture error (default: fail-safe exit 0)")
    return p


def main(argv: Optional[Sequence[str]] = None, stdout=None, stdin=None) -> int:
    args = _build_parser().parse_args(argv)
    out = stdout or sys.stdout
    inp = stdin or sys.stdin
    try:
        config = resolve_config(
            assistant=args.assistant, repo=args.repo, vault=args.vault,
            corpus=args.corpus, ledger_dir=args.ledger_dir,
            privacy_mode=args.privacy)

        event: Optional[Dict[str, Any]] = None
        if args.from_hook:
            raw = inp.read()
            payload = json.loads(raw) if raw.strip() else {}
            event = event_from_claude_hook(payload, config)
            if event is None:
                return 0  # not a memory-read context event; nothing to capture
        elif args.event_json:
            raw = inp.read() if args.event_json == "-" else args.event_json
            event = json.loads(raw)
        else:
            event = {
                "session_id": args.session_id,
                "file_path":  args.file_path,
                "memory_id":  args.memory_id,
                "source":     "cli",
            }

        if not config.supported:
            print(f"muninn-capture: live capture not yet supported for "
                  f"'{config.assistant}'; event skipped.", file=sys.stderr)
            return 0

        result = capture_event(event, config)
        out.write(json.dumps(result) + "\n")
        return 0
    except Exception as e:  # fail-safe: a capture fault must never break a session
        print(f"muninn-capture: skipped ({e})", file=sys.stderr)
        return 1 if args.strict_exit else 0


if __name__ == "__main__":
    raise SystemExit(main())
