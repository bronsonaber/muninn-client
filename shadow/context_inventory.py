"""shadow/context_inventory.py, `muninn inventory`: context-surface coverage.

THE PROBLEM THIS CLOSES (the adversarial audit's kill-shot):
    `muninn doctor` scans the *.md memory vault and can report COMPLETE with a
    great health score while the agent is still steered by context Muninn never
    looked at: .cursor/rules/*.mdc, .cursorrules, AGENTS.md, .claude/ settings,
    Codex instruction files, an MCP memory server. If those go uninspected AND
    unmentioned, "Agent Context Governance" collapses into "Markdown vault lint"
    and the report can emit a FALSE clean bill of health.

    The fix is not more findings. It is COVERAGE HONESTY: the doctor must be
    explicit about what context surfaces it did and did NOT inspect, and it must
    fail closed (never COMPLETE) when a surface that influences the agent is
    present but unscanned.

WHAT THIS MODULE DOES (Wave 2a, the honesty layer only):
    Given a target root and the set of file paths the doctor actually read, it
    DETECTS the context surfaces that can influence an agent and CLASSIFIES each:

      SCANNED                 Muninn read this file this run (it is in the
                              scanned set). Proof, not assumption: the class is
                              derived from what read_vault actually read.
      DETECTED_BUT_UNSCANNED  present and agent-influencing, but the doctor does
                              NOT inspect it today (e.g. a .cursor/rules/*.mdc
                              always-apply rule, a .cursorrules file, .claude
                              settings, a Codex config file).
      UNKNOWN                 not introspectable from the filesystem at all
                              (e.g. an MCP memory server's server-side store).

    It then derives a coverage status:
      FULL_CONTEXT_COVERAGE     every detected surface was scanned.
      PARTIAL_CONTEXT_COVERAGE  at least one surface is DETECTED_BUT_UNSCANNED.
      UNKNOWN_CONTEXT_COVERAGE  no unscanned local surface, but a non-
                                introspectable (UNKNOWN) surface is present.

    NOT in this wave (see docs/HARDENING_BACKLOG.md): actually PARSING/auditing
    the new surfaces (reading .mdc rules for contradictions, etc.), a coverage
    benchmark + Verified Context Coverage Recall (VCCR) metric, and a --auto root
    detector. This module only inventories and classifies; it never reads a
    surface's semantic content to raise a finding.

Design rules match the rest of Muninn: pure stdlib, deterministic (no wall
clock), utf-8, graceful (a detector that raises is skipped, never fatal), and
it emits vault-relative pointers only (the doctor's redactor tokenises them),
never raw bodies.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Sequence, Set

_here = pathlib.Path(__file__).parent
if str(_here.parent) not in sys.path:
    sys.path.insert(0, str(_here.parent))

# ── Classification vocabulary ────────────────────────────────────────────────
SCANNED = "SCANNED"
DETECTED_BUT_UNSCANNED = "DETECTED_BUT_UNSCANNED"
UNKNOWN = "UNKNOWN"

# ── Coverage status vocabulary ───────────────────────────────────────────────
FULL_CONTEXT_COVERAGE = "FULL_CONTEXT_COVERAGE"
PARTIAL_CONTEXT_COVERAGE = "PARTIAL_CONTEXT_COVERAGE"
UNKNOWN_CONTEXT_COVERAGE = "UNKNOWN_CONTEXT_COVERAGE"

# The one-line authority statement stamped on every report. Findings are scoped
# to what was scanned; this sentence says so out loud.
AUTHORITY_LINE = ("Report authority: findings apply only to the scanned "
                  "surfaces.")

# Bounded discovery: never enumerate an unbounded tree. A pathological vault
# (millions of files) cannot make inventory hang; past the cap we stop globbing
# for a pattern (the doctor's own read_vault ceiling is the real scan bound).
_MAX_MATCHES = 4000
# Per-file read cap when sniffing a config for a memory-server signal.
_SNIFF_BYTES = 200_000


@dataclass
class Surface:
    """One detected context surface and how it is classified."""
    surface_type: str     # stable machine key (e.g. "cursor_rules")
    label: str            # human label (e.g. ".cursor/rules/*.mdc")
    pointer: str          # vault-relative path, count, or "(server-side)"
    classification: str   # SCANNED | DETECTED_BUT_UNSCANNED | UNKNOWN
    influence: str        # one line: how this surface steers the agent


# ── Bounded discovery helpers ────────────────────────────────────────────────

def _rglob(root: pathlib.Path, pattern: str) -> List[pathlib.Path]:
    out: List[pathlib.Path] = []
    try:
        for p in root.rglob(pattern):
            out.append(p)
            if len(out) >= _MAX_MATCHES:
                break
    except OSError:
        pass
    return out


def _rel(p: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return p.name


def _resolved(p: pathlib.Path) -> str:
    try:
        return str(p.resolve())
    except OSError:
        return str(p)


# ── Surface detectors ────────────────────────────────────────────────────────
# Each detector returns concrete files. Whether a detected FILE is SCANNED or
# DETECTED_BUT_UNSCANNED is decided against the scanned-path set (ground truth:
# what read_vault actually read), never assumed. UNKNOWN surfaces are handled
# separately since they are not local files.

def _find_claude_md(root: pathlib.Path) -> List[pathlib.Path]:
    return [p for p in _rglob(root, "CLAUDE.md") if p.is_file()]


def _find_agents_md(root: pathlib.Path) -> List[pathlib.Path]:
    return [p for p in _rglob(root, "AGENTS.md") if p.is_file()]


def _find_cursor_rules(root: pathlib.Path) -> List[pathlib.Path]:
    # Cursor project rules: .cursor/rules/**/*.mdc (always-apply / auto-attached
    # rule files). The .mdc extension is NOT read by read_vault.
    return [p for p in _rglob(root, "*.mdc")
            if p.is_file() and ".cursor" in p.parts]


def _find_cursorrules(root: pathlib.Path) -> List[pathlib.Path]:
    # Legacy single-file Cursor rules.
    return [p for p in _rglob(root, ".cursorrules") if p.is_file()]


def _find_claude_settings(root: pathlib.Path) -> List[pathlib.Path]:
    out: List[pathlib.Path] = []
    for name in ("settings.json", "settings.local.json"):
        out += [p for p in _rglob(root, name)
                if p.is_file() and ".claude" in p.parts]
    return out


def _find_codex_config(root: pathlib.Path) -> List[pathlib.Path]:
    # Codex .codex/ config files (config.toml, etc.). Codex's AGENTS.md
    # instruction file is covered by _find_agents_md; a .md under .codex is
    # scanned by read_vault and will classify SCANNED via the scanned set.
    out: List[pathlib.Path] = []
    for d in _rglob(root, ".codex"):
        try:
            if not d.is_dir():
                continue
            for f in d.rglob("*"):
                if f.is_file():
                    out.append(f)
                    if len(out) >= _MAX_MATCHES:
                        return out
        except OSError:
            continue
    return out


# surface_type -> (human label, influence sentence, finder)
_FILE_DETECTORS = [
    ("claude_md", "CLAUDE.md",
     "project/system instructions loaded into the agent's context on every run.",
     _find_claude_md),
    ("agents_md", "AGENTS.md",
     "agent operating instructions (Codex / multi-agent) that steer behaviour.",
     _find_agents_md),
    ("cursor_rules", ".cursor/rules/*.mdc",
     "Cursor project rules that can be always-apply or auto-attached, silently "
     "prepended to the agent's context.",
     _find_cursor_rules),
    ("cursorrules_legacy", ".cursorrules",
     "legacy single-file Cursor rules prepended to the agent's context.",
     _find_cursorrules),
    ("claude_settings", ".claude/settings*.json",
     "Claude Code settings/permissions/hooks that shape what the agent may do "
     "and what runs around it.",
     _find_claude_settings),
    ("codex_config", ".codex/ config",
     "Codex configuration files that influence how the agent runs.",
     _find_codex_config),
]

# Files sniffed for an MCP memory-server signal (an UNKNOWN, server-side store).
_MCP_MEMORY_HINT = re.compile(r"memory", re.IGNORECASE)


def _find_mcp_configs(root: pathlib.Path) -> List[pathlib.Path]:
    out: List[pathlib.Path] = []
    out += [p for p in _rglob(root, ".mcp.json") if p.is_file()]
    out += [p for p in _rglob(root, "mcp.json")
            if p.is_file() and ".cursor" in p.parts]
    out += _find_claude_settings(root)
    return out


def _detect_unknown_surfaces(root: pathlib.Path) -> List[Surface]:
    """An MCP memory server injects stored memories into the agent's context,
    but its store lives server-side and is NOT a local file Muninn can read. If
    a memory-bearing MCP config is present, record the server-side store as an
    UNKNOWN surface (coverage cannot be full when a non-introspectable memory
    source is wired in)."""
    for p in _find_mcp_configs(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")[:_SNIFF_BYTES]
        except OSError:
            continue
        low = text.lower()
        if _MCP_MEMORY_HINT.search(low) and (
                "mcpservers" in low or "command" in low
                or p.name in (".mcp.json", "mcp.json")):
            return [Surface(
                surface_type="mcp_memory_server",
                label="MCP memory server (server-side store)",
                pointer="(server-side, not introspectable)",
                classification=UNKNOWN,
                influence="an MCP memory server can inject stored memories into "
                          "the agent's context; its server-side store is not a "
                          "local file Muninn can read, so its contents are "
                          "outside this report.",
            )]
    return []


def detect_surfaces(root: pathlib.Path,
                    scanned_paths: Set[str]) -> List[Surface]:
    """Detect every context surface under ``root`` and classify each. A detected
    FILE is SCANNED iff its resolved path is in ``scanned_paths`` (what the
    doctor actually read), else DETECTED_BUT_UNSCANNED. UNKNOWN surfaces are
    non-local and always UNKNOWN. Deterministic order."""
    surfaces: List[Surface] = []
    for surface_type, label, influence, finder in _FILE_DETECTORS:
        try:
            files = finder(root)
        except Exception:
            files = []
        for f in files:
            cls = SCANNED if _resolved(f) in scanned_paths \
                else DETECTED_BUT_UNSCANNED
            surfaces.append(Surface(
                surface_type=surface_type, label=label,
                pointer=_rel(f, root), classification=cls, influence=influence))
    try:
        surfaces.extend(_detect_unknown_surfaces(root))
    except Exception:
        pass
    surfaces.sort(key=lambda s: (s.classification, s.surface_type, s.pointer))
    return surfaces


def coverage_status(surfaces: Sequence[Surface]) -> str:
    """FULL only when nothing is unscanned/unknown. DETECTED_BUT_UNSCANNED
    dominates (a concrete local surface we skipped); UNKNOWN alone downgrades to
    UNKNOWN_CONTEXT_COVERAGE."""
    if any(s.classification == DETECTED_BUT_UNSCANNED for s in surfaces):
        return PARTIAL_CONTEXT_COVERAGE
    if any(s.classification == UNKNOWN for s in surfaces):
        return UNKNOWN_CONTEXT_COVERAGE
    return FULL_CONTEXT_COVERAGE


def build_coverage(root: pathlib.Path,
                   entries: Optional[Sequence[Any]] = None,
                   scanned_paths: Optional[Set[str]] = None,
                   vault_file_count: Optional[int] = None) -> Dict[str, Any]:
    """Build the Context Influence Map block for a report.

    ``scanned_paths`` (resolved absolute path strings the doctor read) is the
    ground truth for SCANNED; when omitted it is derived from ``entries``
    (VaultEntry.file_path). A synthetic 'memory vault' SCANNED row summarises
    what was audited so the map always shows the positive coverage too.

    ``vault_file_count`` sets the count shown on the memory-vault row. Wave 2b
    unions the audited NON-md context surfaces into ``scanned_paths`` (so they
    classify SCANNED, not merely detected), which would otherwise inflate the
    memory-vault row; passing the *.md file count keeps that row honest."""
    root = pathlib.Path(root)
    if scanned_paths is None:
        scanned_paths = set()
        for e in entries or []:
            fp = getattr(e, "file_path", None)
            if fp:
                scanned_paths.add(str(fp))

    surfaces = detect_surfaces(root, scanned_paths)
    vault_count = len(scanned_paths) if vault_file_count is None else vault_file_count
    # Positive-coverage summary row: the *.md memory vault the doctor audited.
    surfaces.insert(0, Surface(
        surface_type="memory_vault",
        label="memory vault (*.md files)",
        pointer=f"{vault_count} file(s)",
        classification=SCANNED,
        influence="the *.md memory files Muninn read and audited this run."))

    status = coverage_status(surfaces)
    counts = {SCANNED: 0, DETECTED_BUT_UNSCANNED: 0, UNKNOWN: 0}
    for s in surfaces:
        counts[s.classification] = counts.get(s.classification, 0) + 1

    def _group(cls: str) -> List[Dict[str, Any]]:
        return [asdict(s) for s in surfaces if s.classification == cls]

    return {
        "coverage_status": status,
        "authority_line": AUTHORITY_LINE,
        "counts": counts,
        "scanned": _group(SCANNED),
        "detected_but_unscanned": _group(DETECTED_BUT_UNSCANNED),
        "unknown": _group(UNKNOWN),
        "unscanned_surface_types": sorted({
            s.surface_type for s in surfaces
            if s.classification in (DETECTED_BUT_UNSCANNED, UNKNOWN)}),
    }


# ── Root auto-detection (--auto), the wrong-root footgun guard ───────────────
# A first user who points Muninn at the wrong directory (an empty repo, a parent
# with no memory) gets a technically-clean report that is meaningless. --auto
# detects where the agent-context actually lives and recommends the right scan,
# so a false-clean on the wrong root is not possible by accident.

@dataclass
class RootCandidate:
    path: str
    signals: List[str]     # which context kinds are present here
    md_count: int          # *.md files under this root (bounded)
    score: int             # ranking score (higher = stronger context root)


# Per-signal weight. A real memory vault (many *.md) and steering surfaces both
# mark a genuine context root; a lone stray CLAUDE.md scores less than a vault.
_ROOT_SIGNAL_WEIGHT = {
    "cursor_rules": 5, "cursorrules_legacy": 5, "claude_settings": 4,
    "codex_config": 3, "claude_md": 5, "agents_md": 5, "mcp_memory": 2,
    "memory_vault": 4,
}


# Root detection is SHALLOW and BOUNDED on purpose: it must be cheap enough to run
# over ~10 candidate dirs (including ~/.claude and a start dir's parents) without
# ever traversing the whole filesystem. A context root is identified by top-level
# markers, not by a deep recursive scan.
_MAX_MD_WALK_ENTRIES = 5000    # dir entries examined before md-count gives up
_MD_COUNT_CAP = 64             # enough to know "this is a vault"; stop counting there
_ROOT_SKIP_DIRS = frozenset({".git", "node_modules", "backups", ".venv",
                             "venv", "__pycache__", ".mypy_cache",
                             ".pytest_cache", "site-packages"})


def _bounded_md_count(d: pathlib.Path) -> int:
    """Count *.md files under ``d`` with a hard ceiling on both matches and the
    number of directory entries walked, so a giant tree cannot hang detection."""
    count = 0
    entries = 0
    try:
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in _ROOT_SKIP_DIRS
                       and not x.startswith(".git")]
            for f in files:
                entries += 1
                if f.endswith(".md"):
                    count += 1
                    if count >= _MD_COUNT_CAP:
                        return count
                if entries >= _MAX_MD_WALK_ENTRIES:
                    return count
    except OSError:
        return count
    return count


def _any_mdc(d: pathlib.Path) -> bool:
    try:
        for p in d.iterdir():
            if p.is_file() and p.suffix == ".mdc":
                return True
            if p.is_dir():
                for q in p.iterdir():
                    if q.is_file() and q.suffix == ".mdc":
                        return True
    except OSError:
        return False
    return False


def _root_signals(d: pathlib.Path) -> Tuple[List[str], int]:
    """Which context kinds are present AT directory ``d`` (top-level markers),
    plus its bounded *.md count. Shallow and bounded; never raises."""
    signals: List[str] = []
    try:
        if (d / "CLAUDE.md").is_file():
            signals.append("claude_md")
        if (d / "AGENTS.md").is_file():
            signals.append("agents_md")
        rules_dir = d / ".cursor" / "rules"
        if rules_dir.is_dir() and _any_mdc(rules_dir):
            signals.append("cursor_rules")
        if (d / ".cursorrules").is_file():
            signals.append("cursorrules_legacy")
        claude_dir = d / ".claude"
        if claude_dir.is_dir() and (
                (claude_dir / "settings.json").is_file()
                or (claude_dir / "settings.local.json").is_file()):
            signals.append("claude_settings")
        if (d / ".codex").is_dir():
            signals.append("codex_config")
        if (d / ".mcp.json").is_file() or (d / ".cursor" / "mcp.json").is_file():
            signals.append("mcp_memory")
        md_count = _bounded_md_count(d)
        if md_count > 0:
            signals.append("memory_vault")
    except OSError:
        return [], 0
    return signals, md_count


def detect_context_roots(start: pathlib.Path,
                         home: Optional[pathlib.Path] = None,
                         extra_roots: Optional[Sequence[pathlib.Path]] = None,
                         ) -> List[RootCandidate]:
    """Detect candidate context roots at and around ``start``: ``start`` itself,
    its parents up to (and including) ``home``, and the well-known ~/memory and
    ~/.claude roots. Returns signal-bearing candidates ranked strongest-first
    (deterministic: score desc, then path). Bounded and never raises."""
    start = pathlib.Path(start).expanduser()
    home = pathlib.Path(home).expanduser() if home else pathlib.Path.home()
    try:
        start_res = start.resolve()
    except OSError:
        start_res = start
    try:
        home_res = home.resolve()
    except OSError:
        home_res = home

    # Ordered, de-duplicated candidate directories.
    seen: Set[str] = set()
    dirs: List[pathlib.Path] = []

    def _add(p: pathlib.Path) -> None:
        try:
            rp = p.expanduser().resolve()
        except OSError:
            return
        if not rp.is_dir():
            return
        key = str(rp)
        if key not in seen:
            seen.add(key)
            dirs.append(rp)

    _add(start_res)
    # Walk parents up to home (inclusive), but at most a few levels, so a scan
    # launched from a subdirectory still finds the CLAUDE.md/AGENTS.md/.cursor root
    # above it WITHOUT ever climbing to the filesystem root and scanning system
    # dirs. A candidate shallower than 2 path components (e.g. "/", "/tmp") is
    # never a context root and is skipped.
    cur = start_res
    for _ in range(6):  # bounded parent walk
        if str(cur) == str(home_res) or cur == cur.parent:
            break
        cur = cur.parent
        if len(cur.parts) >= 2:
            _add(cur)
        if str(cur) == str(home_res):
            break
    _add(home / "memory")
    _add(home / ".claude")
    for r in extra_roots or []:
        _add(pathlib.Path(r))

    candidates: List[RootCandidate] = []
    for d in dirs:
        signals, md_count = _root_signals(d)
        if not signals:
            continue
        score = sum(_ROOT_SIGNAL_WEIGHT.get(s, 1) for s in signals)
        # Slightly reward a substantial vault so a real memory dir outranks a lone
        # stray file, without letting size dominate a surface-rich root.
        score += min(md_count, 10)
        candidates.append(RootCandidate(
            path=str(d), signals=sorted(signals), md_count=md_count, score=score))

    candidates.sort(key=lambda c: (-c.score, c.path))
    return candidates


def recommend_root(candidates: Sequence[RootCandidate]) -> Optional[RootCandidate]:
    """The single recommended root, or None when it is ambiguous (a tie at the
    top) or nothing was found. Ambiguity returns None ON PURPOSE: better to ask
    than to silently scan the wrong strong candidate."""
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    if candidates[0].score > candidates[1].score:
        return candidates[0]
    return None


def render_roots(candidates: Sequence[RootCandidate],
                 recommended: Optional[RootCandidate]) -> str:
    L = ["MUNINN --auto: detected context roots (where your agent context lives)"]
    if not candidates:
        L.append("  none found. No CLAUDE.md, AGENTS.md, .cursor rules, .cursorrules,")
        L.append("  .claude settings, Codex config, or *.md memory vault was detected")
        L.append("  at or around the start path. Point --vault at your memory vault")
        L.append("  or the directory that holds your agent's context.")
        return "\n".join(L) + "\n"
    for c in candidates:
        mark = "  * " if (recommended and c.path == recommended.path) else "    "
        L.append(f"{mark}{c.path}")
        L.append(f"        signals: {', '.join(c.signals)}  "
                 f"(*.md files: {c.md_count}, score {c.score})")
    if recommended:
        L.append("")
        L.append(f"recommended scan: muninn doctor --vault {recommended.path}")
    else:
        L.append("")
        L.append("AMBIGUOUS: multiple equally-strong roots. Re-run with an explicit")
        L.append("--vault <path> from the list above; Muninn will not guess which one")
        L.append("you meant (guessing risks a false-clean on the wrong root).")
    return "\n".join(L) + "\n"


# ── CLI (`muninn inventory`), observe-only ───────────────────────────────────

def render_text(coverage: Dict[str, Any], root: str) -> str:
    L = [f"CONTEXT INFLUENCE MAP for {root}",
         f"coverage: {coverage['coverage_status']}",
         coverage["authority_line"], ""]

    def _emit(heading: str, rows: List[Dict[str, Any]]) -> None:
        L.append(f"{heading}: {len(rows)}")
        for s in rows:
            L.append(f"  - [{s['label']}] {s['pointer']}")
            L.append(f"      influence: {s['influence']}")

    _emit("SCANNED (audited)", coverage.get("scanned", []))
    _emit("DETECTED_BUT_UNSCANNED (unaudited, influences the agent)",
          coverage.get("detected_but_unscanned", []))
    _emit("UNKNOWN (not introspectable)", coverage.get("unknown", []))
    return "\n".join(L) + "\n"


def main(argv: Optional[Sequence[str]] = None, stdout=None) -> int:
    """Observe-only inventory over a target root. Reads *.md to learn what the
    doctor would scan, then reports which context surfaces are and are not
    covered. Writes nothing."""
    from shadow._bundle_primitives import read_vault  # local import: keep module import light

    p = argparse.ArgumentParser(
        prog="muninn inventory",
        description="Context surface inventory (observe-only). Reports which "
                    "agent-context surfaces Muninn scans vs. only detects.")
    p.add_argument("--vault", "--root", dest="vault",
                   default=str(pathlib.Path("~/memory").expanduser()),
                   help="target root to inventory (default: ~/memory)")
    p.add_argument("--json", action="store_true",
                   help="emit the coverage block as JSON")
    args = p.parse_args(argv)
    out = stdout or sys.stdout

    root = pathlib.Path(args.vault).expanduser()
    if not root.is_dir():
        print(f"muninn inventory: root not found: {root}", file=sys.stderr)
        return 2
    try:
        entries = read_vault(root)
    except Exception:
        entries = []
    scanned_paths = {e.file_path for e in entries if getattr(e, "file_path", None)}
    coverage = build_coverage(root, scanned_paths=scanned_paths)
    if args.json:
        out.write(json.dumps(coverage, ensure_ascii=False, indent=2,
                             sort_keys=True) + "\n")
    else:
        out.write(render_text(coverage, str(root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
