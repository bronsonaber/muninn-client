"""shadow/scan_scope.py: honest scan-scope filtering for the vault collection
layer (shadow/dryrun.read_vault, shadow/truthrot.read_memory_units).

THE PROBLEM this closes (a real dogfood run, first-contact credibility):
scanning a messy human vault counted git-ignored `.claude/worktrees/` agent
scratch as canonical memory. A worktree copy of a real file duplicated the
real file's frontmatter `name:`, manufacturing a PHANTOM duplicate-id
finding, and stale/rot counts were inflated the same way, by counting
throwaway scratch the vault owner already told git to ignore.

THE FIX: by default, honor the vault's own ignore rules.
  * If the vault is inside a git repo, `git check-ignore` decides (the exact
    rules git itself would apply: .gitignore at any level, .git/info/exclude,
    core.excludesFile). This is delegated to git rather than reimplemented,
    so it is exactly as correct as git's own answer, not an approximation.
  * A `.muninnignore` file at the vault root (gitignore-style globs) is
    applied ON TOP of .gitignore for vault-owner excludes that are not (or
    should not be) committed to .gitignore. Supported syntax: '#' comments,
    blank lines, a trailing '/' for a directory-only pattern, a leading '/'
    to anchor to the vault root, '*' / '?' wildcards (never cross a '/'),
    and '**' for "any number of directories". NOT supported: '!' negation
    and POSIX character classes ('[abc]'); a pattern using either is still
    accepted but is compared literally, so it will not do what a real
    gitignore file would do with it. This is a deliberate scope limit,
    stated here rather than silently under- or over-matching.
  * If the vault is NOT inside a git repo, there is nothing for git to
    ignore, so the fallback is to scan everything (a .muninnignore still
    applies if present).
  * `--include-ignored` (threaded down from the doctor CLI) restores the old
    scan-everything behavior: no filtering happens at all, and the report
    says so explicitly.

Every exclusion is counted and named (which rule excluded it); nothing is
ever silently dropped. See ScanScope.disclosure_line / as_report_dict.

Design rules (match the rest of Muninn): pure stdlib, deterministic, utf-8,
no em dashes. Read-only: this module never writes anything; `git check-ignore`
is a read-only git plumbing command.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

MUNINNIGNORE_NAME = ".muninnignore"

# git subprocess calls are bounded so a hostile or oversized vault cannot hang
# a doctor run indefinitely.
_GIT_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class ExcludedPath:
    """One candidate path that scan-scope filtering excluded."""
    path: str   # absolute path, as given by the caller's candidate list
    rule: str   # the excluding rule, e.g. ".gitignore:3:scratch/" or
                # ".muninnignore:1:.claude/worktrees/"


@dataclass
class ScanScope:
    """Result of applying scan-scope filtering to one candidate file list.

    `included` preserves the candidates' original relative order (callers
    that need a stable, sorted walk should sort candidates before passing
    them in; this never re-sorts)."""
    included: List[pathlib.Path]
    excluded: List[ExcludedPath] = field(default_factory=list)
    is_git_repo: bool = False
    muninnignore_used: bool = False
    include_ignored: bool = False

    @property
    def included_count(self) -> int:
        return len(self.included)

    @property
    def excluded_count(self) -> int:
        return len(self.excluded)

    def excluded_by_rule_summary(self) -> Dict[str, int]:
        """Excluded-path counts grouped by rule SOURCE (".gitignore" vs
        ".muninnignore"), for a short, honest scan-scope report line."""
        counts: Dict[str, int] = {}
        for e in self.excluded:
            source = e.rule.split(":", 1)[0] if e.rule else "unknown"
            counts[source] = counts.get(source, 0) + 1
        return counts

    def disclosure_line(self) -> str:
        """One honest, human-readable line: what was scanned, what was not,
        and why. Never silent about an exclusion."""
        if self.include_ignored:
            return (f"scan scope: {self.included_count} file(s) included; "
                    "--include-ignored set, so NO gitignore/.muninnignore "
                    "filtering was applied (old scan-everything behavior).")
        if not self.is_git_repo:
            if self.muninnignore_used:
                by_rule = self.excluded_by_rule_summary()
                parts = ", ".join(f"{n} by {src}" for src, n in
                                  sorted(by_rule.items()))
                exclusion = (f"{self.excluded_count} excluded ({parts})"
                             if self.excluded_count else "0 excluded")
                return (f"scan scope: {self.included_count} file(s) included, "
                        f"{exclusion}; the vault is not inside a git repo (no "
                        ".gitignore to honor), but .muninnignore was applied.")
            return (f"scan scope: {self.included_count} file(s) included, "
                    "0 excluded; the vault is not inside a git repo, so there "
                    "is no .gitignore to honor (scanned everything).")
        if self.excluded_count == 0:
            return (f"scan scope: {self.included_count} file(s) included, "
                    "0 excluded (.gitignore/.muninnignore honored, nothing "
                    "matched).")
        by_rule = self.excluded_by_rule_summary()
        parts = ", ".join(f"{n} by {src}" for src, n in sorted(by_rule.items()))
        return (f"scan scope: {self.included_count} file(s) included, "
                f"{self.excluded_count} excluded ({parts}).")

    def as_report_dict(self, vault_root: pathlib.Path,
                       sample_cap: int = 20) -> Dict[str, Any]:
        """JSON-safe report section: counts, the excluding rule breakdown, and
        a capped sample of excluded paths as VAULT-RELATIVE pointers (never
        raw absolute paths, matching every other pointer this tool reports)."""
        try:
            root_resolved = pathlib.Path(vault_root).resolve()
        except OSError:
            root_resolved = pathlib.Path(vault_root)

        def _rel(p: str) -> str:
            try:
                return str(pathlib.Path(p).resolve().relative_to(root_resolved))
            except (OSError, ValueError):
                return pathlib.Path(p).name

        return {
            "is_git_repo": self.is_git_repo,
            "include_ignored": self.include_ignored,
            "muninnignore_present": self.muninnignore_used,
            "included_count": self.included_count,
            "excluded_count": self.excluded_count,
            "excluded_by_rule": self.excluded_by_rule_summary(),
            "excluded_sample": [
                {"pointer": _rel(e.path), "rule": e.rule}
                for e in self.excluded[:sample_cap]
            ],
            "excluded_sample_capped": self.excluded_count > sample_cap,
            "disclosure_line": self.disclosure_line(),
        }


# ── git .gitignore delegation ────────────────────────────────────────────────

def is_git_repo(root: pathlib.Path) -> bool:
    """True if `root` sits inside a git working tree. Never raises."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=_GIT_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and out.stdout.strip() == "true"


def _git_ignored(root: pathlib.Path,
                 candidates: Sequence[pathlib.Path]) -> Dict[str, str]:
    """{absolute_path_str: rule} for every candidate git would ignore, via one
    batched `git check-ignore -v --stdin` call (never one process per file).
    Empty dict if nothing is ignored, candidates is empty, or git itself is
    unavailable/fails outright (never raises; a git failure degrades to "no
    exclusions found" rather than aborting the scan)."""
    if not candidates:
        return {}
    stdin_text = "".join(f"{p}\n" for p in candidates)
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-v", "--stdin"],
            input=stdin_text, capture_output=True, text=True,
            timeout=_GIT_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return {}
    # exit 0 = at least one candidate matched; 1 = none matched. Both are
    # ordinary outcomes. Anything else means git itself errored; treat that
    # as "no ignore data available" rather than silently over-excluding.
    if out.returncode not in (0, 1):
        return {}
    ignored: Dict[str, str] = {}
    for line in out.stdout.splitlines():
        if "\t" not in line:
            continue
        source_line_pattern, pathname = line.split("\t", 1)
        ignored[pathname] = source_line_pattern
    return ignored


# ── .muninnignore (gitignore-style globs, vault-root-only, no negation) ─────

@dataclass(frozen=True)
class _MuninnIgnoreRule:
    lineno: int
    raw: str
    regex: "re.Pattern"


def _translate_glob_body(body: str) -> str:
    """Translate the non-anchor part of one gitignore-style glob segment
    string into a regex body (no ^/$ anchors, caller adds those). '*' and '?'
    never cross a '/'; '**' (as its own path segment or as a `**/` prefix)
    matches "any number of path segments"."""
    i, n = 0, len(body)
    out: List[str] = []
    while i < n:
        c = body[i]
        if c == "*":
            if i + 1 < n and body[i + 1] == "*":
                if i + 2 < n and body[i + 2] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        out.append(re.escape(c))
        i += 1
    return "".join(out)


def _compile_muninnignore_pattern(pattern: str) -> "re.Pattern":
    dir_only = pattern.endswith("/")
    body = pattern[:-1] if dir_only else pattern
    leading_slash = body.startswith("/")
    if leading_slash:
        body = body[1:]
    anchored = leading_slash or ("/" in body)
    translated = _translate_glob_body(body)
    suffix = r"(?:/.*)?" if dir_only else ""
    if anchored:
        expr = f"^{translated}{suffix}$"
    else:
        expr = f"(?:^|.*/){translated}{suffix}$"
    return re.compile(expr)


def load_muninnignore(vault_root: pathlib.Path) -> List[_MuninnIgnoreRule]:
    """Parse `<vault_root>/.muninnignore` if present. Never raises; an
    unreadable file behaves as if absent."""
    path = pathlib.Path(vault_root) / MUNINNIGNORE_NAME
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rules: List[_MuninnIgnoreRule] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            regex = _compile_muninnignore_pattern(line)
        except re.error:
            continue
        rules.append(_MuninnIgnoreRule(lineno=lineno, raw=line, regex=regex))
    return rules


def _muninnignore_match(rel_posix: str,
                        rules: Sequence[_MuninnIgnoreRule]) -> Optional[str]:
    """Last-match-wins (gitignore semantics: later lines override earlier
    ones), returned as a `.muninnignore:<line>:<pattern>` rule string, or None
    if nothing in `rules` matches."""
    matched: Optional[str] = None
    for r in rules:
        if r.regex.search(rel_posix):
            matched = f"{MUNINNIGNORE_NAME}:{r.lineno}:{r.raw}"
    return matched


# ── Entry point ──────────────────────────────────────────────────────────────

def compute_scan_scope(vault_root: pathlib.Path,
                       candidates: Sequence[pathlib.Path],
                       include_ignored: bool = False) -> ScanScope:
    """Apply scan-scope filtering to one already-collected candidate file
    list (a caller's own rglob/walk result). Order is preserved.

    include_ignored=True is the escape hatch: every candidate is included,
    unfiltered, and the returned ScanScope says so (is_git_repo is still
    probed and reported, purely informational, since no filtering ran)."""
    vault_root = pathlib.Path(vault_root)
    candidates = list(candidates)

    if include_ignored:
        return ScanScope(included=candidates, excluded=[],
                         is_git_repo=is_git_repo(vault_root),
                         muninnignore_used=False, include_ignored=True)

    repo = is_git_repo(vault_root)
    gitignored = _git_ignored(vault_root, candidates) if repo else {}
    rules = load_muninnignore(vault_root)

    try:
        root_resolved = vault_root.resolve()
    except OSError:
        root_resolved = vault_root

    included: List[pathlib.Path] = []
    excluded: List[ExcludedPath] = []
    for p in candidates:
        key = str(p)
        rule = gitignored.get(key)
        if rule is None and rules:
            try:
                rel = str(p.resolve().relative_to(root_resolved)).replace("\\", "/")
            except (OSError, ValueError):
                rel = p.name
            rule = _muninnignore_match(rel, rules)
        if rule is not None:
            excluded.append(ExcludedPath(path=key, rule=rule))
        else:
            included.append(p)

    return ScanScope(included=included, excluded=excluded, is_git_repo=repo,
                     muninnignore_used=bool(rules), include_ignored=False)
