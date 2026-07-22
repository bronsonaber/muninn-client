"""shadow/receipt.py: renders the Context Receipt, a reviewer-readable
Markdown comment for an AI-authored pull request.

INPUT CONTRACT: this module renders, it never scans, redacts, or reshapes.
The caller (a GitHub Action entrypoint, or a human at a terminal) must hand
render_receipt() a report that has already been through the SAME pipeline
shadow/doctor.py's own CLI uses, in the SAME order:

    report = doctor.run_doctor(vault_dir, ...)
    report = redact.redact_report(report, entries=captured)   # DEFAULT-ON
    report["first_look"] = doctor.build_first_look(report)

render_receipt() refuses (raises ValueError) a report that skipped either
step: report["redacted"] must be True (this comment is posted PUBLICLY to a
PR, so an unredacted report must never reach it) and report["first_look"]
must be present (the receipt is a first-contact triage view, never the raw
findings list).

NO-APPROVAL LAW: this module inherits shadow/doctor.py's rule verbatim. The
receipt leads with doctor.NOT_A_CODE_REVIEW_DISCLAIMER and its own verdict
line never uses "approved", "all clear", "safe to merge", "looks safe", or
"passed" -- see tests/test_shadow_receipt.py::test_no_blessing_language for
the enforced word list, checked case-insensitively over the WHOLE render.

DECISION CARD, NOT A REPORT CARD (GTM audit, 2026-07): the receipt leads
with the one thing a reviewer needs to decide, not with coverage stats or a
score. Immediately under the disclaimer sits "Decision needed before merge"
(one plain-language sentence naming the highest-priority finding), "Why it
matters" (that finding's own consequence, straight from
doctor.Finding.consequence -- the field is already documented "why it
matters"), and "Evidence" (that finding's redacted-pointer evidence,
verbatim). Coverage detail and the refusal-to-conclude breakdown still
render, just BELOW the decision, never ahead of it. Every render ends on the
same verbatim closing line: "Muninn does not approve code. It shows the
context risk your reviewer should decide."

"WHAT MUNINN REFUSED TO CONCLUDE": mirrors shadow/repair_plan.py's own
safety taxonomy (NEVER_TOUCH / PROPOSE_ONLY) WITHOUT calling repair_plan's
full transaction builder, which re-hashes the vault and is meant for the
`muninn repair plan` apply path, not a read-only PR comment:
    NEVER_TOUCH   reused directly: repair_plan._looks_like_secret_or_inject
                  (a pure, zero-I/O check on finding_id). These are the
                  secret/injection-shaped findings that always lead
                  first-look (FIRST_LOOK_ALWAYS_LEAD_CHECKS) yet whose own
                  confidence is deliberately "medium" -- the matcher proves
                  the SHAPE, never whether it is live vs. quoted, so Muninn
                  will never auto-fix these and does not conclude they are
                  live secrets.
    PROPOSE_ONLY  first_look's own "review_later" list: every ambiguous
                  stale/duplicate/history/policy finding build_first_look
                  already demoted and labeled "possible", never asserted as
                  fact. That demotion IS the refusal-to-conclude.
"""
from __future__ import annotations

from typing import Any, Dict, List

from shadow._bundle_primitives import (  # noqa: E402
    NOT_A_CODE_REVIEW_DISCLAIMER, STATUS_NO_RISKS_FOUND,
    _looks_like_secret_or_inject,
)

# HTML comment marker so a caller (the GitHub Action) can find Muninn's own
# prior comment on a PR and UPSERT (edit) it rather than spamming a new one
# every run. Invisible in GitHub's rendered Markdown. Versioned so a future
# incompatible receipt shape can still recognize (and replace) an old one.
HIDDEN_MARKER = "<!-- muninn:context-receipt:v1 -->"

# The mandated closing line (GTM audit decision-card rework): identical text
# on every render, local-mode or server-mode, findings or none. Never a
# blessing -- states plainly what Muninn is and is not.
CLOSING_LINE = ("Muninn does not approve code. It shows the context risk "
                "your reviewer should decide.")

# Terminal control bytes (ANSI / C0 / C1) stripped from every rendered
# string, same guard shadow/doctor.py applies to its own terminal output
# (_term_safe) -- a crafted memory id/title must not smuggle escape
# sequences or zero-width tricks into a PUBLIC PR comment.
_CTRL = ({c for c in range(0x00, 0x20)} | {0x7F} | set(range(0x80, 0xA0)))
_CTRL.discard(0x0A)  # keep LF (line structure)
_CTRL.discard(0x09)  # keep TAB


def _safe(s: Any) -> str:
    return "".join(ch for ch in str(s) if ord(ch) not in _CTRL)


def _sentence(text: str) -> str:
    """Capitalize a fragment's first letter and make sure it ends with
    terminal punctuation, so a Finding field written as a lowercase clause
    (doctor.py's own convention -- see the Finding dataclass docstring:
    diagnosis/consequence/recommended_fix are all written as mid-sentence
    clauses) reads as a complete sentence in the receipt. Empty input passes
    through empty; this never invents content."""
    t = text.strip()
    if not t:
        return t
    t = t[0].upper() + t[1:]
    if not t.endswith((".", "!", "?")):
        t += "."
    return t


def _coverage_section(report: Dict[str, Any]) -> List[str]:
    """Coverage honesty: what was actually scanned, what was detected but
    not scanned, what could not be introspected at all, and how many files
    the vault's own .gitignore/.muninnignore excluded from scope. Every
    pointer here already passed through redact.redact_report (path#hash /
    mem#hash), so nothing here is a raw filesystem path."""
    L = ["### What was scanned"]
    cov = report.get("context_coverage") or {}
    status = cov.get("coverage_status", "UNKNOWN_CONTEXT_COVERAGE")
    L.append(f"- coverage status: `{_safe(status)}`")

    def _emit(heading: str, rows: List[Dict[str, Any]], cap: int = 10) -> None:
        L.append(f"- {heading}: {len(rows)}")
        for row in rows[:cap]:
            L.append(f"  - {_safe(row.get('label', 'surface'))}: "
                     f"`{_safe(row.get('pointer', ''))}`")
        if len(rows) > cap:
            L.append(f"  - ...and {len(rows) - cap} more")

    _emit("scanned this run", cov.get("scanned", []))
    unscanned = cov.get("detected_but_unscanned", [])
    if unscanned:
        _emit("detected but NOT scanned (influence the agent, unaudited)",
              unscanned)
    unknown = cov.get("unknown", [])
    if unknown:
        _emit("unknown / not introspectable", unknown)

    scope = report.get("scan_scope") or {}
    excluded = scope.get("excluded_count", 0)
    if excluded:
        L.append(f"- {excluded} file(s) excluded from scope by "
                 f".gitignore/.muninnignore ({_safe(scope.get('disclosure_line', ''))})")
    return L


def _finding_lines(f: Dict[str, Any]) -> List[str]:
    sev = _safe(f.get("severity", ""))
    conf = _safe(f.get("confidence", ""))
    title = _safe(f.get("title", ""))
    action = _safe(f.get("recommended_fix") or "manual review required")
    evidence = f.get("evidence") or []
    lines = [f"- **[{sev} / {conf} confidence]** {title}"]
    if evidence:
        lines.append(f"  - where: `{_safe(evidence[0])}`")
    lines.append(f"  - reviewer action: {action}")
    return lines


def _other_findings_section(rest: List[Dict[str, Any]]) -> List[str]:
    """The remaining high-confidence findings once the single decision above
    has claimed the lead slot. Capped so a pathological vault cannot balloon
    the comment; the cap is stated honestly rather than silently dropping
    rows."""
    L = ["### Other high-confidence findings needing review"]
    cap = 14
    for f in rest[:cap]:
        L.extend(_finding_lines(f))
    if len(rest) > cap:
        L.append(f"- ...and {len(rest) - cap} more high-confidence finding(s). "
                 f"Run `muninn doctor --first-look` locally over this same "
                 f"commit for the full list.")
    return L


def _refused_section(first_look: Dict[str, Any]) -> List[str]:
    """'What Muninn refused to conclude': the NEVER_TOUCH / PROPOSE_ONLY
    view, see the module docstring for the exact mapping."""
    lead = first_look.get("lead", [])
    review_later = first_look.get("review_later", [])
    never_touch = [f for f in lead if _looks_like_secret_or_inject(f)]

    L = ["### What Muninn refused to conclude"]
    if not never_touch and not review_later:
        L.append("Nothing ambiguous this run: every finding above is "
                 "high-confidence and no secret/injection shape was matched.")
        return L
    if never_touch:
        L.append(f"- **NEVER_TOUCH** ({len(never_touch)}): secret/injection-"
                 f"shaped text matched above by SHAPE only. Muninn cannot "
                 f"tell a live credential or a real injection from a quoted "
                 f"example, so it draws no conclusion either way and will "
                 f"never propose an automated fix. A human must verify the "
                 f"match in context before acting.")
    if review_later:
        cap = 10
        L.append(f"- **PROPOSE_ONLY** ({len(review_later)}): ambiguous "
                 f"stale/duplicate/history/policy items, demoted and "
                 f"labeled possible, never asserted as fact:")
        for f in review_later[:cap]:
            title = _safe(f.get("title", ""))
            if title.lower().startswith("possible:"):
                title = title[len("possible:"):].strip()
            L.append(f"  - possible: {title}")
        if len(review_later) > cap:
            L.append(f"  - ...and {len(review_later) - cap} more")
    return L


def _decision_section_local(first_look: Dict[str, Any]) -> List[str]:
    """The decision card's lead block for local (first-look) mode:
    'Decision needed before merge' / 'Why it matters' / 'Evidence', built
    from the single highest-priority lead finding (first_look["lead"][0] --
    build_first_look already orders/labels this list, this function does no
    re-prioritizing of its own). Any remaining lead findings are named in
    the decision line's count and rendered in full by
    _other_findings_section, never dropped."""
    lead = first_look.get("lead", [])
    L = ["### Decision needed before merge"]
    if not lead:
        L.append(f"No context risk found in the scanned surfaces "
                 f"({STATUS_NO_RISKS_FOUND}). Nothing here requires a merge "
                 f"decision; this is not an approval, only an absence of "
                 f"findings in what was scanned.")
        return L

    primary, rest = lead[0], lead[1:]
    decision = _sentence(_safe(primary.get("title", "")) or
                         "an unreviewed context risk")
    if rest:
        decision += (f" ({len(lead)} high-confidence findings this run; "
                     f"see below for the rest.)")
    L.append(decision)
    L.append("")
    L.append("### Why it matters")
    consequence = _safe(primary.get("consequence", "")).strip()
    L.append(_sentence(consequence or
             "the diff can still pass CI while this context risk goes "
             "unresolved"))
    L.append("")
    L.append("### Evidence")
    evidence = primary.get("evidence") or []
    if evidence:
        for e in evidence:
            L.append(f"- `{_safe(e)}`")
    else:
        L.append("- (no evidence pointer recorded for this finding)")
    fix = _safe(primary.get("recommended_fix", "")).strip()
    if fix:
        L.append("")
        L.append(f"Recommended fix: {_sentence(fix)}")
    if rest:
        L.append("")
        L.extend(_other_findings_section(rest))
    return L


# Human phrasing for each content-free high-risk finding TYPE the server's
# scores-v1 may name per pointer (muninn_server.scoring's finding-type enum):
# (noun for the decision line, why-it-matters clause). policy_collision is
# handled separately below (it needs its paired-pointer evidence), so it is
# not in this map. A type that is absent (an older server that predates the
# `type` field), unknown (a newer type this client predates), or a MIX of
# distinct recognized types all fall back to _GENERIC_HIGH_* -- the honest
# secret-or-injection wording, never a false-specific claim, never a crash.
_HIGH_TYPE_NOUN = {
    "secret_shaped": "secret-shaped content",
    "injection_shaped": "injection-shaped content",
    "contradiction": "a contradiction between context surfaces",
}
_HIGH_TYPE_WHY = {
    "secret_shaped": ("the diff passes CI but may carry a live secret the "
                      "server could not rule out as safe"),
    "injection_shaped": ("the diff passes CI but may carry an injection-"
                         "shaped instruction the server could not rule out "
                         "as safe"),
    "contradiction": ("the diff passes CI but two context surfaces disagree "
                      "in a way the server cannot resolve as safe"),
}
_GENERIC_HIGH_NOUN = "secret- or injection-shaped content"
_GENERIC_HIGH_WHY = ("the diff passes CI but may carry a live secret or an "
                     "injection-shaped instruction the server could not rule "
                     "out as safe")


def _decision_lead_policy_collision(
        high: List[Dict[str, Any]], flagged: List[Dict[str, Any]],
        policy_collisions: List[Dict[str, Any]]) -> List[str]:
    """The decision-card lead for a run whose dominant finding is a package-
    manager policy collision. Evidence prefers the paired pointers the
    server's policy_collisions list carries (context surface + lockfile +
    closed-vocabulary reason); if that list is absent but a high_risk pointer
    is TYPED policy_collision (e.g. an older/partial server that dropped the
    paired list), it still names the collision from the typed pointer alone
    rather than falling back to the misleading secret/injection phrasing --
    that mismatch is the exact live bug this receiver fixes."""
    collision_files = [f for f in high
                       if isinstance(f, dict) and f.get("type") == "policy_collision"]
    have_pairs = bool(policy_collisions)
    n = len(policy_collisions) if have_pairs else len(collision_files)
    plural = "" if n == 1 else "s"
    L = [_sentence(
        "your context tells the agent to use one package manager "
        "while the repo's lockfile implies another" +
        (f" ({n} such collision{plural} this run)" if n > 1 else "")),
        "",
        "### Why it matters",
        _sentence("the diff can pass CI and still install the wrong "
                  "dependencies"),
        "",
        "### Evidence"]
    cap = 15
    if have_pairs:
        for pc in policy_collisions[:cap]:
            L.append(f"- context surface `{_safe(pc.get('pointer', ''))}` "
                     f"conflicts with lockfile "
                     f"`{_safe(pc.get('other_pointer', ''))}` "
                     f"(reason: `{_safe(pc.get('reason', ''))}`)")
        collision_pointers = {pc.get("pointer") for pc in policy_collisions
                              if isinstance(pc, dict)}
    else:
        for f in collision_files[:cap]:
            L.append(f"- context surface `{_safe(f.get('pointer', ''))}` "
                     f"(lane hint: `{_safe(f.get('lane_hint', ''))}`); the "
                     f"paired lockfile pointer was not carried in this "
                     f"receipt")
        collision_pointers = {f.get("pointer") for f in collision_files
                              if isinstance(f, dict)}
    if n > cap:
        L.append(f"- ...and {n - cap} more")
    # A collision surface's own file entry also scores risk == high_risk
    # (muninn_server.scoring._risk_for), but that entry's high_risk status IS
    # the collision just named above, not a SEPARATE finding -- excluded here
    # so "additional ... for other reasons" never double-counts the same
    # pointer under a misleading label.
    other_high = [f for f in high
                  if not (isinstance(f, dict) and f.get("pointer") in collision_pointers)]
    other = len(other_high) + len(flagged)
    if other:
        L.append("")
        L.append(_sentence(
            f"{other} additional pointer{'s' if other != 1 else ''} "
            f"flagged or high-risk for other reasons, listed below"))
    return L


def _decision_lead_high_risk(high: List[Dict[str, Any]],
                             flagged: List[Dict[str, Any]],
                             high_types: set) -> List[str]:
    """The decision-card lead for a high_risk run that is NOT a policy
    collision. Names the finding by its content-free TYPE when the server
    supplied one (secret-shaped vs. injection-shaped, distinctly); falls back
    to the honest generic secret-or-injection wording when the type is
    absent (older server), unknown, or a mix of distinct types."""
    recognized = {t for t in high_types if t in _HIGH_TYPE_NOUN}
    if len(recognized) == 1:
        only = next(iter(recognized))
        noun = _HIGH_TYPE_NOUN[only]
        why = _HIGH_TYPE_WHY[only]
    else:
        noun = _GENERIC_HIGH_NOUN
        why = _GENERIC_HIGH_WHY

    n = len(high)
    singular = n == 1
    plural = "" if singular else "s"
    verb = "needs" if singular else "need"
    scores_verb = "scores" if singular else "score"
    L = [_sentence(f"{n} pointer{plural} in the submitted bundle "
                   f"{scores_verb} high_risk for {noun} and {verb} a human "
                   f"call before this merges"),
         "",
         "### Why it matters",
         _sentence(why),
         "",
         "### Evidence"]
    cap = 15
    for f in high[:cap]:
        L.append(f"- `{_safe(f.get('pointer', ''))}` "
                 f"(lane hint: `{_safe(f.get('lane_hint', ''))}`)")
    if n > cap:
        L.append(f"- ...and {n - cap} more")
    if flagged:
        m = len(flagged)
        L.append("")
        L.append(f"{m} additional flagged pointer{'s' if m != 1 else ''} for "
                 f"structural hygiene listed below.")
    return L


def _decision_lead_flagged(flagged: List[Dict[str, Any]]) -> List[str]:
    """The decision-card lead for a run with only structural-hygiene flags
    (no high_risk, no policy collision)."""
    n = len(flagged)
    singular = n == 1
    plural = "" if singular else "s"
    verb = "needs" if singular else "need"
    what = ("was flagged for structural hygiene" if singular
            else "were flagged for structural hygiene")
    L = [_sentence(f"{n} pointer{plural} in the submitted bundle {what} "
                   f"and {verb} a human call before this merges"),
         "",
         "### Why it matters",
         _sentence("the diff passes CI but the flagged pointer(s) may signal "
                   "structural drift the server cannot resolve as safe"),
         "",
         "### Evidence"]
    cap = 15
    for f in flagged[:cap]:
        L.append(f"- `{_safe(f.get('pointer', ''))}` "
                 f"(lane hint: `{_safe(f.get('lane_hint', ''))}`)")
    if n > cap:
        L.append(f"- ...and {n - cap} more")
    return L


def _decision_section_server(scores: Dict[str, Any]) -> List[str]:
    """The decision card's lead block for server-scored mode, same shape as
    _decision_section_local above but adapted to the server's scores-v1
    fields (risk_counts / files, not a first_look lead list). The card LEADS
    with the dominant finding TYPE, named from the content-free `type`
    category the server now carries per pointer.

    policy_collision LEADS when present: it is a provable, deterministic
    contradiction (a context surface's directive text vs. the repo's own
    lockfile), the marquee case this decision card exists to prove server
    mode catches -- see muninn_server.scoring._risk_for's own docstring for
    why it is scored HIGH alongside secret/injection rather than folded into
    the lower structural-hygiene tier. Its presence is detected from EITHER
    the paired policy_collisions list OR a high_risk pointer typed
    policy_collision, so a receipt names the collision even if the paired
    list is missing. When no policy collision is present, high_risk pointers
    take priority over flagged ones for naming the decision and are named by
    their own finding type (secret-shaped vs. injection-shaped, distinctly),
    falling back to the honest generic wording when the type is absent
    (older server), unknown, or mixed. Every pointer at the leading risk
    level is listed as evidence, never just one. A policy_collision finding
    is never hidden even when it does not lead: the dedicated 'Policy
    collisions' section below always renders it."""
    files = scores.get("files")
    files = files if isinstance(files, list) else []
    high = [f for f in files if isinstance(f, dict) and f.get("risk") == "high_risk"]
    flagged = [f for f in files if isinstance(f, dict) and f.get("risk") == "flagged"]
    policy_collisions = scores.get("policy_collisions")
    policy_collisions = policy_collisions if isinstance(policy_collisions, list) else []

    L = ["### Decision needed before merge"]
    if not high and not flagged and not policy_collisions:
        L.append(f"No context risk found in the scanned surfaces "
                 f"({STATUS_NO_RISKS_FOUND}). Nothing here requires a merge "
                 f"decision; this is not an approval, only an absence of "
                 f"findings in what was submitted.")
        return L

    high_types = {f.get("type") for f in high
                  if isinstance(f, dict) and isinstance(f.get("type"), str)}
    has_policy_collision = bool(policy_collisions) or ("policy_collision" in high_types)

    if has_policy_collision:
        L.extend(_decision_lead_policy_collision(high, flagged, policy_collisions))
    elif high:
        L.extend(_decision_lead_high_risk(high, flagged, high_types))
    else:
        L.extend(_decision_lead_flagged(flagged))
    return L


def _server_scored_section(scores: Dict[str, Any]) -> List[str]:
    """What the server actually scored: counts only, same pointer-only
    discipline as _coverage_section above -- nothing here is raw filesystem
    content, only the fixed scores-v1 shape muninn_server/scoring.py
    returns."""
    L = ["### What was scored"]
    L.append(f"- files scored: {scores.get('file_count', 0)}")
    rc = scores.get("risk_counts") or {}
    L.append(f"- risk breakdown: clear={rc.get('clear', 0)}, "
             f"flagged={rc.get('flagged', 0)}, high_risk={rc.get('high_risk', 0)}")
    lc = scores.get("lane_counts") or {}
    if lc:
        lane_str = ", ".join(f"{_safe(k)}={v}" for k, v in sorted(lc.items()))
        L.append(f"- admission lane hints: {lane_str}")
    dup = scores.get("duplicate_group_count", 0) or 0
    coll = scores.get("collision_group_count", 0) or 0
    if dup:
        L.append(f"- {dup} duplicate-id group(s) detected")
    if coll:
        L.append(f"- {coll} case-fold collision group(s) detected")
    policy_collisions = scores.get("policy_collisions")
    if isinstance(policy_collisions, list) and policy_collisions:
        L.append(f"- {len(policy_collisions)} policy collision(s) detected "
                 f"(context directive vs. lockfile)")
    rs = scores.get("resource_stats") or {}
    L.append(f"- resource footprint: {rs.get('total_size_bytes', 0)} bytes, "
             f"~{rs.get('total_est_tokens', 0)} est. tokens")
    return L


def _server_pointer_section(heading: str, files: List[Dict[str, Any]],
                            risk: str, cap: int = 15) -> List[str]:
    rows = [f for f in files if isinstance(f, dict) and f.get("risk") == risk]
    L = [f"### {heading}"]
    if not rows:
        L.append("None this run.")
        return L
    for f in rows[:cap]:
        L.append(f"- `{_safe(f.get('pointer', ''))}` "
                 f"(lane hint: `{_safe(f.get('lane_hint', ''))}`)")
    if len(rows) > cap:
        L.append(f"- ...and {len(rows) - cap} more")
    return L


def _policy_collision_section(policy_collisions: List[Dict[str, Any]],
                              cap: int = 15) -> List[str]:
    """Always renders every policy_collision finding, whether or not it led
    the decision card above (see _decision_section_server's own docstring
    for when it does not lead) -- a finding is never dropped just because
    it was not the one named first."""
    L = ["### Policy collisions (package manager mismatch)"]
    if not policy_collisions:
        L.append("None this run.")
        return L
    for pc in policy_collisions[:cap]:
        L.append(f"- context surface `{_safe(pc.get('pointer', ''))}` "
                 f"conflicts with lockfile "
                 f"`{_safe(pc.get('other_pointer', ''))}` "
                 f"(reason: `{_safe(pc.get('reason', ''))}`)")
    if len(policy_collisions) > cap:
        L.append(f"- ...and {len(policy_collisions) - cap} more")
    return L


def render_server_receipt(receipt: Dict[str, Any]) -> str:
    """Render the Context Receipt Markdown for a SERVER-scored run (Phase 5:
    shadow.pr_action's server mode). The caller must have already verified
    `receipt`'s ed25519 signature (shadow.server_client.verify_receipt)
    BEFORE ever calling this function -- this renderer does not verify
    anything itself, it only asserts the two structural things a public PR
    comment must never skip (an accepted verdict, and a `scores` object to
    render), the same refuse-to-render posture render_receipt() above takes
    for an unredacted/non-first-look report.

    In server mode the scoring itself already ran server-side
    (muninn_server.scoring.score_bundle, over the redacted bundle the
    server received) -- this function ONLY renders what the server
    returned. It never re-scores, and it reuses HIDDEN_MARKER and
    NOT_A_CODE_REVIEW_DISCLAIMER directly (not a second, drifting copy) so
    the same upsert_comment lookup finds and edits either a local-mode or a
    server-mode receipt on the same PR, and so the same no-blessing-
    language discipline applies to both. The decision card format (see
    module docstring) is shared with render_receipt() above via
    _decision_section_server, adapted to the server's scores-v1 shape."""
    if receipt.get("verdict") != "accepted":
        raise ValueError(
            "render_server_receipt refuses to render: receipt verdict is "
            f"not 'accepted' ({receipt.get('verdict')!r}). Only an accepted, "
            "signed receipt is ever posted.")
    scores = receipt.get("scores")
    if not isinstance(scores, dict):
        raise ValueError(
            "render_server_receipt refuses to render: receipt has no "
            "'scores' object.")

    files = scores.get("files")
    files = files if isinstance(files, list) else []

    L: List[str] = [
        HIDDEN_MARKER, "", "## Muninn Context Receipt (server-scored)", "",
        _safe(NOT_A_CODE_REVIEW_DISCLAIMER), "",
    ]
    L.extend(_decision_section_server(scores))
    L.append("")
    L.extend(_server_scored_section(scores))
    L.append("")
    L.extend(_server_pointer_section(
        "High-risk pointers (need review)", files, "high_risk"))
    L.append("")
    L.extend(_server_pointer_section(
        "Flagged pointers (structural hygiene, not safety)", files, "flagged"))
    L.append("")
    policy_collisions = scores.get("policy_collisions")
    policy_collisions = policy_collisions if isinstance(policy_collisions, list) else []
    L.extend(_policy_collision_section(policy_collisions))
    L.append("")
    L.append("### What Muninn refused to conclude")
    L.append("- **risk = high_risk**: secret/injection-shaped signal matched "
             "by SHAPE only, on the redacted bundle the server received. "
             "The server cannot tell a live credential or a real injection "
             "from a quoted example, so it draws no conclusion either way "
             "and never proposes an automated fix. A human must verify the "
             "match in context before acting.")
    L.append("- **policy_collision**: a structural fact (a directive "
             "pattern matched in a context surface against which lockfile "
             "is actually present), not a semantic read of intent. Muninn "
             "does not conclude which package manager the project should "
             "standardize on, only that the two disagree today; a human "
             "must decide which side is correct.")
    L.append("- **lane hints** reflect Muninn's real admission engine run "
             "over only the signals a redacted bundle can honestly carry "
             "(no provenance data crosses the wire); a `reject` hint here "
             "is that engine's own fail-safe default given today's bundle "
             "schema, not an assertion that the underlying memory is bad.")
    L.append("")
    L.append(f"_Server-scored and signed: request `{_safe(receipt.get('request_id', ''))}`, "
             f"key `{_safe(receipt.get('key_id', ''))}`, at `{_safe(receipt.get('ts', ''))}`. "
             f"This signature was verified by the client before this comment "
             f"was posted. Findings are shown as stable pointers "
             f"(`path#hash`), never raw filesystem paths, filenames, memory "
             f"ids, or secret literals. Run `muninn doctor --first-look "
             f"--unredacted` on your own machine for full local detail "
             f"(never share that report)._")
    L.append("")
    L.append(CLOSING_LINE)
    return "\n".join(L) + "\n"


def render_receipt(report: Dict[str, Any]) -> str:
    """Render the Context Receipt Markdown comment for a completed,
    first-look-shaped, REDACTED doctor report. Raises ValueError if the
    report was not put through both steps -- this function never redacts or
    reshapes on the caller's behalf, so a caller cannot accidentally post an
    unredacted or non-first-look report by skipping a step upstream."""
    if not report.get("redacted"):
        raise ValueError(
            "render_receipt refuses to render: report is not redacted. "
            "This receipt is posted PUBLICLY to a pull request; call "
            "shadow.redact.redact_report(report, entries=...) first.")
    first_look = report.get("first_look")
    if first_look is None:
        raise ValueError(
            "render_receipt refuses to render: report has no first_look "
            "section. Call shadow.doctor.build_first_look(report) and set "
            "report['first_look'] before rendering.")

    L: List[str] = [HIDDEN_MARKER, "", "## Muninn Context Receipt", "",
                    _safe(NOT_A_CODE_REVIEW_DISCLAIMER), ""]
    L.extend(_decision_section_local(first_look))
    L.append("")
    L.extend(_coverage_section(report))
    L.append("")
    L.extend(_refused_section(first_look))
    L.append("")
    L.append("_Redacted for public posting: findings are shown as stable "
             "pointers (`path#hash` / `mem#hash`), never raw filesystem "
             "paths, filenames, memory ids, or secret literals. Run "
             "`muninn doctor --first-look --unredacted` on your own "
             "machine for full local detail (never share that report)._")
    L.append("")
    L.append(CLOSING_LINE)
    return "\n".join(L) + "\n"
