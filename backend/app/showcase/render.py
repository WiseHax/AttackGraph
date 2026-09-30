"""Human-readable showcase reports (Markdown and standalone HTML).

The narrative is built once, as a small document model derived only from the
ShowcaseReport, and then rendered to GitHub-flavoured Markdown or to a
self-contained HTML page (inline CSS and SVG; no JavaScript, fonts or other
external resources). All text taken from the report is escaped for the
target format (SEC-8). The wording is deliberately analytical: paths are
"plausible under the model", scores are comparative, nothing is claimed to be
exploitable in reality.
"""

import uuid
from dataclasses import dataclass
from html import escape as html_escape

from app.showcase.report import PathReport, ShowcaseReport
from app.showcase.svg import render_svg

# ---------------------------------------------------------------------------
# Document model
# ---------------------------------------------------------------------------

# An inline run is (style, text) with style in {"text", "b", "code"}.
Inline = list[tuple[str, str]]


@dataclass(frozen=True)
class Para:
    runs: Inline


@dataclass(frozen=True)
class Note:
    runs: Inline


@dataclass(frozen=True)
class Bullets:
    items: list[Inline]


@dataclass(frozen=True)
class Table:
    headers: list[str]
    rows: list[list[Inline]]


@dataclass(frozen=True)
class Pre:
    text: str


@dataclass(frozen=True)
class Graph:
    src: str
    alt: str


@dataclass(frozen=True)
class Section:
    title: str
    blocks: list


def t(text: str) -> Inline:
    return [("text", text)]


def b(text: str) -> tuple[str, str]:
    return ("b", text)


def c(text: str) -> tuple[str, str]:
    return ("code", text)


def s(text: str) -> tuple[str, str]:
    return ("text", text)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _risk(value: float) -> str:
    return f"{value:.4f}"


def _env(value: float) -> str:
    # env-risk-v1 saturates towards 1 with many paths; 8 decimals keep the
    # before/after difference visible without rounding it to 1.
    return f"{value:.8f}"


def _short(identifier: uuid.UUID | str) -> str:
    return str(identifier)[:8]


class _Names:
    def __init__(self, report: ShowcaseReport) -> None:
        self.entities = {e.id: e for e in report.environment.entities}
        self.relationships = {r.id: r for r in report.environment.relationships}
        self.evidence = {e.id: e for e in report.environment.evidence}
        self.findings = {f.id: f for f in report.environment.findings}

    def entity(self, entity_id: uuid.UUID) -> str:
        return self.entities[entity_id].name

    def relationship(self, relationship_id: uuid.UUID) -> str:
        r = self.relationships[relationship_id]
        return f"{self.entity(r.source_entity_id)} —{r.relationship_type}→ {self.entity(r.target_entity_id)}"

    def route(self, path: PathReport, all_paths: list[PathReport] | None = None) -> str:
        text = " → ".join(self.entity(n) for n in path.node_ids)
        # Paths through parallel relationships share their entities; name the
        # relationship that distinguishes them (ARCH-15).
        twins = [p for p in (all_paths or []) if p.node_ids == path.node_ids and p.path_id != path.path_id]
        if twins:
            hops = sorted({
                i for twin in twins for i, (a, b) in enumerate(zip(path.relationship_ids, twin.relationship_ids))
                if a != b
            })
            via = "; ".join(
                f"{self.relationships[path.relationship_ids[i]].relationship_type} "
                f"{self.entity(path.node_ids[i])} → {self.entity(path.node_ids[i + 1])}"
                for i in hops
            )
            text += f" (via {via})"
        return text

    def evidence_label(self, evidence_id: uuid.UUID) -> str:
        e = self.evidence[evidence_id]
        return e.record or _short(e.id)


def _chain(report: ShowcaseReport, names: _Names, path: PathReport) -> str:
    source, target = report.analysis.source_entity_id, report.analysis.target_entity_id

    def node_line(node_id: uuid.UUID) -> str:
        e = names.entities[node_id]
        tags = [e.entity_type]
        if node_id == source:
            tags.append("entry point")
        if node_id == target:
            tags.append("critical asset")
        if e.finding_ids:
            tags.append(f"{len(e.finding_ids)} finding{'s' if len(e.finding_ids) > 1 else ''}")
        separator = " · "
        return f"{e.name}  [{separator.join(tags)}]"

    lines = [node_line(path.node_ids[0])]
    for step in path.steps:
        evidence = ", ".join(names.evidence_label(e) for e in step.evidence_ids) or "no evidence (inferred)"
        lines.append(
            f"  │ {step.relationship_type} · {step.truth_tier.lower()} · "
            f"confidence {step.resolved_confidence} · {evidence}"
        )
        lines.append("  ▼")
        lines.append(node_line(step.to_entity_id))
    return "\n".join(lines)


def _significance(report: ShowcaseReport, names: _Names, path: PathReport) -> list[Inline]:
    risk = path.risk
    items: list[Inline] = [[
        s("Risk "), b(_risk(risk.numeric_risk)), s(f" ({risk.category}) over {path.hop_count} relationships."),
    ]]
    items.append(t(
        f"Target criticality {risk.target_criticality.value:.2f}, entry exposure "
        f"{risk.entry_exposure.value:.2f}, path enablement {risk.edge_enablement.value:.4f} "
        f"(geometric mean), confidence {risk.confidence.value:.4f} (weakest link)."
    ))
    if risk.finding_ids:
        titles = "; ".join(
            f"{names.findings[f].title} ({names.findings[f].severity}) on "
            f"{names.entity(names.findings[f].entity_id)}"
            for f in sorted(risk.finding_ids, key=lambda f: (names.findings[f].title, str(f)))
        )
        items.append(t(
            f"Findings on the path (the most severe sets the amplifier to {risk.finding_amplifier.value:.2f}): "
            f"{titles}."
        ))
    inferred = [st for st in path.steps if st.truth_tier == "INFERRED"]
    if inferred:
        items.append(t(
            "Contains an inferred relationship (no direct observation), which resolves to UNKNOWN "
            "confidence and lowers the path's confidence factor."
        ))
    decayed = sorted({
        names.evidence_label(ev)
        for st in path.steps for ev in st.evidence_ids
        if names.evidence[ev].confidence_at_evaluation != names.evidence[ev].recorded_confidence
    })
    if decayed:
        items.append(t(f"Relies on stale evidence downgraded by decay-policy-v1: {', '.join(decayed)}."))
    return items


# ---------------------------------------------------------------------------
# Narrative
# ---------------------------------------------------------------------------


def build_document(report: ShowcaseReport, graph_src: str = "graph.svg") -> tuple[str, list[Section]]:
    names = _Names(report)
    env = report.environment
    baseline = report.baseline
    remediation = report.remediation
    ranking = remediation.ranking
    featured = names.relationships[remediation.featured_relationship_id]
    featured_result = ranking.candidates[0]
    source = names.entity(report.analysis.source_entity_id)
    target = names.entity(report.analysis.target_entity_id)
    paths_by_risk = sorted(baseline.paths, key=lambda p: (-p.risk.numeric_risk, p.path_id))
    paths_by_id = {p.path_id: p for p in baseline.paths}
    path_rank = {p.path_id: i + 1 for i, p in enumerate(paths_by_risk)}
    observed = sum(1 for r in env.relationships if r.truth_tier == "OBSERVED")
    inferred = len(env.relationships) - observed
    fingerprint = report.analysis.provenance.policy_fingerprint
    after_paths = [paths_by_id[pid] for pid in remediation.after.path_ids]
    after_top = max(after_paths, key=lambda p: (p.risk.numeric_risk, p.path_id)) if after_paths else None
    before_top = paths_by_risk[0]
    sections: list[Section] = []

    header = [
        Note([s("Synthetic demonstration. "), s(" ".join(report.disclaimer[1:]))]),
        Bullets([
            [b("Environment: "), s(env.organisation)],
            [b("Evaluation time: "), c(report.analysis.evaluation_time.strftime("%Y-%m-%dT%H:%M:%SZ"))],
            [b("Policy: "), c(report.analysis.policy.version), s(" · fingerprint "), c(fingerprint[:16] + "…")],
            [b("Scope: "), s(report.scope.display_name + " "), c(f"{report.scope.scope_id} v{report.scope.definition_version}")],
            [b("Engine identity: "), c(report.engine_identity.status)],
        ]),
    ]
    sections.append(Section("", header))

    reduction_paths = baseline.path_count - remediation.after.path_count
    summary = [
        [s(f"The model contains {len(env.entities)} entities, {len(env.relationships)} relationships "
           f"({observed} observed, {inferred} inferred), {len(env.evidence)} evidence records and "
           f"{len(env.findings)} findings.")],
        [s("Bounded traversal from "), b(source), s(" to the critical asset "), b(target),
         s(" found "), b(f"{baseline.path_count} plausible paths"), s(" and terminated "),
         c(baseline.termination_reason),
         s(" (not saturated: every path within the policy's bounds was enumerated)." if not baseline.is_saturated
           else " (saturated: the path set is a lower bound).")],
        [s("Highest path risk "), b(_risk(before_top.risk.numeric_risk)), s(f" ({before_top.risk.category}); "
           "environment risk (env-risk-v1) "), b(_env(baseline.environment_risk)), s(".")],
        [s("Counterfactual analysis ranks removing "), b(names.relationship(featured.id)),
         s(" first: it removes "), b(f"{reduction_paths} of {baseline.path_count} paths"),
         s(", the highest remaining path risk is "),
         b(_risk(after_top.risk.numeric_risk) if after_top else "none"),
         s(f" ({after_top.risk.category})" if after_top else ""),
         s(" and environment risk becomes "), b(_env(remediation.after.environment_risk)), s(".")],
    ]
    if remediation.equivalent_relationship_ids:
        summary.append([s("Equivalent candidate(s) with the identical effect: "),
                        s("; ".join(names.relationship(r) for r in remediation.equivalent_relationship_ids)),
                        s(".")])
    summary.append([
        s("The ranking is "),
        b("persistence-authoritative" if report.persistence.ranking_persistence_authoritative
          else "not persistence-authoritative"),
        s("; engine identity is "), c(report.engine_identity.status),
        s(", so the persistence preconditions are "),
        b("met" if report.persistence.preconditions_met else "not met"),
        s(" (persistence itself is not implemented)."),
    ])
    sections.append(Section("Executive summary", [Bullets(summary)]))

    entity_rows = []
    for e in sorted(env.entities, key=lambda e: (e.entity_type, e.name)):
        entity_rows.append([
            t(e.name), t(e.entity_type), t(e.criticality or "—"), t(e.exposure or "—"),
            t(str(len(e.finding_ids)) if e.finding_ids else "—"),
        ])
    sections.append(Section("Environment overview", [
        Para(t(f"{env.organisation}: {len(env.entities)} entities connected by "
               f"{len(env.relationships)} directed, typed relationships. Traversal follows the stored "
               "direction of each relationship. The graph below is rendered from the analysed projection.")),
        Graph(graph_src, "AttackGraph showcase graph"),
        Table(["Entity", "Type", "Criticality", "Exposure", "Findings"], entity_rows),
    ]))

    critical = [e for e in env.entities if e.criticality == "CRITICAL"]
    surface = [e for e in env.entities if e.exposure == "EXTERNAL"]
    sections.append(Section("Critical assets", [Bullets([
        [b(e.name), s(f" ({e.entity_type}) — {e.description}")] for e in critical
    ])]))
    sections.append(Section("Attack surface", [
        Para(t("Entities with EXTERNAL exposure, and the relationships through which the analysis source "
               "reaches them:")),
        Bullets([
            [b(e.name), s(f" ({e.entity_type})")] + [
                s(" — reached via "),
                s("; ".join(names.relationship(r.id) for r in env.relationships
                            if r.target_entity_id == e.id and r.source_entity_id == report.analysis.source_entity_id)
                  or "the analysis source itself"),
            ]
            for e in surface
        ]),
    ]))

    path_rows = [
        [t(str(path_rank[p.path_id])), t(_risk(p.risk.numeric_risk)), t(p.risk.category),
         t(str(p.hop_count)), t(names.route(p, baseline.paths)), [c(_short(p.path_id))]]
        for p in paths_by_risk
    ]
    path_blocks: list = [
        Para(t(f"{baseline.path_count} plausible paths under the model, ordered by risk-v1 score. Each path "
               "has a deterministic identity (a hash of its ordered entity and relationship IDs), so parallel "
               "relationships produce distinct paths.")),
        Table(["#", "Risk", "Category", "Hops", "Route", "Path ID"], path_rows),
    ]
    for p in paths_by_risk[:3]:
        path_blocks.append(Para([b(f"Path {path_rank[p.path_id]}"), s(" · "), c(p.path_id)]))
        path_blocks.append(Pre(_chain(report, names, p)))
        path_blocks.append(Bullets(_significance(report, names, p)))
    sections.append(Section("Attack paths", path_blocks))

    top = before_top.risk
    factor_rows = [
        [t("Target criticality"), t(f"{top.target_criticality.value:.4f}"), t(top.target_criticality.description)],
        [t("Entry exposure"), t(f"{top.entry_exposure.value:.4f}"), t(top.entry_exposure.description)],
        [t("Path enablement"), t(f"{top.edge_enablement.value:.4f}"), t(top.edge_enablement.description)],
        [t("Confidence"), t(f"{top.confidence.value:.4f}"), t(top.confidence.description)],
        [t("Control dampening"), t(f"{top.control_dampening.value:.4f}"), t(top.control_dampening.description)],
        [t("Finding amplifier"), t(f"{top.finding_amplifier.value:.4f}"), t(top.finding_amplifier.description)],
        [[b("Path risk")], [b(_risk(top.numeric_risk))], t(f"category {top.category}")],
    ]
    sections.append(Section("Risk analysis", [
        Para(t("risk-v1 multiplies target criticality, entry exposure, path enablement (geometric mean of the "
               "relationship types), confidence (weakest link, INFERRED × 0.8) and control dampening; the "
               "most severe finding on the path then amplifies the result: risk = base + (1 − base) × "
               "amplifier. Every score ships with this breakdown. Breakdown of the highest-risk path:")),
        Table(["Factor", "Value", "Basis"], factor_rows),
        Para(t(f"Environment risk (env-risk-v1) aggregates the {baseline.path_count} path scores as "
               f"1 − ∏(1 − risk) = {_env(baseline.environment_risk)}.")),
        Note(t("The weights of risk-v1 and the decay parameters are structurally defined but not empirically "
               "calibrated. env-risk-v1 does not correct for overlapping paths, so correlated paths are counted "
               "more than once and the aggregate rises towards 1 as the number of paths grows; it is a "
               "comparative score, not a probability. Differences under one fixed policy are more meaningful "
               "than absolute levels.")),
    ]))

    evidence_rows = []
    for e in sorted(env.evidence, key=lambda e: (e.record or "", str(e.id))):
        supports = [names.relationship(r) for r in e.supports_relationship_ids] + [
            f"finding: {names.findings[f].title}" for f in e.supports_finding_ids
        ]
        decayed = e.confidence_at_evaluation != e.recorded_confidence
        evidence_rows.append([
            [c(e.record or _short(e.id))], t(e.source), t(e.collected_at.strftime("%Y-%m-%d") if e.collected_at else "—"),
            t(f"{e.freshness_ttl_seconds // 86400} d" if e.freshness_ttl_seconds else "—"),
            t(e.recorded_confidence or "—"),
            [b(e.confidence_at_evaluation)] if decayed else t(e.confidence_at_evaluation),
            t("; ".join(supports)),
        ])
    finding_rows = [
        [t(names.entity(f.entity_id)), t(f.title), t(f.severity),
         t(", ".join(names.evidence_label(e) for e in f.supporting_evidence_ids) or "—")]
        for f in sorted(env.findings, key=lambda f: (names.entity(f.entity_id), f.title))
    ]
    inferred_rels = [r for r in env.relationships if r.truth_tier == "INFERRED"]
    multi = [r for r in env.relationships if len(r.evidence_ids) > 1]
    lineage_blocks: list = [
        Para(t("Every observed relationship names the evidence behind it. At the evaluation time, "
               "decay-policy-v1 downgrades stale evidence by one confidence tier (highlighted); when several "
               "records support a relationship, the latest collection wins. Canonical evidence is never "
               "modified by analysis.")),
        Table(["Record", "Source", "Collected", "TTL", "Recorded", "At evaluation", "Supports"], evidence_rows),
    ]
    if multi:
        lineage_blocks.append(Bullets([
            [s("Multiple evidence: "), b(names.relationship(r.id)), s(" is supported by "),
             s(", ".join(names.evidence_label(e) for e in r.evidence_ids)),
             s(f"; resolved confidence {r.resolved_confidence} from {r.resolved_source}.")]
            for r in multi
        ]))
    if inferred_rels:
        lineage_blocks.append(Bullets([
            [s("Inferred relationship: "), b(names.relationship(r.id)),
             s(f" — {r.description} It carries no evidence and resolves to {r.resolved_confidence} confidence.")]
            for r in inferred_rels
        ]))
    lineage_blocks.append(Table(["Entity", "Finding", "Severity", "Supporting evidence"], finding_rows))
    lineage_blocks.append(Note(t(
        "risk-v1 consumes only a finding's severity; the supporting evidence of findings is shown for lineage "
        "and is not an analytical input.")))
    sections.append(Section("Evidence and finding lineage", lineage_blocks))

    bounded = report.bound_sensitivity
    sections.append(Section("Saturation and termination", [
        Bullets([
            [b("Primary analysis: "), s(f"max_paths {report.analysis.policy.max_paths}, max_hops "
                                         f"{report.analysis.policy.max_hops}, traversal_budget "
                                         f"{report.analysis.policy.traversal_budget}. Termination "),
             c(baseline.termination_reason),
             s(f"; saturated: {'yes' if baseline.is_saturated else 'no'}. All {len(ranking.candidates)} "
               f"remediation candidates are rankable." if not ranking.is_saturated else
               "; the ranking is saturated.")],
            [b("Bound sensitivity: "), s(f"the same analysis with max_paths {bounded.policy.max_paths} stops at "
                                         f"{bounded.baseline_path_count} paths and terminates "),
             c(bounded.baseline_termination_reason),
             s(f". The result is a lower bound, not a measurement: {bounded.rankable_candidate_count} of "
               f"{bounded.candidate_count} candidates are rankable, and the ranking is "
               f"{'persistence-authoritative' if bounded.persistence_authoritative else 'not persistence-authoritative'} ("),
             c(", ".join(bounded.non_authoritative_reasons) or "—"), s(").")],
            [b("Comparability: "), s(bounded.comparability_detail + ".")],
        ]),
    ]))

    candidate_rows = []
    for index, cand in enumerate(ranking.candidates):
        candidate_rows.append([
            t(str(index + 1)), t(names.relationship(cand.target_relationship_id)),
            t(f"{cand.baseline_path_count} → {cand.counterfactual_path_count}"),
            t(_env(cand.counterfactual_environment_risk)), t(f"{cand.risk_reduction:.8f}"),
            t("yes" if cand.rankable else "no"),
        ])
    after_top_text = f"{_risk(after_top.risk.numeric_risk)} ({after_top.risk.category})" if after_top else "none"
    before_after = "\n".join([
        f"BEFORE       {remediation.before.path_count} plausible paths",
        f"             highest path risk  {_risk(before_top.risk.numeric_risk)} ({before_top.risk.category})",
        f"             environment risk   {_env(remediation.before.environment_risk)}",
        "   │",
        f"REMEDIATION  remove {names.relationship(featured.id)}",
        f"   │         relationship {featured.id}",
        "   ▼",
        f"AFTER        {remediation.after.path_count} plausible paths "
        f"({len(remediation.removed_path_ids)} removed)",
        f"             highest path risk  {after_top_text}",
        f"             environment risk   {_env(remediation.after.environment_risk)} "
        f"(reduction {featured_result.risk_reduction:.8f})",
    ])
    removed = sorted((paths_by_id[pid] for pid in remediation.removed_path_ids), key=lambda p: path_rank[p.path_id])
    remaining = sorted(after_paths, key=lambda p: path_rank[p.path_id])
    sections.append(Section("Remediation counterfactual", [
        Para(t("Each relationship on a plausible path was removed, one at a time, from a clone of the "
               "projection; traversal and risk were recomputed under the identical policy and the candidates "
               "ranked by the reduction in environment risk. The canonical store and the baseline projection "
               "are not modified" + (" (verified after the run)." if remediation.baseline_projection_unchanged
                                     else "."))),
        Pre(before_after),
        Para([b(f"Removed paths ({len(removed)})"), s(" — every one uses the removed relationship:")]),
        Bullets([[s(f"#{path_rank[p.path_id]} ({_risk(p.risk.numeric_risk)}) {names.route(p, baseline.paths)}")]
                 for p in removed]),
        Para([b(f"Remaining paths ({len(remaining)})"), s(" — none uses it:")]),
        Bullets([[s(f"#{path_rank[p.path_id]} ({_risk(p.risk.numeric_risk)}) {names.route(p, baseline.paths)}")]
                 for p in remaining]),
        Table(["Rank", "Relationship removed", "Paths", "Environment risk after", "Reduction", "Rankable"],
              candidate_rows),
        Note(t("Relationships in series on exactly the same paths have identical effects; the engine orders such "
               "ties deterministically by relationship ID. A counterfactual is an analytical what-if on the "
               "model, not a statement that the change is sufficient or safe to make.")),
    ]))

    prov = report.analysis.provenance
    sections.append(Section("Provenance and persistence authority", [
        Table(["Property", "Value"], [
            [t("Policy version"), [c(prov.policy_version)]],
            [t("Policy fingerprint"), [c(prov.policy_fingerprint)]],
            [t("Evaluation time (UTC)"), [c(prov.evaluation_time.strftime("%Y-%m-%dT%H:%M:%SZ"))]],
            [t("Scope identity"), [c(f"{prov.scope_id} v{prov.scope_definition_version}")]],
            [t("Scope semantics"), t(f"{report.scope.input_boundary_kind} input boundary, "
                                     f"{report.scope.reporting_selector} reporting selector")],
            [t("Ranking persistence-authoritative"),
             t("yes" if report.persistence.ranking_persistence_authoritative else
               "no (" + ", ".join(report.persistence.ranking_non_authoritative_reasons) + ")")],
            [t("Engine identity"), [c(report.engine_identity.status)]],
            [t("Persistence preconditions met"), t("yes" if report.persistence.preconditions_met else "no")],
        ]),
        Note(t("Engine identity is only VERIFIED inside a clean, traceable, hardened container build. A run from "
               "a development checkout is reported as unverifiable, so its results could not be persisted even "
               "once persistence exists.")),
    ]))

    sections.append(Section("What this demonstrates", [Bullets([
        t("The real AttackGraph pipeline end to end: canonical records written through the repositories, exact "
          "scope resolution, graph projection, bounded deterministic traversal, risk-v1, env-risk-v1 and "
          "counterfactual remediation ranking."),
        t("Evidence lineage from relationships to their records, including decay of stale evidence and "
          "inferred relationships without evidence."),
        t("Truthful saturation and termination semantics, policy fingerprints, comparability refusal and "
          "persistence-authority gates."),
        t("Determinism: the same fixture and evaluation time produce byte-identical artifacts; only the "
          "engine-identity section reflects where the run happens."),
    ])]))
    sections.append(Section("What this does not demonstrate", [Bullets([
        t("Anything about a real environment: the data is synthetic and was never collected from a system."),
        t("That any path is exploitable in practice, or that the environment is secure after the remediation."),
        t("Calibrated risk: scores are comparative under versioned, uncalibrated formulas."),
        t("Data collection, scanning or connectors: AttackGraph does not act on or probe any environment."),
    ])]))
    return "AttackGraph — Security Analysis Report", sections


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

_MD_SPECIAL = "\\`*_{}[]<>()#+!|"


def _md_escape(text: str) -> str:
    return "".join("\\" + ch if ch in _MD_SPECIAL else ch for ch in text)


def _md_inline(runs: Inline) -> str:
    out = []
    for style, text in runs:
        if style == "b":
            out.append(f"**{_md_escape(text)}**")
        elif style == "code":
            out.append(f"`{text.replace('`', chr(39))}`")
        else:
            out.append(_md_escape(text))
    return "".join(out)


def render_markdown(report: ShowcaseReport, graph_src: str = "graph.svg") -> str:
    title, sections = build_document(report, graph_src)
    lines = [f"# {_md_escape(title)}", ""]
    for section in sections:
        if section.title:
            lines += [f"## {_md_escape(section.title)}", ""]
        for block in section.blocks:
            if isinstance(block, Para):
                lines += [_md_inline(block.runs), ""]
            elif isinstance(block, Note):
                lines += [f"> {_md_inline(block.runs)}", ""]
            elif isinstance(block, Bullets):
                lines += [f"- {_md_inline(item)}" for item in block.items] + [""]
            elif isinstance(block, Table):
                lines.append("| " + " | ".join(_md_escape(h) for h in block.headers) + " |")
                lines.append("|" + "|".join("---" for _ in block.headers) + "|")
                for row in block.rows:
                    lines.append("| " + " | ".join(_md_inline(cell) for cell in row) + " |")
                lines.append("")
            elif isinstance(block, Pre):
                lines += ["```text", block.text.replace("```", "'''"), "```", ""]
            elif isinstance(block, Graph):
                lines += [f"![{_md_escape(block.alt)}]({block.src})", ""]
    lines.append("---")
    lines.append("")
    lines.append(_md_escape(
        f"Generated by the AttackGraph showcase ({report.project.schema_version}). "
        "Machine-readable result: showcase.json."
    ))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
:root { --bg:#ffffff; --fg:#0f172a; --muted:#475569; --line:#e2e8f0; --soft:#f8fafc; --accent:#1d4ed8; --warn:#b91c1c; }
@media (prefers-color-scheme: dark) { :root { --bg:#0b1120; --fg:#e2e8f0; --muted:#94a3b8; --line:#1e293b; --soft:#111827; --accent:#93c5fd; --warn:#fca5a5; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif; }
main { max-width:1080px; margin:0 auto; padding:32px 16px 64px; }
h1 { font-size:28px; margin:0 0 16px; }
h2 { font-size:20px; margin:40px 0 12px; padding-top:12px; border-top:1px solid var(--line); }
p, li { max-width:80ch; }
code { font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:var(--soft); padding:1px 4px; border-radius:4px; overflow-wrap:anywhere; }
pre { font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:var(--soft); border:1px solid var(--line); border-radius:8px; padding:12px 14px; overflow-x:auto; }
blockquote { margin:12px 0; padding:8px 14px; border-left:4px solid var(--accent); background:var(--soft); color:var(--muted); }
.table-wrap { overflow-x:auto; margin:12px 0; }
table { border-collapse:collapse; font-size:13px; min-width:100%; }
th, td { border:1px solid var(--line); padding:6px 8px; text-align:left; vertical-align:top; }
th { background:var(--soft); }
.graph { overflow-x:auto; border:1px solid var(--line); border-radius:8px; margin:12px 0; background:#ffffff; }
.graph svg { display:block; max-width:none; }
footer { margin-top:48px; color:var(--muted); font-size:13px; }
"""


def _html_inline(runs: Inline) -> str:
    out = []
    for style, text in runs:
        if style == "b":
            out.append(f"<strong>{html_escape(text)}</strong>")
        elif style == "code":
            out.append(f"<code>{html_escape(text)}</code>")
        else:
            out.append(html_escape(text))
    return "".join(out)


def render_html(report: ShowcaseReport) -> str:
    title, sections = build_document(report)
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html_escape(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        f"<h1>{html_escape(title)}</h1>",
    ]
    for section in sections:
        if section.title:
            parts.append(f"<h2>{html_escape(section.title)}</h2>")
        for block in section.blocks:
            if isinstance(block, Para):
                parts.append(f"<p>{_html_inline(block.runs)}</p>")
            elif isinstance(block, Note):
                parts.append(f"<blockquote>{_html_inline(block.runs)}</blockquote>")
            elif isinstance(block, Bullets):
                parts.append("<ul>" + "".join(f"<li>{_html_inline(item)}</li>" for item in block.items) + "</ul>")
            elif isinstance(block, Table):
                head = "".join(f"<th>{html_escape(h)}</th>" for h in block.headers)
                body = "".join(
                    "<tr>" + "".join(f"<td>{_html_inline(cell)}</td>" for cell in row) + "</tr>"
                    for row in block.rows
                )
                parts.append(f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
                             f"<tbody>{body}</tbody></table></div>")
            elif isinstance(block, Pre):
                parts.append(f"<pre>{html_escape(block.text)}</pre>")
            elif isinstance(block, Graph):
                parts.append(f'<div class="graph">{render_svg(report)}</div>')
    parts.append(
        f"<footer>Generated by the AttackGraph showcase ({html_escape(report.project.schema_version)}). "
        "Machine-readable result: showcase.json.</footer>"
    )
    parts += ["</main>", "</body>", "</html>"]
    return "\n".join(parts) + "\n"
