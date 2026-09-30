"""Showcase orchestration over the real AttackGraph engines.

Pipeline (each step is the existing component, not a re-implementation):

    empty, migrated PostgreSQL  (checked; fail closed otherwise)
      -> synthetic fixture written through the canonical repositories
      -> resolve_analytical_scope (exact scope_id + definition_version, ARCH-28)
      -> AnalysisContext (AnalysisPolicyV2, UTC evaluation time, canonical scope)
      -> GraphBuilder -> NetworkXStore projection
      -> TraversalEngine under the policy's bounds
      -> risk-v1 per path, env-risk-v1 aggregate
      -> CounterfactualEngine over every relationship on the baseline paths
      -> the same under a tighter max_paths (saturation semantics)
      -> ShowcaseReport

The whole run happens inside one database transaction that is always rolled
back: nothing is persisted to the canonical store and no analytical output is
ever written to it (ARCH-4). The showcase's own baseline is cross-checked
against the counterfactual engine's baseline and the run fails closed on any
divergence.
"""

import uuid
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import selectinload
from sqlalchemy.pool import NullPool

from app.analytics.aggregator import EnvironmentRiskAggregator
from app.analytics.comparability import ComparabilityError, verify_comparability
from app.analytics.context import AnalysisContext
from app.analytics.counterfactual import CounterfactualEngine
from app.analytics.decay import apply_decay, resolve_edge_evidence
from app.analytics.engine_identity import EngineIdentityService
from app.analytics.path_analysis import build_risk_input, traversal_bounds_for_policy
from app.analytics.policy import AnalysisPolicyV2, generate_policy_fingerprint
from app.analytics.risk_engine import RiskEngine
from app.domain.models import Base, Evidence, Finding
from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import TraversalEngine
from app.graph.scope_resolution import resolve_analytical_scope
from app.schemas.analytics import FindingRiskInput, generate_canonical_path_id
from app.showcase.fixture import SHOWCASE_EVALUATION_TIME, SHOWCASE_FIXTURE, ShowcaseFixture, load_showcase_fixture
from app.showcase.report import (
    SHOWCASE_SCHEMA_VERSION,
    AnalysisReport,
    BaselineReport,
    BoundSensitivityReport,
    EngineIdentityReport,
    EntityReport,
    EnvironmentReport,
    EvidenceReport,
    FindingReport,
    PathReport,
    PathStep,
    PersistenceAuthorityReport,
    ProjectInfo,
    ProjectionReport,
    RelationshipReport,
    RemediationReport,
    RiskState,
    ScopeReport,
    ShowcaseReport,
)
from app.storage.graph_queries import get_all_entities_for_projection, get_all_relationships_for_projection

# Modelled attacker effort per relationship type for the showcase policy.
# These are policy values chosen for the demonstration, not calibrated
# measurements (ANA-12); they are part of the policy fingerprint.
_SHOWCASE_EDGE_COSTS = {
    "CAN_ASSUME": 2,
    "CAN_AUTHENTICATE_TO": 2,
    "COMMUNICATES_WITH": 1,
    "DEPENDS_ON": 2,
    "EXPOSES": 1,
    "HAS_PERMISSION_ON": 1,
    "MEMBER_OF": 1,
    "ROUTES_TO": 1,
    "RUNS_AS": 1,
    "STORES": 2,
    "TRUSTS": 2,
}


def showcase_policy(max_paths: int = 50) -> AnalysisPolicyV2:
    """The analysis policy of the showcase (all relationship types allowed)."""
    return AnalysisPolicyV2(
        traversal_policy_version="traversal-policy-v1",
        risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1",
        decay_policy_version="decay-policy-v1",
        max_hops=8,
        traversal_budget=12,
        max_paths=max_paths,
        allowed_edge_types=None,
        edge_costs=_SHOWCASE_EDGE_COSTS,
    )


SHOWCASE_POLICY = showcase_policy()
# Same policy with an enumeration limit below the number of plausible paths,
# used to demonstrate saturation semantics.
BOUNDED_POLICY = showcase_policy(max_paths=4)

DISCLAIMER = [
    "Synthetic demonstration: every entity, address, record and finding is fictional.",
    "AttackGraph analyses a model of an authorized environment; it does not scan, probe or exploit anything.",
    "Attack paths are plausible paths under the model and the policy's bounds, not confirmed attacks.",
    "Risk values are comparative analytical scores under versioned formulas, not probabilities of compromise.",
]

_BACKEND_DIR = Path(__file__).resolve().parents[2]


class ShowcaseDatabaseNotReady(RuntimeError):
    """The target database cannot host a showcase run."""


class ShowcaseConsistencyError(RuntimeError):
    """Two engine outputs that must agree did not."""


def _alembic_head() -> str:
    config = Config()
    config.set_main_option("script_location", str(_BACKEND_DIR / "alembic"))
    return ScriptDirectory.from_config(config).get_current_head()


async def ensure_database_ready(session: AsyncSession) -> None:
    """Require a PostgreSQL database migrated to the Alembic head with no canonical data.

    With a UNIVERSAL scope the projection contains every entity in the
    database, so any pre-existing data would enter the analysis and the
    report. The showcase therefore refuses to run on a non-empty database.
    """
    if session.bind.dialect.name != "postgresql":
        raise ShowcaseDatabaseNotReady("the showcase requires PostgreSQL")
    has_version_table = (await session.execute(text("SELECT to_regclass('alembic_version')"))).scalar()
    if has_version_table is None:
        raise ShowcaseDatabaseNotReady(
            "database is not migrated; run `alembic upgrade head` first"
        )
    current = (await session.execute(text("SELECT version_num FROM alembic_version"))).scalar()
    head = _alembic_head()
    if current != head:
        raise ShowcaseDatabaseNotReady(
            f"database schema revision {current!r} is not the Alembic head {head!r}"
        )
    for table in Base.metadata.sorted_tables:
        if (await session.execute(select(table).limit(1))).first() is not None:
            raise ShowcaseDatabaseNotReady(
                f"table {table.name!r} is not empty; the showcase requires an empty AttackGraph "
                f"database so that no real data enters the analysis"
            )


def _engine_identity_report(service: EngineIdentityService) -> EngineIdentityReport:
    status = service.check_immutability()
    try:
        metadata = service.get_metadata()
    except (OSError, ValueError, TypeError):
        metadata = None
    return EngineIdentityReport(
        status=status,
        persistence_authorized=service.authorize_persistence(),
        metadata=metadata,
    )


def _project_info() -> ProjectInfo:
    from app.main import app as api

    return ProjectInfo(name="AttackGraph", version=api.version, schema_version=SHOWCASE_SCHEMA_VERSION)


def _max_risk(paths: list[PathReport]) -> float:
    return max(p.risk.numeric_risk for p in paths)


async def analyze(
    session: AsyncSession,
    engine_identity: EngineIdentityService,
    fixture: ShowcaseFixture = SHOWCASE_FIXTURE,
) -> ShowcaseReport:
    """Run the showcase inside the caller's transaction (which the caller rolls back)."""
    await ensure_database_ready(session)
    loaded = await load_showcase_fixture(session, fixture)

    # 1. Canonical scope resolution by exact version (ARCH-28).
    scope = await resolve_analytical_scope(session, loaded.scope_id, loaded.definition_version)

    # 2. Analysis context: V2 policy, UTC evaluation time, canonical scope.
    policy = SHOWCASE_POLICY
    context = AnalysisContext(policy=policy, evaluation_time=SHOWCASE_EVALUATION_TIME, scope=scope)
    evaluation_time = context.evaluation_time

    # 3. Graph projection from the canonical store.
    store = NetworkXStore()
    await GraphBuilder(session, store).build(scope)

    # Canonical inventory of this run, and proof that all of it was projected.
    entities = sorted(await get_all_entities_for_projection(session), key=lambda e: str(e.id))
    relationships = sorted(await get_all_relationships_for_projection(session), key=lambda r: str(r.id))
    evidence_rows = sorted(
        (await session.execute(select(Evidence))).scalars().all(), key=lambda e: str(e.id)
    )
    finding_rows = sorted(
        (await session.execute(select(Finding).options(selectinload(Finding.evidence_links)))).scalars().all(),
        key=lambda f: str(f.id),
    )
    all_projected = all(store.get_entity(e.id) is not None for e in entities) and all(
        store.get_relationship(r.id) is not None for r in relationships
    )
    if not all_projected:
        raise ShowcaseConsistencyError("canonical records are missing from the graph projection")

    findings_map: dict[uuid.UUID, list[FindingRiskInput]] = {}
    for finding in finding_rows:
        findings_map.setdefault(finding.entity_id, []).append(
            FindingRiskInput(finding_id=finding.id, entity_id=finding.entity_id, severity=finding.severity)
        )

    source_id = fixture.entity(fixture.source_entity).id
    target_id = fixture.entity(fixture.target_entity).id

    # 4. Bounded traversal under the policy's bounds (the same bounds the
    # counterfactual engine derives from this policy).
    bounds = traversal_bounds_for_policy(policy)
    traversal = TraversalEngine(store).find_paths(
        source_id,
        target_id,
        policy=bounds.policy,
        max_hops=bounds.max_hops,
        max_paths=bounds.max_paths,
        allowed_types=bounds.allowed_types,
    )

    # 5. risk-v1 per path and 6. env-risk-v1 over the paths in traversal order.
    path_reports: list[PathReport] = []
    for path in traversal.paths:
        risk_input = build_risk_input(path, store, findings_map, evaluation_time)
        risk = RiskEngine.calculate(risk_input, formula_version=policy.risk_formula_version)
        steps = []
        for index, relationship_id in enumerate(path.edge_ids):
            edge = store.get_relationship(relationship_id)
            steps.append(PathStep(
                relationship_id=relationship_id,
                relationship_type=risk_input.edge_types[index],
                truth_tier=risk_input.edge_truth_tiers[index],
                from_entity_id=path.node_ids[index],
                to_entity_id=path.node_ids[index + 1],
                resolved_confidence=risk_input.edge_confidences[index],
                resolved_source=risk_input.edge_sources[index],
                evidence_ids=sorted(edge["evidence_ids"], key=str),
            ))
        path_reports.append(PathReport(
            path_id=generate_canonical_path_id(path),
            node_ids=list(path.node_ids),
            relationship_ids=list(path.edge_ids),
            hop_count=len(path.edge_ids),
            steps=steps,
            risk=risk,
        ))
    if not path_reports:
        raise ShowcaseConsistencyError("the showcase environment produced no attack paths")
    environment_risk = EnvironmentRiskAggregator.calculate(p.risk.numeric_risk for p in path_reports)
    baseline_path_ids = [p.path_id for p in path_reports]

    # 7. Counterfactual remediation over every relationship on a baseline path.
    candidate_ids = sorted({rid for p in path_reports for rid in p.relationship_ids}, key=str)
    ranking = CounterfactualEngine(store, findings_map).evaluate_candidates(
        source_id, target_id, candidate_ids, context=context
    )

    # The counterfactual engine enumerated its own baseline with the same
    # policy; both must agree exactly, or the showcase is not showing the engine.
    if (
        ranking.baseline_path_count != len(path_reports)
        or ranking.baseline_environment_risk != environment_risk
        or ranking.baseline_is_saturated != traversal.is_saturated
        or ranking.baseline_termination_reason != traversal.termination_reason
    ):
        raise ShowcaseConsistencyError("showcase baseline diverges from the counterfactual engine baseline")
    for candidate in ranking.candidates:
        if sorted(candidate.removed_path_ids + candidate.remaining_path_ids) != sorted(baseline_path_ids):
            raise ShowcaseConsistencyError(
                f"counterfactual path sets for {candidate.target_relationship_id} do not partition the baseline"
            )

    featured = ranking.candidates[0]
    if not featured.rankable:
        raise ShowcaseConsistencyError("the top-ranked candidate is not rankable (saturated analysis)")
    equivalent = sorted(
        (
            c.target_relationship_id
            for c in ranking.candidates[1:]
            if c.risk_reduction == featured.risk_reduction
            and c.remaining_path_ids == featured.remaining_path_ids
        ),
        key=str,
    )
    remaining = set(featured.remaining_path_ids)
    remaining_paths = [p for p in path_reports if p.path_id in remaining]
    # Counterfactual isolation (ARCH-17): the baseline projection still holds
    # every relationship after all candidates were evaluated on clones.
    baseline_unchanged = all(store.get_relationship(r.id) is not None for r in relationships)

    remediation = RemediationReport(
        candidate_relationship_ids=candidate_ids,
        ranking=ranking,
        featured_relationship_id=featured.target_relationship_id,
        equivalent_relationship_ids=equivalent,
        before=RiskState(
            path_count=len(path_reports),
            environment_risk=environment_risk,
            max_path_risk=_max_risk(path_reports),
            path_ids=sorted(baseline_path_ids),
        ),
        after=RiskState(
            path_count=featured.counterfactual_path_count,
            environment_risk=featured.counterfactual_environment_risk,
            max_path_risk=_max_risk(remaining_paths) if remaining_paths else None,
            path_ids=featured.remaining_path_ids,
        ),
        removed_path_ids=featured.removed_path_ids,
        baseline_projection_unchanged=baseline_unchanged,
    )
    if len(remaining_paths) != featured.counterfactual_path_count:
        raise ShowcaseConsistencyError("remaining paths do not match the counterfactual path count")

    # 8. Bound sensitivity: the same analysis under a tighter max_paths.
    bounded_context = AnalysisContext(
        policy=BOUNDED_POLICY, evaluation_time=SHOWCASE_EVALUATION_TIME, scope=scope
    )
    bounded = CounterfactualEngine(store, findings_map).evaluate_candidates(
        source_id, target_id, candidate_ids, context=bounded_context
    )
    try:
        verify_comparability(policy, BOUNDED_POLICY)
        comparable, comparability_detail = True, "policy fingerprints match"
    except ComparabilityError:
        comparable, comparability_detail = False, (
            f"policy fingerprints differ (max_paths {policy.max_paths} vs {BOUNDED_POLICY.max_paths}); "
            f"the results are not comparable (ARCH-20)"
        )

    engine = _engine_identity_report(engine_identity)
    path_relationship_ids = {rid for p in path_reports for rid in p.relationship_ids}
    supports_relationships: dict[uuid.UUID, list[uuid.UUID]] = {}
    for relationship in relationships:
        for link in relationship.evidence_links:
            supports_relationships.setdefault(link.evidence_id, []).append(relationship.id)
    supports_findings: dict[uuid.UUID, list[uuid.UUID]] = {}
    for finding in finding_rows:
        for link in finding.evidence_links:
            supports_findings.setdefault(link.evidence_id, []).append(finding.id)

    relationship_reports = []
    for relationship in relationships:
        edge = store.get_relationship(relationship.id)
        resolved_confidence, resolved_source = resolve_edge_evidence(
            raw_evidence_list=edge.get("raw_evidence"),
            edge_id=str(relationship.id),
            truth_tier=edge["truth_tier"],
            evaluation_time=evaluation_time,
        )
        relationship_reports.append(RelationshipReport(
            id=relationship.id,
            source_entity_id=relationship.source_entity_id,
            target_entity_id=relationship.target_entity_id,
            relationship_type=relationship.relationship_type,
            truth_tier=relationship.truth_tier,
            description=(relationship.metadata_ or {}).get("description"),
            evidence_ids=sorted((link.evidence_id for link in relationship.evidence_links), key=str),
            resolved_confidence=resolved_confidence,
            resolved_source=resolved_source,
            on_baseline_path=relationship.id in path_relationship_ids,
        ))

    environment = EnvironmentReport(
        organisation=fixture.organisation,
        notes=list(fixture.notes),
        entities=[
            EntityReport(
                id=e.id,
                canonical_key=e.canonical_key,
                entity_type=e.entity_type,
                name=e.name,
                description=e.description,
                criticality=e.criticality,
                exposure=e.exposure,
                address=(e.metadata_ or {}).get("address"),
                finding_ids=sorted((f.id for f in finding_rows if f.entity_id == e.id), key=str),
            )
            for e in entities
        ],
        relationships=relationship_reports,
        evidence=[
            EvidenceReport(
                id=e.id,
                source=e.source,
                source_type=e.source_type,
                assertion=e.assertion,
                collected_at=e.collected_at,
                freshness_ttl_seconds=e.freshness_ttl_seconds,
                recorded_confidence=e.confidence,
                confidence_at_evaluation=apply_decay(
                    {
                        "confidence": e.confidence,
                        "collected_at": e.collected_at,
                        "freshness_ttl_seconds": e.freshness_ttl_seconds,
                    },
                    evaluation_time,
                ),
                record=(e.raw_reference or {}).get("record"),
                supports_relationship_ids=sorted(supports_relationships.get(e.id, []), key=str),
                supports_finding_ids=sorted(supports_findings.get(e.id, []), key=str),
            )
            for e in evidence_rows
        ],
        findings=[
            FindingReport(
                id=f.id,
                entity_id=f.entity_id,
                title=f.title,
                severity=f.severity,
                description=f.description,
                supporting_evidence_ids=sorted((link.evidence_id for link in f.evidence_links), key=str),
            )
            for f in finding_rows
        ],
    )

    return ShowcaseReport(
        project=_project_info(),
        disclaimer=list(DISCLAIMER),
        engine_identity=engine,
        scope=ScopeReport(
            scope_id=scope.scope_id,
            definition_version=scope.definition_version,
            display_name=fixture.scope_display_name,
            input_boundary_kind=scope.input_boundary_kind,
            reporting_selector=scope.reporting_selector,
        ),
        analysis=AnalysisReport(
            source_entity_id=source_id,
            target_entity_id=target_id,
            evaluation_time=evaluation_time,
            policy=policy,
            provenance=context.provenance(),
        ),
        environment=environment,
        projection=ProjectionReport(
            entity_count=len(entities),
            relationship_count=len(relationships),
            all_canonical_records_projected=all_projected,
        ),
        baseline=BaselineReport(
            termination_reason=traversal.termination_reason,
            is_saturated=traversal.is_saturated,
            path_count=len(path_reports),
            environment_risk=environment_risk,
            max_path_risk=_max_risk(path_reports),
            paths=path_reports,
        ),
        remediation=remediation,
        bound_sensitivity=BoundSensitivityReport(
            policy=BOUNDED_POLICY,
            policy_fingerprint=generate_policy_fingerprint(BOUNDED_POLICY),
            baseline_termination_reason=bounded.baseline_termination_reason,
            baseline_is_saturated=bounded.baseline_is_saturated,
            baseline_path_count=bounded.baseline_path_count,
            is_saturated=bounded.is_saturated,
            rankable_candidate_count=sum(1 for c in bounded.candidates if c.rankable),
            candidate_count=len(bounded.candidates),
            persistence_authoritative=bounded.persistence_authoritative,
            non_authoritative_reasons=bounded.non_authoritative_reasons,
            comparable_with_primary=comparable,
            comparability_detail=comparability_detail,
        ),
        persistence=PersistenceAuthorityReport(
            ranking_persistence_authoritative=ranking.persistence_authoritative,
            ranking_non_authoritative_reasons=ranking.non_authoritative_reasons,
            engine_status=engine.status,
            engine_persistence_authorized=engine.persistence_authorized,
            preconditions_met=ranking.persistence_authoritative and engine.persistence_authorized,
        ),
    )


async def run_showcase(database_url: str, engine_identity: EngineIdentityService) -> ShowcaseReport:
    """Run the showcase against `database_url` in a transaction that is always rolled back."""
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                session = AsyncSession(bind=connection, expire_on_commit=False)
                try:
                    return await analyze(session, engine_identity)
                finally:
                    await session.close()
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
