"""End-to-End Integration tests for Counterfactual Engine."""

import pytest
from sqlalchemy import select

from app.domain.models import Finding
from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore
from app.analytics.counterfactual import CounterfactualEngine
from app.schemas.analytics import FindingRiskInput
from scripts.load_synthetic_data import load_synthetic_topology


@pytest.mark.asyncio
@pytest.mark.integration
async def test_postgres_counterfactual_pipeline(pg_session):
    """Test the complete Phase 5 counterfactual analytical pipeline.

    Verifies that the canonical graph and PostgreSQL database remain
    immutable while evaluating deterministic risk reduction.
    """

    # 1. Setup Topology
    topology = await load_synthetic_topology(pg_session)
    entities = topology["entities"]
    relationships = topology["relationships"]

    # 2. Build Graph (Phase 2)
    store = NetworkXStore()
    builder = GraphBuilder(pg_session, store)
    await builder.build()

    # Take snapshot for immutability check
    initial_nodes = list(store.graph.nodes(data=True))
    initial_edges = list(store.graph.edges(keys=True, data=True))

    # 3. Load Findings Map
    stmt = select(Finding)
    finding_results = await pg_session.execute(stmt)
    db_findings = finding_results.scalars().all()

    findings_map = {}
    for f in db_findings:
        if f.entity_id not in findings_map:
            findings_map[f.entity_id] = []
        findings_map[f.entity_id].append(
            FindingRiskInput(
                finding_id=f.id,
                entity_id=f.entity_id,
                severity=f.severity
            )
        )

    # 4. Counterfactual Engine (Phase 5)
    engine = CounterfactualEngine(store, findings_map)
    source_id = entities["admin"]
    target_id = entities["customer_data"]

    candidates = [
        relationships["jump_routes_app"],
        relationships["admin_auth_jump"]
    ]

    from datetime import datetime, timezone
    eval_time = datetime.now(timezone.utc)
    # Prove evaluation_time is required here as well
    ranking = engine.evaluate_candidates(
        source_id, target_id,
        candidate_relationship_ids=candidates,
        evaluation_time=eval_time
    )

    # Assert Ranking Output
    assert ranking.baseline_path_count > 0
    assert ranking.baseline_environment_risk > 0.0
    assert len(ranking.candidates) == 2

    # Ensure subset invariant for all candidates
    for c in ranking.candidates:
        assert c.baseline_path_count == ranking.baseline_path_count
        assert len(c.removed_path_ids) + len(c.remaining_path_ids) == ranking.baseline_path_count

    # Assert deterministic tie-breaking logic
    # risk_reduction DESC -> cf_env_risk ASC -> cf_path_count ASC -> uuid ASC
    expected_order = sorted(
        ranking.candidates,
        key=lambda r: (
            -r.risk_reduction,
            r.counterfactual_environment_risk,
            r.counterfactual_path_count,
            str(r.target_relationship_id)
        )
    )
    assert ranking.candidates == expected_order

    # 5. Assert Graph and Database Immutability
    final_nodes = list(store.graph.nodes(data=True))
    final_edges = list(store.graph.edges(keys=True, data=True))

    assert initial_nodes == final_nodes
    assert initial_edges == final_edges
