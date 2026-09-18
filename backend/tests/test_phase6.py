"""Tests for Phase 6 analytical requirements."""

import uuid
import pytest
from datetime import datetime, timezone, timedelta

from app.schemas.analytics import (
    AttackPath,
    TraversalPolicy,
    RiskInput,
)
from app.analytics.decay import apply_decay, resolve_edge_evidence
from app.analytics.risk_engine import RiskEngine
from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import TraversalEngine
from app.analytics.overlap import PathOverlapAnalyzer
from app.schemas.analytics import generate_canonical_path_id


@pytest.fixture
def eval_time():
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_decay_policy_exact_bounds(eval_time):
    """Test step-decay exact bounds and exemptions."""
    # Exemption: missing TTL
    ev1 = {"confidence": "HIGH", "collected_at": eval_time - timedelta(days=1)}
    assert apply_decay(ev1, eval_time) == "HIGH"

    # Exemption: TTL = 0
    ev2 = {"confidence": "HIGH", "collected_at": eval_time - timedelta(days=1), "freshness_ttl_seconds": 0}
    assert apply_decay(ev2, eval_time) == "HIGH"

    # Exemption: missing collected_at
    ev_no_collected = {"confidence": "HIGH", "freshness_ttl_seconds": 3600}
    assert apply_decay(ev_no_collected, eval_time) == "HIGH"

    # Exact boundary (not stale yet)
    ev3 = {"confidence": "HIGH", "collected_at": eval_time - timedelta(hours=1), "freshness_ttl_seconds": 3600}
    assert apply_decay(ev3, eval_time) == "HIGH"

    # Just expired -> downgrade HIGH to MEDIUM
    ev4 = {"confidence": "HIGH", "collected_at": eval_time - timedelta(hours=1, seconds=1), "freshness_ttl_seconds": 3600}
    assert apply_decay(ev4, eval_time) == "MEDIUM"

    # Downgrade MEDIUM to LOW
    ev5 = {"confidence": "MEDIUM", "collected_at": eval_time - timedelta(days=10), "freshness_ttl_seconds": 3600}
    assert apply_decay(ev5, eval_time) == "LOW"

    # Downgrade LOW to UNKNOWN
    ev6 = {"confidence": "LOW", "collected_at": eval_time - timedelta(days=10), "freshness_ttl_seconds": 3600}
    assert apply_decay(ev6, eval_time) == "UNKNOWN"

    # UNKNOWN stays UNKNOWN
    ev7 = {"confidence": "UNKNOWN", "collected_at": eval_time - timedelta(days=10), "freshness_ttl_seconds": 3600}
    assert apply_decay(ev7, eval_time) == "UNKNOWN"


def test_resolve_edge_evidence(eval_time):
    """Test temporal conflict resolution and pessimistic fallback."""
    edge_id = "test-edge"

    # Inferred provenance
    conf, src = resolve_edge_evidence([], edge_id, "INFERRED", eval_time)
    assert conf == "UNKNOWN"
    assert src == f"inference:{edge_id}"

    # Missing source -> unique
    conf, src = resolve_edge_evidence([], edge_id, "OBSERVED", eval_time)
    assert conf == "UNKNOWN"
    assert src == f"unknown-source:{edge_id}"

    # Temporal resolution (latest wins)
    ev_list = [
        {"confidence": "HIGH", "source": "scanner-A", "collected_at": eval_time - timedelta(days=2)},
        {"confidence": "LOW", "source": "scanner-A", "collected_at": eval_time - timedelta(days=1)},
    ]
    conf, src = resolve_edge_evidence(ev_list, edge_id, "OBSERVED", eval_time)
    assert conf == "LOW" # Latest is LOW
    assert src == "scanner-A"

    # Tied timestamp, pessimistic fallback (min confidence wins)
    ev_list_tied = [
        {"confidence": "HIGH", "source": "scanner-A", "collected_at": eval_time - timedelta(days=1)},
        {"confidence": "LOW", "source": "scanner-A", "collected_at": eval_time - timedelta(days=1)},
    ]
    conf, src = resolve_edge_evidence(ev_list_tied, edge_id, "OBSERVED", eval_time)
    assert conf == "LOW"
    assert src == "scanner-A"

    # Decay-before-grouping order
    # Stale HIGH decays to MEDIUM. It is newer than a fresh LOW, so it wins, and its decayed value is MEDIUM.
    ev_list_decay = [
        {"confidence": "LOW", "source": "scanner-A", "collected_at": eval_time - timedelta(days=2), "freshness_ttl_seconds": 86400 * 10},
        {"confidence": "HIGH", "source": "scanner-A", "collected_at": eval_time - timedelta(days=1, seconds=1), "freshness_ttl_seconds": 86400},
    ]
    conf, src = resolve_edge_evidence(ev_list_decay, edge_id, "OBSERVED", eval_time)
    # The second one is newer (days=1 vs days=2). Its timestamp is higher.
    # It decays from HIGH to MEDIUM because it's 1 second past TTL.
    # It wins because it is newer.
    assert conf == "MEDIUM"


def test_traversal_budget_bounds():
    """Test max_hops computational bounds and semantic zero-cost edges."""
    store = NetworkXStore()
    n1 = uuid.uuid4()
    n2 = uuid.uuid4()
    n3 = uuid.uuid4()
    n4 = uuid.uuid4()
    n5 = uuid.uuid4()

    store.add_entity(n1, "HOST", "A")
    store.add_entity(n2, "HOST", "B")
    store.add_entity(n3, "HOST", "C")
    store.add_entity(n4, "HOST", "D")
    store.add_entity(n5, "HOST", "E")

    # Path: A -> B (cost 0) -> C (cost 0) -> D (cost 1)
    store.add_relationship(uuid.uuid4(), n1, n2, "EXPOSES", "OBSERVED")
    store.add_relationship(uuid.uuid4(), n2, n3, "ROUTES_TO", "OBSERVED")
    store.add_relationship(uuid.uuid4(), n3, n4, "CAN_AUTHENTICATE_TO", "OBSERVED")

    # Zero-cost cycle: D -> B (cost 0)
    store.add_relationship(uuid.uuid4(), n4, n2, "ROUTES_TO", "OBSERVED")

    engine = TraversalEngine(store)

    policy = TraversalPolicy(
        max_hops=2, # Computational bound
        traversal_budget=5,
        edge_costs={"EXPOSES": 0, "ROUTES_TO": 0, "CAN_AUTHENTICATE_TO": 1}
    )

    # Will fail to find path because max_hops=2 (computational limit hit)
    res1 = engine.find_paths(n1, n4, policy=policy)
    assert res1.paths_found == 0

    policy2 = TraversalPolicy(
        max_hops=10,
        traversal_budget=0, # Semantic bound
        edge_costs={"EXPOSES": 0, "ROUTES_TO": 0, "CAN_AUTHENTICATE_TO": 1}
    )

    # Will fail because accumulated cost (1) > traversal_budget (0)
    res2 = engine.find_paths(n1, n4, policy=policy2)
    assert res2.paths_found == 0

    policy3 = TraversalPolicy(
        max_hops=10,
        traversal_budget=1, # Exact boundary
        edge_costs={"EXPOSES": 0, "ROUTES_TO": 0, "CAN_AUTHENTICATE_TO": 1}
    )

    # Succeeds (exact boundary)
    res3 = engine.find_paths(n1, n4, policy=policy3)
    assert res3.paths_found == 1

    # Zero-cost cycle safety: max_hops terminates it
    store.add_relationship(uuid.uuid4(), n4, n5, "CAN_AUTHENTICATE_TO", "OBSERVED")
    # Path A -> B -> C -> D -> E (budget=2)
    # The cycle D -> B -> C -> D -> E is blocked by node visitation logic in TraversalEngine (visited list prevents node cycles)
    # So zero-cost cycle is naturally safe, but max_hops would break it if edges were parallel.
    # Let's add parallel zero-cost edges
    for i in range(15):
        store.add_relationship(uuid.uuid4(), n2, n3, "ROUTES_TO", "OBSERVED")

    res_parallel = engine.find_paths(n1, n5, policy=TraversalPolicy(max_hops=3, traversal_budget=10, edge_costs={"EXPOSES": 0, "ROUTES_TO": 0, "CAN_AUTHENTICATE_TO": 1}))
    # max_hops=3 breaks it before it can reach E (needs 4 hops: A->B, B->C, C->D, D->E)
    assert res_parallel.paths_found == 0


def test_source_aware_confidence_risk_v2():
    """Test same-source vs different-source risk-v2 calculations."""
    path = AttackPath(
        node_ids=[uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()],
        edge_ids=[uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    )

    # Same source correlated edges (all from scanner-A)
    # scanner-A confidence = min(HIGH, MEDIUM, HIGH) = MEDIUM (0.8)
    # Path confidence = 0.8
    ri_same = RiskInput(
        path=path,
        target_criticality="HIGH",
        entry_exposure="EXTERNAL",
        edge_types=["ROUTES_TO", "ROUTES_TO", "ROUTES_TO"],
        edge_confidences=["HIGH", "MEDIUM", "HIGH"],
        edge_truth_tiers=["OBSERVED", "OBSERVED", "OBSERVED"],
        edge_sources=["scanner-A", "scanner-A", "scanner-A"],
        findings=[]
    )

    res_same = RiskEngine.calculate(ri_same, formula_version="risk-v2")
    assert res_same.confidence.value == 0.8

    # Different sources
    # scanner-A = min(HIGH, HIGH) = HIGH (1.0)
    # scanner-B = min(MEDIUM) = MEDIUM (0.8)
    # Path confidence = 1.0 * 0.8 = 0.8
    ri_diff = RiskInput(
        path=path,
        target_criticality="HIGH",
        entry_exposure="EXTERNAL",
        edge_types=["ROUTES_TO", "ROUTES_TO", "ROUTES_TO"],
        edge_confidences=["HIGH", "HIGH", "MEDIUM"],
        edge_truth_tiers=["OBSERVED", "OBSERVED", "OBSERVED"],
        edge_sources=["scanner-A", "scanner-A", "scanner-B"],
        findings=[]
    )

    res_diff = RiskEngine.calculate(ri_diff, formula_version="risk-v2")
    assert res_diff.confidence.value == 0.8

    # Different sources punishing
    # scanner-A = min(MEDIUM) = 0.8
    # scanner-B = min(MEDIUM) = 0.8
    # Path confidence = 0.8 * 0.8 = 0.64
    ri_punish = RiskInput(
        path=path,
        target_criticality="HIGH",
        entry_exposure="EXTERNAL",
        edge_types=["ROUTES_TO", "ROUTES_TO", "ROUTES_TO"],
        edge_confidences=["HIGH", "MEDIUM", "MEDIUM"],
        edge_truth_tiers=["OBSERVED", "OBSERVED", "OBSERVED"],
        edge_sources=["scanner-A", "scanner-A", "scanner-B"],
        findings=[]
    )
    # Wait, scanner-A = min(HIGH, MEDIUM) = 0.8
    res_punish = RiskEngine.calculate(ri_punish, formula_version="risk-v2")
    assert res_punish.confidence.value == pytest.approx(0.64)

    # Ensure risk-v1 is unchanged (agnostic min)
    # min(HIGH, MEDIUM, MEDIUM) = MEDIUM (0.8)
    res_v1 = RiskEngine.calculate(ri_punish, formula_version="risk-v1")
    assert res_v1.confidence.value == 0.8

    # Source vs source_type: Group strictly by `source`
    ri_types = RiskInput(
        path=path,
        target_criticality="HIGH",
        entry_exposure="EXTERNAL",
        edge_types=["ROUTES_TO", "ROUTES_TO", "ROUTES_TO"],
        edge_confidences=["HIGH", "MEDIUM", "HIGH"],
        edge_truth_tiers=["OBSERVED", "OBSERVED", "OBSERVED"],
        edge_sources=["scanner-A", "scanner-B", "scanner-A"], # scanner-B is a different source, even if same type
        findings=[]
    )
    # scanner-A = HIGH (1.0), scanner-B = MEDIUM (0.8) => 0.8
    res_types = RiskEngine.calculate(ri_types, formula_version="risk-v2")
    assert res_types.confidence.value == 0.8


def test_path_overlap_analyzer():
    """Test Jaccard overlap avoidance and edge participation."""
    n1, n2, n3, n4 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    e1, e2, e3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    p1 = AttackPath(node_ids=[n1, n2, n4], edge_ids=[e1, e2])
    p2 = AttackPath(node_ids=[n1, n3, n4], edge_ids=[e3, e2])

    from app.schemas.analytics import PathfindingResult
    pr = PathfindingResult(
        source_id=n1,
        target_id=n4,
        paths=[p1, p2],
        max_hops=6,
        max_paths=100,
        paths_found=2
    )

    path_risks = {
        generate_canonical_path_id(p1): 0.9,
        generate_canonical_path_id(p2): 0.8
    }

    result = PathOverlapAnalyzer.analyze(pr, path_risks, top_k=1)

    # Edge e2 is shared
    assert result.unweighted_edge_participation[e2] == 2
    assert result.unweighted_edge_participation[e1] == 1

    assert result.risk_weighted_edge_participation[e2] == pytest.approx(1.7) # 0.9 + 0.8
    assert result.risk_weighted_edge_participation[e1] == 0.9

    # Node choke points (n4 is target, n1 is source -> excluded)
    assert result.node_choke_points.get(n2) == 1
    assert result.node_choke_points.get(n3) == 1
    assert n4 not in result.node_choke_points

    # Jaccard
    # Top-K = 1, so it only compares p1 against p2
    # p1 edges = {e1, e2}, p2 edges = {e3, e2}
    # intersection = {e2} (len 1)
    # union = {e1, e2, e3} (len 3)
    # overlap = 1/3
    assert len(result.top_k_jaccard_overlap) == 1
    assert result.top_k_jaccard_overlap[0]["overlap"] == 1/3

