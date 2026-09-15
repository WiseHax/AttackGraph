import uuid
import pytest
from pydantic import ValidationError

from app.graph.networkx import NetworkXStore
from app.schemas.analytics import AttackPath, FindingRiskInput, generate_canonical_path_id
from app.analytics.counterfactual import CounterfactualEngine


@pytest.fixture
def store():
    s = NetworkXStore()
    
    # Simple diamond graph
    # A -> B -> D
    # A -> C -> D
    # B -> D (parallel edge)
    
    s.add_entity(uuid.UUID(int=1), "HOST", "A", criticality="MEDIUM", exposure="EXTERNAL")
    s.add_entity(uuid.UUID(int=2), "HOST", "B")
    s.add_entity(uuid.UUID(int=3), "HOST", "C")
    s.add_entity(uuid.UUID(int=4), "HOST", "D", criticality="HIGH")
    
    s.add_relationship(uuid.UUID(int=101), uuid.UUID(int=1), uuid.UUID(int=2), "COMMUNICATES_WITH", "OBSERVED")
    s.add_relationship(uuid.UUID(int=102), uuid.UUID(int=1), uuid.UUID(int=3), "COMMUNICATES_WITH", "OBSERVED")
    s.add_relationship(uuid.UUID(int=103), uuid.UUID(int=2), uuid.UUID(int=4), "EXPOSES", "OBSERVED")
    s.add_relationship(uuid.UUID(int=104), uuid.UUID(int=3), uuid.UUID(int=4), "RUNS_AS", "OBSERVED")
    # Parallel edge
    s.add_relationship(uuid.UUID(int=105), uuid.UUID(int=2), uuid.UUID(int=4), "CAN_AUTHENTICATE_TO", "INFERRED")
    
    # Analytical edge (invalid for removal)
    s.graph.add_edge(uuid.UUID(int=1), uuid.UUID(int=4), key=uuid.UUID(int=999), relationship_type="ROUTES_TO", truth_tier="ANALYTICAL")
    
    return s


def test_generate_canonical_path_id():
    """Cross-process stable path ID (SHA-256 behavior)."""
    n_ids = [uuid.UUID(int=1), uuid.UUID(int=2)]
    e_ids = [uuid.UUID(int=101)]
    p = AttackPath(node_ids=n_ids, edge_ids=e_ids)
    
    pid = generate_canonical_path_id(p)
    assert len(pid) == 64  # SHA-256 hex digest length
    
    # Same data must produce same hash
    p2 = AttackPath(node_ids=n_ids, edge_ids=e_ids)
    assert generate_canonical_path_id(p2) == pid
    
    # Different data must produce different hash
    p3 = AttackPath(node_ids=n_ids, edge_ids=[uuid.UUID(int=102)])
    assert generate_canonical_path_id(p3) != pid


def test_invalid_relationship_candidate(store):
    """Invalid relationship candidate rejection."""
    engine = CounterfactualEngine(store, {})
    with pytest.raises(ValueError, match="not found"):
        engine.evaluate_candidates(
            uuid.UUID(int=1), uuid.UUID(int=4),
            [uuid.UUID(int=555)]
        )


def test_analytical_candidate_rejection(store):
    """ANALYTICAL candidate rejection."""
    engine = CounterfactualEngine(store, {})
    with pytest.raises(ValueError, match="ANALYTICAL"):
        engine.evaluate_candidates(
            uuid.UUID(int=1), uuid.UUID(int=4),
            [uuid.UUID(int=999)]
        )


def test_counterfactual_engine_ranking(store):
    """Counterfactual path-set subset invariant and parallel edge preservation."""
    engine = CounterfactualEngine(store, {})
    
    # Candidates:
    # 101: breaks path through B
    # 104: breaks path through C
    # 103: breaks one of the parallel edges B->D
    ranking = engine.evaluate_candidates(
        uuid.UUID(int=1), uuid.UUID(int=4),
        [uuid.UUID(int=101), uuid.UUID(int=104), uuid.UUID(int=103)]
    )
    
    # 4 paths total because the ANALYTICAL edge (999) creates a 1->4 path.
    assert ranking.baseline_path_count == 4
    assert len(ranking.candidates) == 3
    
    # 101 removes A->B, which destroys both B->D paths. So it removes 2 paths.
    c_101 = next(c for c in ranking.candidates if c.target_relationship_id == uuid.UUID(int=101))
    assert c_101.baseline_path_count == 4
    assert c_101.counterfactual_path_count == 2
    assert len(c_101.removed_path_ids) == 2
    assert len(c_101.remaining_path_ids) == 2
    assert c_101.risk_reduction > 0.0
    
    # Subset invariant: removed + remaining == baseline
    assert len(c_101.removed_path_ids) + len(c_101.remaining_path_ids) == c_101.baseline_path_count
    
    # 103 removes one parallel edge, leaving the other.
    c_103 = next(c for c in ranking.candidates if c.target_relationship_id == uuid.UUID(int=103))
    assert c_103.counterfactual_path_count == 3
    assert len(c_103.removed_path_ids) == 1
    assert len(c_103.remaining_path_ids) == 3
    assert c_103.risk_reduction > 0.0
    
    # Monotonicity check
    assert ranking.candidates[0].risk_reduction >= ranking.candidates[1].risk_reduction
    assert ranking.candidates[1].risk_reduction >= ranking.candidates[2].risk_reduction
    
    # Assert ranking is sorted
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


def test_zero_hop_preservation(store):
    """Zero-hop paths cannot be broken."""
    engine = CounterfactualEngine(store, {})
    
    # Source == Target (A -> A)
    ranking = engine.evaluate_candidates(
        uuid.UUID(int=1), uuid.UUID(int=1),
        [uuid.UUID(int=101)]
    )
    
    assert ranking.baseline_path_count == 1
    assert ranking.baseline_environment_risk > 0.0
    
    c = ranking.candidates[0]
    assert c.counterfactual_path_count == 1
    assert c.risk_reduction == 0.0
    assert len(c.removed_path_ids) == 0
    assert len(c.remaining_path_ids) == 1
