"""Unit tests for the analytical pathfinding engine."""

import uuid
import pytest

from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import TraversalEngine


@pytest.fixture
def store():
    return NetworkXStore()


@pytest.fixture
def pathfinder(store):
    return TraversalEngine(store)


def test_basic_multihop_path(store, pathfinder):
    a, b, c, d = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    
    store.add_entity(a, "SERVER", "A")
    store.add_entity(b, "SERVER", "B")
    store.add_entity(c, "SERVER", "C")
    store.add_entity(d, "SERVER", "D")
    
    r1, r2, r3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    store.add_relationship(r1, a, b, "ROUTES_TO", "OBSERVED")
    store.add_relationship(r2, b, c, "ROUTES_TO", "OBSERVED")
    store.add_relationship(r3, c, d, "ROUTES_TO", "OBSERVED")
    
    result = pathfinder.find_paths(a, d)
    
    assert result.paths_found == 1
    assert result.paths[0].node_ids == [a, b, c, d]
    assert result.paths[0].edge_ids == [r1, r2, r3]


def test_directionality(store, pathfinder):
    a, b = uuid.uuid4(), uuid.uuid4()
    store.add_relationship(uuid.uuid4(), a, b, "ROUTES_TO", "OBSERVED")
    
    assert pathfinder.find_paths(a, b).paths_found == 1
    assert pathfinder.find_paths(b, a).paths_found == 0


def test_source_equals_target(store, pathfinder):
    a = uuid.uuid4()
    store.add_entity(a, "SERVER", "A")
    
    # Should return zero-hop path
    result = pathfinder.find_paths(a, a, max_hops=0)
    assert result.paths_found == 1
    assert result.paths[0].node_ids == [a]
    assert result.paths[0].edge_ids == []

    # Even with max_hops > 0, prefer zero-hop
    result = pathfinder.find_paths(a, a, max_hops=5)
    assert result.paths_found == 1


def test_invalid_and_edge_case_inputs(store, pathfinder):
    a, b = uuid.uuid4(), uuid.uuid4()
    store.add_relationship(uuid.uuid4(), a, b, "ROUTES_TO", "OBSERVED")
    
    # Negative max_hops
    with pytest.raises(ValueError, match="max_hops must be >= 0"):
        pathfinder.find_paths(a, b, max_hops=-1)
        
    # max_paths < 1
    with pytest.raises(ValueError, match="max_paths must be >= 1"):
        pathfinder.find_paths(a, b, max_paths=0)
        
    # Nonexistent source
    assert pathfinder.find_paths(uuid.uuid4(), b).paths_found == 0
    
    # Nonexistent target
    assert pathfinder.find_paths(a, uuid.uuid4()).paths_found == 0

    # allowed_types=None means all allowed
    assert pathfinder.find_paths(a, b, allowed_types=None).paths_found == 1
    
    # allowed_types=[] means none allowed
    assert pathfinder.find_paths(a, b, allowed_types=[]).paths_found == 0


def test_exact_hop_boundary(store, pathfinder):
    a, b, c, d = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    store.add_relationship(uuid.uuid4(), a, b, "ROUTES_TO", "OBSERVED")
    store.add_relationship(uuid.uuid4(), b, c, "ROUTES_TO", "OBSERVED")
    store.add_relationship(uuid.uuid4(), c, d, "ROUTES_TO", "OBSERVED")
    
    # 0 hops
    assert pathfinder.find_paths(a, d, max_hops=0).paths_found == 0
    # 1 hop
    assert pathfinder.find_paths(a, d, max_hops=1).paths_found == 0
    # 2 hops
    assert pathfinder.find_paths(a, d, max_hops=2).paths_found == 0
    # 3 hops (exact boundary)
    assert pathfinder.find_paths(a, d, max_hops=3).paths_found == 1
    # 4 hops (one over boundary)
    assert pathfinder.find_paths(a, d, max_hops=4).paths_found == 1


def test_max_paths_enforcement(store, pathfinder):
    a, b = uuid.uuid4(), uuid.uuid4()
    
    # Create 5 distinct relationships between A and B
    for _ in range(5):
        store.add_relationship(uuid.uuid4(), a, b, "ROUTES_TO", "OBSERVED")
        
    # Should find all 5 normally
    assert pathfinder.find_paths(a, b).paths_found == 5
    
    # With max_paths=2, should stop at 2
    result = pathfinder.find_paths(a, b, max_paths=2)
    assert result.paths_found == 2
    assert len(result.paths) == 2


def test_relationship_type_filtering(store, pathfinder):
    a, b = uuid.uuid4(), uuid.uuid4()
    
    r1 = uuid.uuid4()
    r2 = uuid.uuid4()
    store.add_relationship(r1, a, b, "EXPOSES", "OBSERVED")
    store.add_relationship(r2, a, b, "ROUTES_TO", "OBSERVED")
    
    # Allowed both
    assert pathfinder.find_paths(a, b).paths_found == 2
    
    # Only ROUTES_TO
    res = pathfinder.find_paths(a, b, allowed_types=["ROUTES_TO"])
    assert res.paths_found == 1
    assert res.paths[0].edge_ids == [r2]


def test_cycle_handling(store, pathfinder):
    a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    
    # A -> B -> C -> A
    store.add_relationship(uuid.uuid4(), a, b, "ROUTES_TO", "OBSERVED")
    store.add_relationship(uuid.uuid4(), b, c, "ROUTES_TO", "OBSERVED")
    store.add_relationship(uuid.uuid4(), c, a, "ROUTES_TO", "OBSERVED")
    
    # Search from A to C
    # It will go A->B->C (target found). It will not loop infinitely.
    result = pathfinder.find_paths(a, c)
    assert result.paths_found == 1


def test_parallel_edge_preservation_and_determinism(store, pathfinder):
    a, b = uuid.uuid4(), uuid.uuid4()
    
    r1 = uuid.uuid4()
    r2 = uuid.uuid4()
    
    # Same source, same target, same type, different ID
    # To test determinism, we can control the UUIDs or just assert sorted order
    # Let's ensure r1 and r2 are ordered predictably by sorting their UUID strings
    if str(r1) > str(r2):
        r1, r2 = r2, r1  # Ensure r1 < r2 in string representation
        
    store.add_relationship(r2, a, b, "ROUTES_TO", "OBSERVED")
    store.add_relationship(r1, a, b, "ROUTES_TO", "OBSERVED")
    
    result = pathfinder.find_paths(a, b)
    assert result.paths_found == 2
    
    # The edges should be traversed in deterministic order.
    # Our Pathfinder sorts by relationship_type, target_id, relationship_id.
    # So r1 should be first.
    assert result.paths[0].edge_ids == [r1]
    assert result.paths[1].edge_ids == [r2]
