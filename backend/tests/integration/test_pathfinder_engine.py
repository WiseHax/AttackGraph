"""Integration tests for end-to-end analytical pathfinding."""

import pytest

from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import TraversalEngine
from scripts.load_synthetic_data import load_synthetic_topology


@pytest.mark.asyncio
@pytest.mark.integration
async def test_end_to_end_pathfinding(pg_session):
    """Verify pathfinding works on a graph built from PostgreSQL."""
    # 1. Load synthetic data into PostgreSQL
    topology = await load_synthetic_topology(pg_session)
    entities = topology["entities"]
    rels = topology["relationships"]

    # 2. Project into GraphStore
    store = NetworkXStore()
    builder = GraphBuilder(pg_session, store)
    await builder.build()
    
    # 3. Verify Graph Immutability Initial State
    initial_nodes = store.graph.number_of_nodes()
    initial_edges = store.graph.number_of_edges()

    # 4. Run Pathfinding
    pathfinder = TraversalEngine(store)
    
    # Find path from admin -> jump_host -> app_prod -> customer_data
    source_id = entities["admin"]
    target_id = entities["customer_data"]
    
    result = pathfinder.find_paths(source_id, target_id)
    
    # Assert Result
    assert result.paths_found == 1
    assert result.max_hops == 6
    assert result.max_paths == 100
    
    path = result.paths[0]
    
    # Node sequence: admin, jump_host, app_prod, customer_data
    assert path.node_ids == [
        entities["admin"],
        entities["jump_host"],
        entities["app_prod"],
        entities["customer_data"]
    ]
    
    # Edge sequence: auth, routes, depends
    assert path.edge_ids == [
        rels["admin_auth_jump"],
        rels["jump_routes_app"],
        rels["app_depends_db"]
    ]
    
    # 5. Verify Immutability (Graph was not modified)
    assert store.graph.number_of_nodes() == initial_nodes
    assert store.graph.number_of_edges() == initial_edges
    
    # Ensure no ANALYTICAL truth tiers were injected
    for u, v, key, data in store.graph.edges(keys=True, data=True):
        assert data["truth_tier"] != "ANALYTICAL"
