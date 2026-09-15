"""Integration tests for end-to-end graph projection from PostgreSQL."""

import pytest

from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore
from scripts.load_synthetic_data import load_synthetic_topology


@pytest.mark.asyncio
@pytest.mark.integration
async def test_end_to_end_projection(pg_session):
    """Verify that PostgreSQL facts are correctly projected into NetworkX."""
    # 1. Load synthetic data into PostgreSQL
    topology = await load_synthetic_topology(pg_session)
    entities = topology["entities"]
    rels = topology["relationships"]

    # 2. Project into GraphStore
    store = NetworkXStore()
    builder = GraphBuilder(pg_session, store)
    await builder.build()

    # 3. Assert Nodes
    assert store.graph.number_of_nodes() == 6
    
    admin_node = store.get_entity(entities["admin"])
    assert admin_node is not None
    assert admin_node["entity_type"] == "USER"

    jump_node = store.get_entity(entities["jump_host"])
    assert jump_node is not None
    assert jump_node["criticality"] == "HIGH"
    
    # 4. Assert Edges
    assert store.graph.number_of_edges() == 3

    # Check jump_host -> app_prod (ROUTES_TO)
    rel_routes = store.get_relationship(rels["jump_routes_app"])
    assert rel_routes is not None
    assert rel_routes["relationship_type"] == "ROUTES_TO"
    assert rel_routes["truth_tier"] == "OBSERVED"
    assert rel_routes["confidence"] == "HIGH"
    assert len(rel_routes["evidence_ids"]) == 1

    # Check app_prod -> customer_data (DEPENDS_ON, INFERRED)
    rel_depends = store.get_relationship(rels["app_depends_db"])
    assert rel_depends is not None
    assert rel_depends["relationship_type"] == "DEPENDS_ON"
    assert rel_depends["truth_tier"] == "INFERRED"
    assert len(rel_depends["evidence_ids"]) == 0

    # 5. Verify Determinism (Rebuilding produces the exact same graph)
    await builder.build()
    assert store.graph.number_of_nodes() == 6
    assert store.graph.number_of_edges() == 3
