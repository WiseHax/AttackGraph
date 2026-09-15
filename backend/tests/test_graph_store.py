"""Unit tests for GraphStore and NetworkXStore implementation."""

import uuid

import pytest

from app.graph.networkx import NetworkXStore


@pytest.fixture
def store():
    return NetworkXStore()


def test_add_and_get_entity(store):
    entity_id = uuid.uuid4()
    store.add_entity(
        entity_id,
        entity_type="SERVER",
        name="test-server",
        criticality="HIGH",
    )

    data = store.get_entity(entity_id)
    assert data is not None
    assert data["entity_type"] == "SERVER"
    assert data["name"] == "test-server"
    assert data["criticality"] == "HIGH"


def test_get_missing_entity(store):
    assert store.get_entity(uuid.uuid4()) is None


def test_add_and_get_relationship(store):
    source_id = uuid.uuid4()
    target_id = uuid.uuid4()
    rel_id = uuid.uuid4()

    store.add_relationship(
        relationship_id=rel_id,
        source_id=source_id,
        target_id=target_id,
        relationship_type="EXPOSES",
        truth_tier="OBSERVED",
        confidence="HIGH",
    )

    data = store.get_relationship(rel_id)
    assert data is not None
    assert data["relationship_type"] == "EXPOSES"
    assert data["truth_tier"] == "OBSERVED"
    assert data["confidence"] == "HIGH"


def test_get_missing_relationship(store):
    assert store.get_relationship(uuid.uuid4()) is None


def test_analytical_truth_tier_rejected(store):
    with pytest.raises(ValueError, match="ANALYTICAL truth tier cannot be persisted"):
        store.add_relationship(
            relationship_id=uuid.uuid4(),
            source_id=uuid.uuid4(),
            target_id=uuid.uuid4(),
            relationship_type="EXPOSES",
            truth_tier="ANALYTICAL",
        )


def test_multiple_edges_between_same_nodes(store):
    source_id = uuid.uuid4()
    target_id = uuid.uuid4()
    
    rel1_id = uuid.uuid4()
    rel2_id = uuid.uuid4()

    # Same nodes, same type, different relationships
    store.add_relationship(
        relationship_id=rel1_id,
        source_id=source_id,
        target_id=target_id,
        relationship_type="EXPOSES",
        truth_tier="OBSERVED",
        port=80,
    )
    store.add_relationship(
        relationship_id=rel2_id,
        source_id=source_id,
        target_id=target_id,
        relationship_type="EXPOSES",
        truth_tier="INFERRED",
        port=443,
    )

    # MultiDiGraph should preserve both
    edge1 = store.get_relationship(rel1_id)
    edge2 = store.get_relationship(rel2_id)

    assert edge1 is not None and edge1["port"] == 80
    assert edge2 is not None and edge2["port"] == 443


def test_get_neighbors(store):
    source_id = uuid.uuid4()
    target_id_1 = uuid.uuid4()
    target_id_2 = uuid.uuid4()

    store.add_relationship(
        relationship_id=uuid.uuid4(),
        source_id=source_id,
        target_id=target_id_1,
        relationship_type="ROUTES_TO",
        truth_tier="OBSERVED",
    )
    store.add_relationship(
        relationship_id=uuid.uuid4(),
        source_id=source_id,
        target_id=target_id_2,
        relationship_type="EXPOSES",
        truth_tier="OBSERVED",
    )

    neighbors = store.get_neighbors(source_id)
    assert len(neighbors) == 2
    assert target_id_1 in neighbors
    assert target_id_2 in neighbors


def test_clear_graph(store):
    entity_id = uuid.uuid4()
    store.add_entity(entity_id, "SERVER", "test")
    store.add_relationship(
        uuid.uuid4(), entity_id, uuid.uuid4(), "ROUTES_TO", "OBSERVED"
    )

    assert store.get_entity(entity_id) is not None
    
    store.clear()
    
    assert store.get_entity(entity_id) is None
