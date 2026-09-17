import uuid

import pytest

from app.graph.networkx import NetworkXStore

from app.graph.pathfinder import TraversalEngine

from app.schemas.analytics import TraversalPolicy



def build_test_graph():

    store = NetworkXStore()

    a, b, c, d = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    # A -> B -> C -> D

    # A -> C

    store.add_entity(a, "HOST", "A")

    store.add_entity(b, "HOST", "B")

    store.add_entity(c, "HOST", "C")

    store.add_entity(d, "HOST", "D")



    store.add_relationship(uuid.uuid4(), a, b, "EXPOSES", "OBSERVED")

    store.add_relationship(uuid.uuid4(), b, c, "EXPOSES", "OBSERVED")

    store.add_relationship(uuid.uuid4(), c, d, "EXPOSES", "OBSERVED")

    store.add_relationship(uuid.uuid4(), a, c, "ROUTES_TO", "OBSERVED")



    return store, a, d



def test_saturation_exhausted():

    store, source, target = build_test_graph()

    engine = TraversalEngine(store)



    # 2 possible paths from A to D: A->B->C->D, A->C->D

    # Set max_paths to 10

    result = engine.find_paths(source, target, max_paths=10)



    assert len(result.paths) == 2

    assert result.is_saturated is False

    assert result.termination_reason == "EXHAUSTED"



def test_saturation_max_paths_reached():

    store, source, target = build_test_graph()

    engine = TraversalEngine(store)



    # Set max_paths to 1

    result = engine.find_paths(source, target, max_paths=1)



    assert len(result.paths) == 1

    assert result.is_saturated is True

    assert result.termination_reason == "MAX_PATHS_REACHED"



def test_saturation_max_hops_distinct():

    store, source, target = build_test_graph()

    engine = TraversalEngine(store)



    # Set max_hops to 2. A->C->D is 2 hops. A->B->C->D is 3 hops.

    # So it will only find 1 path (A->C->D).

    # Since max_paths is 10, it will exhaust.

    result = engine.find_paths(source, target, max_hops=2, max_paths=10)



    assert len(result.paths) == 1

    # is_saturated should be False because it exhausted the *bounded domain* (hops <= 2)

    assert result.is_saturated is False

    assert result.termination_reason == "EXHAUSTED"



def test_saturation_traversal_budget_distinct():

    store, source, target = build_test_graph()

    engine = TraversalEngine(store)



    policy = TraversalPolicy(

        max_hops=10,

        traversal_budget=2,

        edge_costs={"EXPOSES": 1, "ROUTES_TO": 1}

    )



    # A->C->D costs 2. A->B->C->D costs 3.

    result = engine.find_paths(source, target, policy=policy, max_paths=10)



    assert len(result.paths) == 1

    assert result.is_saturated is False

    assert result.termination_reason == "EXHAUSTED"



def test_saturation_zero_hop():

    store, source, _ = build_test_graph()

    engine = TraversalEngine(store)



    result = engine.find_paths(source, source, max_paths=10)

    assert len(result.paths) == 1

    assert result.is_saturated is False

    assert result.termination_reason == "EXHAUSTED"
