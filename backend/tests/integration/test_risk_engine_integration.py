"""End-to-End Integration tests for the Deterministic Risk Engine."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.domain.models import Finding
from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import Pathfinder
from app.analytics.risk_engine import RiskEngine
from app.schemas.analytics import RiskInput, FindingRiskInput
from scripts.load_synthetic_data import load_synthetic_topology


@pytest.mark.asyncio
@pytest.mark.integration
async def test_postgres_risk_pipeline(pg_session):
    """Test the complete Phase 4 analytical risk pipeline."""
    
    # 1. Setup Topology
    topology = await load_synthetic_topology(pg_session)
    entities = topology["entities"]
    
    # 2. Build Graph (Phase 2)
    store = NetworkXStore()
    builder = GraphBuilder(pg_session, store)
    await builder.build()
    
    # Take snapshot for immutability check
    initial_nodes = list(store.graph.nodes(data=True))
    initial_edges = list(store.graph.edges(keys=True, data=True))
    
    # 3. Pathfinding (Phase 3)
    pathfinder = Pathfinder(store)
    source_id = entities["admin"]
    target_id = entities["customer_data"]
    
    path_result = pathfinder.find_paths(source_id, target_id)
    assert path_result.paths_found > 0
    attack_path = path_result.paths[0]
    
    # 4. Provider Layer: Fetch attributes and findings for the path
    # Fetch entity attributes from GraphStore (purely in-memory)
    target_node = store.get_entity(attack_path.node_ids[-1])
    source_node = store.get_entity(attack_path.node_ids[0])
    
    # Fetch edge attributes from GraphStore
    edge_types = []
    edge_confs = []
    edge_tiers = []
    
    for edge_id in attack_path.edge_ids:
        edge_data = store.get_relationship(edge_id)
        edge_types.append(edge_data["relationship_type"])
        edge_confs.append(edge_data.get("confidence"))
        edge_tiers.append(edge_data["truth_tier"])
        
    # Fetch findings from PostgreSQL (Application Provider Layer)
    stmt = select(Finding).where(Finding.entity_id.in_(attack_path.node_ids))
    finding_results = await pg_session.execute(stmt)
    db_findings = finding_results.scalars().all()
    
    finding_inputs = [
        FindingRiskInput(
            finding_id=f.id,
            entity_id=f.entity_id,
            severity=f.severity
        ) for f in db_findings
    ]
    
    # 5. Build Pure Analytical Context
    risk_input = RiskInput(
        path=attack_path,
        target_criticality=target_node.get("criticality"),
        entry_exposure=source_node.get("exposure"),
        edge_types=edge_types,
        edge_confidences=edge_confs,
        edge_truth_tiers=edge_tiers,
        findings=finding_inputs
    )
    
    # 6. Execute Pure Mathematical Engine (Phase 4)
    risk_result = RiskEngine.calculate(risk_input)
    
    # Assert output structure and explainability
    assert risk_result.formula_version == "risk-v1"
    assert 0.0 <= risk_result.numeric_risk <= 1.0
    assert risk_result.category in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    # The synthetic data has a HIGH finding on the web_server (jump_host)
    # Ensure finding amplification was applied
    assert len(risk_result.finding_ids) > 0
    assert risk_result.finding_amplifier.value > 0.0
    
    # 7. Assert Graph and Database Immutability
    final_nodes = list(store.graph.nodes(data=True))
    final_edges = list(store.graph.edges(keys=True, data=True))
    
    assert initial_nodes == final_nodes
    assert initial_edges == final_edges
