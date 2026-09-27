"""Integration tests for J-1 Scope Foundation and CIB-5."""

import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Scope, ScopeDefinition, Entity, Finding, Evidence, FindingEvidence
from app.storage.repositories import ScopeRepository, ScopeDefinitionRepository
from app.schemas.analytics import AnalyticalScope
from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore


@pytest.mark.asyncio
async def test_v1_selector_validation(pg_session: AsyncSession):
    """Test that invalid v1 selector configurations are rejected by the repository."""
    repo = ScopeDefinitionRepository(pg_session)
    scope = Scope(display_name="Test Scope")
    pg_session.add(scope)
    await pg_session.flush()

    # Valid
    valid_def = ScopeDefinition(
        input_boundary_kind="UNIVERSAL",
        reporting_selector="ALL",
        selector_parameters=None,
        declared_normalization=None
    )
    saved = await repo.create(scope.id, valid_def)
    assert saved.version == 1

    # Invalid input_boundary
    with pytest.raises(ValueError, match="v1 only supports UNIVERSAL"):
        await repo.create(scope.id, ScopeDefinition(
            input_boundary_kind="NARROW",
            reporting_selector="ALL"
        ))

    # Invalid selector
    with pytest.raises(ValueError, match="v1 only supports ALL"):
        await repo.create(scope.id, ScopeDefinition(
            input_boundary_kind="UNIVERSAL",
            reporting_selector="ENVIRONMENT_EQUALS"
        ))

    # Invalid params
    with pytest.raises(ValueError, match="selector_parameters to be None"):
        await repo.create(scope.id, ScopeDefinition(
            input_boundary_kind="UNIVERSAL",
            reporting_selector="ALL",
            selector_parameters={"env": "PROD"}
        ))


@pytest.mark.asyncio
async def test_scope_immutability(pg_session: AsyncSession):
    """Test that PostgreSQL triggers enforce structural immutability."""
    repo = ScopeDefinitionRepository(pg_session)
    scope = Scope(display_name="Immutability Test Scope")
    pg_session.add(scope)
    await pg_session.flush()

    valid_def = ScopeDefinition(
        input_boundary_kind="UNIVERSAL",
        reporting_selector="ALL"
    )
    saved = await repo.create(scope.id, valid_def)
    
    # DB-level UPDATE should fail
    with pytest.raises(Exception, match="Modification of this record is strictly prohibited"):
        await pg_session.execute(
            text(f"UPDATE scope_definitions SET reporting_selector = 'OTHER' WHERE scope_id = '{scope.id}' AND version = 1")
        )
        
    await pg_session.rollback()

    # Recreate for DELETE test since rollback destroyed the previous one
    scope2 = Scope(display_name="Immutability Test Scope 2")
    pg_session.add(scope2)
    await pg_session.flush()

    valid_def2 = ScopeDefinition(
        input_boundary_kind="UNIVERSAL",
        reporting_selector="ALL"
    )
    await repo.create(scope2.id, valid_def2)

    # DB-level DELETE should fail
    with pytest.raises(Exception, match="Modification of this record is strictly prohibited"):
        await pg_session.execute(
            text(f"DELETE FROM scope_definitions WHERE scope_id = '{scope2.id}' AND version = 1")
        )
        
    await pg_session.rollback()


@pytest.mark.asyncio
async def test_scope_lifecycle(pg_session: AsyncSession):
    """Test that Scope cannot be deleted via DB."""
    scope = Scope(display_name="Lifecycle Test Scope")
    pg_session.add(scope)
    await pg_session.flush()

    with pytest.raises(Exception, match="Modification of this record is strictly prohibited"):
        await pg_session.execute(
            text(f"DELETE FROM scopes WHERE id = '{scope.id}'")
        )
        
    await pg_session.rollback()


@pytest.mark.asyncio
async def test_explicit_scope_resolution(pg_session: AsyncSession):
    """Test that GraphBuilder explicitly requires and validates AnalyticalScope."""
    store = NetworkXStore()
    builder = GraphBuilder(pg_session, store)

    # Missing argument (Python will raise TypeError natively)
    
    # Invalid boundary
    invalid_scope = AnalyticalScope(
        input_boundary_kind="UNIVERSAL", # type checkers complain if we pass "OTHER", but we can bypass for test
        reporting_selector="ALL"
    )
    # Bypass pydantic validation for test
    invalid_scope_dict = invalid_scope.model_dump()
    invalid_scope_dict["input_boundary_kind"] = "OTHER"
    
    # We must instantiate via construct to bypass validation for testing the builder
    bad_scope = AnalyticalScope.model_construct(**invalid_scope_dict)

    with pytest.raises(ValueError, match="Unsupported input boundary"):
        await builder.build(bad_scope)


@pytest.mark.asyncio
async def test_finding_evidence_non_consumption(pg_session: AsyncSession):
    """CIB-5: Test that FindingEvidence is structurally excluded from analytical pipeline."""
    from app.analytics.risk_engine import RiskEngine
    from app.schemas.analytics import RiskInput, AttackPath, FindingRiskInput

    # Setup base input
    path = AttackPath(node_ids=[uuid.uuid4(), uuid.uuid4()], edge_ids=[uuid.uuid4()])
    
    # Even if finding evidence exists in DB, the RiskInput purely takes FindingRiskInput
    finding_id = uuid.uuid4()
    base_input = RiskInput(
        path=path,
        target_criticality="HIGH",
        entry_exposure="EXTERNAL",
        edge_types=["EXPOSES"],
        edge_confidences=["HIGH"],
        edge_truth_tiers=["OBSERVED"],
        edge_sources=["TEST"],
        findings=[
            FindingRiskInput(
                finding_id=finding_id,
                entity_id=path.node_ids[-1],
                severity="CRITICAL"
            )
        ]
    )
    
    base_result = RiskEngine.calculate(base_input)

    # Inject FindingEvidence into DB
    ent = Entity(
        canonical_key="test_entity",
        name="Test Entity",
        entity_type="HOST",
        criticality="HIGH",
        exposure="INTERNAL",
        environment="TEST"
    )
    pg_session.add(ent)
    await pg_session.flush()
    finding = Finding(
        entity_id=ent.id,
        title="Test Finding",
        severity="CRITICAL",
        source="TEST"
    )
    ev = Evidence(
        source="TEST",
        source_type="TEST",
        assertion="TEST"
    )
    pg_session.add(finding)
    pg_session.add(ev)
    await pg_session.flush()
    
    fe = FindingEvidence(finding_id=finding.id, evidence_id=ev.id)
    pg_session.add(fe)
    await pg_session.flush()

    # TRIPWIRE: Ensure FindingRiskInput schema strictly has no evidence fields.
    # If a future developer adds 'evidence_ids' to FindingRiskInput to consume them,
    # these assertions will fail, failing the CIB-5 gate.
    schema_fields = FindingRiskInput.model_fields.keys()
    assert "evidence" not in schema_fields, "CIB-5 Violation: FindingRiskInput now accepts evidence."
    assert "evidence_ids" not in schema_fields, "CIB-5 Violation: FindingRiskInput now accepts evidence."
    assert "evidence_links" not in schema_fields, "CIB-5 Violation: FindingRiskInput now accepts evidence."

    # The RiskInput has no place for FindingEvidence, structurally preventing consumption.
    # We run RiskEngine again to show it is deterministic.
    second_result = RiskEngine.calculate(base_input)
    assert base_result.numeric_risk == second_result.numeric_risk
