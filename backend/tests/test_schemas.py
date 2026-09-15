"""Unit tests for Pydantic schemas.

These tests validate schema-level enforcement without a database.
"""

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.entities import EntityCreate, EntityUpdate, EntityResponse
from app.schemas.relationships import RelationshipCreate, RelationshipResponse
from app.schemas.evidence import EvidenceCreate
from app.schemas.findings import FindingCreate
from app.schemas.audit import AuditLogCreate


# ---------------------------------------------------------------------------
# Entity schemas
# ---------------------------------------------------------------------------

class TestEntityCreate:
    def test_valid_entity(self):
        entity = EntityCreate(
            entity_type="SERVER",
            name="web-server-01",
            canonical_key="server:web-server-01",
        )
        assert entity.entity_type.value == "SERVER"
        assert entity.name == "web-server-01"

    def test_valid_entity_all_fields(self):
        entity = EntityCreate(
            entity_type="DATABASE",
            name="prod-db",
            description="Production database",
            criticality="CRITICAL",
            owner="dba-team",
            environment="production",
            exposure="INTERNAL",
            tags={"team": "backend"},
            canonical_key="db:prod-db",
            metadata={"version": "16"},
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        assert entity.criticality.value == "CRITICAL"
        assert entity.exposure.value == "INTERNAL"

    def test_invalid_entity_type_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            EntityCreate(
                entity_type="TOASTER",
                name="bad-type",
                canonical_key="toaster:1",
            )
        assert "entity_type" in str(exc_info.value)

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            EntityCreate(
                entity_type="SERVER",
                name="",
                canonical_key="server:empty",
            )

    def test_name_too_long_rejected(self):
        with pytest.raises(ValidationError):
            EntityCreate(
                entity_type="SERVER",
                name="x" * 513,
                canonical_key="server:long",
            )

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            EntityCreate(name="no-type")

    def test_extra_fields_rejected(self):
        with pytest.raises(ValidationError):
            EntityCreate(
                entity_type="SERVER",
                name="test",
                canonical_key="server:test",
                hacker_mode=True,
            )

    def test_invalid_criticality_rejected(self):
        with pytest.raises(ValidationError):
            EntityCreate(
                entity_type="SERVER",
                name="test",
                canonical_key="server:test",
                criticality="ULTRA_CRITICAL",
            )

    def test_invalid_exposure_rejected(self):
        with pytest.raises(ValidationError):
            EntityCreate(
                entity_type="SERVER",
                name="test",
                canonical_key="server:test",
                exposure="WIDE_OPEN",
            )


class TestEntityUpdate:
    def test_all_optional(self):
        update = EntityUpdate()
        assert update.name is None

    def test_partial_update(self):
        update = EntityUpdate(name="new-name", criticality="HIGH")
        assert update.name == "new-name"
        assert update.criticality.value == "HIGH"


# ---------------------------------------------------------------------------
# Relationship schemas
# ---------------------------------------------------------------------------

class TestRelationshipCreate:
    def test_valid_observed(self):
        rel = RelationshipCreate(
            source_entity_id=uuid.uuid4(),
            target_entity_id=uuid.uuid4(),
            relationship_type="EXPOSES",
            truth_tier="OBSERVED",
        )
        assert rel.truth_tier.value == "OBSERVED"

    def test_valid_inferred(self):
        rel = RelationshipCreate(
            source_entity_id=uuid.uuid4(),
            target_entity_id=uuid.uuid4(),
            relationship_type="ROUTES_TO",
            truth_tier="INFERRED",
        )
        assert rel.truth_tier.value == "INFERRED"

    def test_analytical_rejected(self):
        """ANALYTICAL must be rejected at the schema level."""
        with pytest.raises(ValidationError) as exc_info:
            RelationshipCreate(
                source_entity_id=uuid.uuid4(),
                target_entity_id=uuid.uuid4(),
                relationship_type="EXPOSES",
                truth_tier="ANALYTICAL",
            )
        assert "truth_tier" in str(exc_info.value)

    def test_invalid_relationship_type_rejected(self):
        with pytest.raises(ValidationError):
            RelationshipCreate(
                source_entity_id=uuid.uuid4(),
                target_entity_id=uuid.uuid4(),
                relationship_type="HACKS",
                truth_tier="OBSERVED",
            )

    def test_with_evidence_ids(self):
        eid = uuid.uuid4()
        rel = RelationshipCreate(
            source_entity_id=uuid.uuid4(),
            target_entity_id=uuid.uuid4(),
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
            evidence_ids=[eid],
        )
        assert rel.evidence_ids == [eid]

    def test_with_confidence(self):
        rel = RelationshipCreate(
            source_entity_id=uuid.uuid4(),
            target_entity_id=uuid.uuid4(),
            relationship_type="RUNS_AS",
            truth_tier="OBSERVED",
            confidence="HIGH",
        )
        assert rel.confidence.value == "HIGH"


# ---------------------------------------------------------------------------
# Evidence schemas
# ---------------------------------------------------------------------------

class TestEvidenceCreate:
    def test_valid_evidence(self):
        ev = EvidenceCreate(
            source="nmap-scan",
            source_type="network_scanner",
            assertion="Port 443 open on 10.0.0.1",
        )
        assert ev.source == "nmap-scan"

    def test_empty_source_rejected(self):
        with pytest.raises(ValidationError):
            EvidenceCreate(
                source="",
                source_type="scanner",
                assertion="test",
            )

    def test_negative_ttl_rejected(self):
        with pytest.raises(ValidationError):
            EvidenceCreate(
                source="test",
                source_type="test",
                assertion="test",
                freshness_ttl_seconds=-1,
            )


# ---------------------------------------------------------------------------
# Finding schemas
# ---------------------------------------------------------------------------

class TestFindingCreate:
    def test_valid_finding(self):
        finding = FindingCreate(
            entity_id=uuid.uuid4(),
            title="CVE-2024-1234",
            severity="CRITICAL",
            source="vulnerability-scanner",
        )
        assert finding.severity.value == "CRITICAL"

    def test_missing_title_rejected(self):
        with pytest.raises(ValidationError):
            FindingCreate(
                entity_id=uuid.uuid4(),
                severity="HIGH",
                source="scanner",
            )


# ---------------------------------------------------------------------------
# AuditLog schemas
# ---------------------------------------------------------------------------

class TestAuditLogCreate:
    def test_valid_audit_log(self):
        log = AuditLogCreate(
            action="entity.created",
            entity_type="Entity",
            entity_id=str(uuid.uuid4()),
            actor="system",
        )
        assert log.action == "entity.created"

    def test_empty_action_rejected(self):
        with pytest.raises(ValidationError):
            AuditLogCreate(action="")
