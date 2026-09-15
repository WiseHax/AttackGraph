"""Unit tests for domain model construction.

Tests basic model instantiation, field defaults, and enum assignments
using SQLite for speed.
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.domain.models import (
    AuditLog,
    Entity,
    Evidence,
    Finding,
    Relationship,
    RelationshipEvidence,
)
from app.domain.enums import (
    Confidence,
    Criticality,
    EntityType,
    Exposure,
    FindingSeverity,
    RelationshipType,
    TruthTier,
)


class TestEntityModel:
    def test_instantiation(self):
        entity = Entity(
            entity_type="SERVER",
            name="test-server",
            canonical_key="server:test",
        )
        assert entity.name == "test-server"
        assert entity.entity_type == "SERVER"

    def test_all_fields(self):
        now = datetime.now(timezone.utc)
        entity = Entity(
            id=uuid.uuid4(),
            entity_type="DATABASE",
            name="prod-db",
            description="Production database",
            criticality="CRITICAL",
            owner="dba",
            environment="production",
            exposure="INTERNAL",
            tags={"team": "backend"},
            canonical_key="db:prod",
            metadata_={"version": "16"},
            first_seen=now,
            last_seen=now,
        )
        assert entity.criticality == "CRITICAL"
        assert entity.exposure == "INTERNAL"
        assert entity.tags == {"team": "backend"}

    @pytest.mark.asyncio
    async def test_persist_and_read(self, db_session):
        entity = Entity(
            entity_type="SERVER",
            name="persist-test",
            canonical_key=f"server:persist-{uuid.uuid4()}",
        )
        db_session.add(entity)
        await db_session.flush()

        loaded = await db_session.get(Entity, entity.id)
        assert loaded is not None
        assert loaded.name == "persist-test"


class TestRelationshipModel:
    @pytest.mark.asyncio
    async def test_create_with_entities(self, db_session):
        src = Entity(entity_type="APPLICATION", name="api", canonical_key=f"app:api-{uuid.uuid4()}")
        tgt = Entity(entity_type="DATABASE", name="db", canonical_key=f"db:db-{uuid.uuid4()}")
        db_session.add_all([src, tgt])
        await db_session.flush()

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
        )
        db_session.add(rel)
        await db_session.flush()

        loaded = await db_session.get(Relationship, rel.id)
        assert loaded is not None
        assert loaded.truth_tier == "OBSERVED"
        assert loaded.relationship_type == "HAS_PERMISSION_ON"


class TestEvidenceModel:
    def test_instantiation(self):
        ev = Evidence(
            source="test-scanner",
            source_type="scanner",
            assertion="Test assertion",
        )
        assert ev.source == "test-scanner"

    @pytest.mark.asyncio
    async def test_persist(self, db_session):
        ev = Evidence(
            source="scanner",
            source_type="network_scanner",
            assertion="Port 443 open",
            confidence="HIGH",
            imported_at=datetime.now(timezone.utc),
        )
        db_session.add(ev)
        await db_session.flush()

        loaded = await db_session.get(Evidence, ev.id)
        assert loaded is not None
        assert loaded.assertion == "Port 443 open"


class TestAuditLogModel:
    @pytest.mark.asyncio
    async def test_create(self, db_session):
        log = AuditLog(
            action="entity.created",
            entity_type="Entity",
            entity_id=str(uuid.uuid4()),
            actor="system",
        )
        db_session.add(log)
        await db_session.flush()

        loaded = await db_session.get(AuditLog, log.id)
        assert loaded is not None
        assert loaded.action == "entity.created"


class TestEnums:
    def test_truth_tier_values(self):
        assert TruthTier.OBSERVED.value == "OBSERVED"
        assert TruthTier.INFERRED.value == "INFERRED"

    def test_truth_tier_no_analytical(self):
        """TruthTier must not contain ANALYTICAL."""
        values = [t.value for t in TruthTier]
        assert "ANALYTICAL" not in values
        assert len(values) == 2

    def test_entity_types(self):
        assert len(EntityType) == 18

    def test_relationship_types(self):
        assert len(RelationshipType) == 11

    def test_finding_severity(self):
        assert FindingSeverity.CRITICAL.value == "CRITICAL"
