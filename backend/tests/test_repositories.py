"""Unit tests for repository classes (SQLite backend).

Tests basic CRUD operations and repository behavior.
PostgreSQL-specific constraint testing is in tests/integration/.
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
)
from app.storage.repositories import (
    AuditLogRepository,
    EntityRepository,
    EvidenceRepository,
    FindingRepository,
    RelationshipRepository,
)
from tests.conftest import make_entity_kwargs, make_evidence_kwargs


class TestEntityRepository:
    @pytest.mark.asyncio
    async def test_create_and_get(self, db_session):
        repo = EntityRepository(db_session)
        entity = Entity(**make_entity_kwargs())
        created = await repo.create(entity)

        loaded = await repo.get_by_id(created.id)
        assert loaded is not None
        assert loaded.name == "test-server"

    @pytest.mark.asyncio
    async def test_get_by_canonical_key(self, db_session):
        repo = EntityRepository(db_session)
        key = f"server:unique-{uuid.uuid4()}"
        entity = Entity(**make_entity_kwargs(canonical_key=key))
        await repo.create(entity)

        found = await repo.get_by_canonical_key(key)
        assert found is not None
        assert found.canonical_key == key

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, db_session):
        repo = EntityRepository(db_session)
        result = await repo.get_by_id(uuid.uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_list_all(self, db_session):
        repo = EntityRepository(db_session)
        for i in range(3):
            await repo.create(Entity(**make_entity_kwargs(
                canonical_key=f"server:list-{i}-{uuid.uuid4()}"
            )))

        entities = await repo.list_all()
        assert len(entities) >= 3

    @pytest.mark.asyncio
    async def test_update(self, db_session):
        repo = EntityRepository(db_session)
        entity = Entity(**make_entity_kwargs())
        created = await repo.create(entity)

        created.name = "updated-name"
        await repo.update(created)

        loaded = await repo.get_by_id(created.id)
        assert loaded.name == "updated-name"

    @pytest.mark.asyncio
    async def test_delete(self, db_session):
        repo = EntityRepository(db_session)
        entity = Entity(**make_entity_kwargs())
        created = await repo.create(entity)

        result = await repo.delete(created.id)
        assert result is True

        loaded = await repo.get_by_id(created.id)
        assert loaded is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, db_session):
        repo = EntityRepository(db_session)
        result = await repo.delete(uuid.uuid4())
        assert result is False


class TestEvidenceRepository:
    @pytest.mark.asyncio
    async def test_create_and_get(self, db_session):
        repo = EvidenceRepository(db_session)
        ev = Evidence(**make_evidence_kwargs())
        created = await repo.create(ev)

        loaded = await repo.get_by_id(created.id)
        assert loaded is not None
        assert loaded.source == "test-scanner"


class TestRelationshipRepository:
    @pytest.mark.asyncio
    async def test_create_with_evidence(self, db_session):
        entity_repo = EntityRepository(db_session)
        evidence_repo = EvidenceRepository(db_session)
        rel_repo = RelationshipRepository(db_session)

        src = await entity_repo.create(Entity(**make_entity_kwargs(
            canonical_key=f"app:src-{uuid.uuid4()}", entity_type="APPLICATION", name="api"
        )))
        tgt = await entity_repo.create(Entity(**make_entity_kwargs(
            canonical_key=f"db:tgt-{uuid.uuid4()}", entity_type="DATABASE", name="db"
        )))
        ev = await evidence_repo.create(Evidence(**make_evidence_kwargs()))

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
        )
        created = await rel_repo.create(rel, evidence_ids=[ev.id])

        evidence_links = await rel_repo.get_evidence(created.id)
        assert len(evidence_links) == 1

    @pytest.mark.asyncio
    async def test_get_by_entity(self, db_session):
        entity_repo = EntityRepository(db_session)
        rel_repo = RelationshipRepository(db_session)

        src = await entity_repo.create(Entity(**make_entity_kwargs(
            canonical_key=f"app:by-entity-{uuid.uuid4()}", entity_type="APPLICATION", name="app"
        )))
        tgt = await entity_repo.create(Entity(**make_entity_kwargs(
            canonical_key=f"db:by-entity-{uuid.uuid4()}", entity_type="DATABASE", name="db"
        )))

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="DEPENDS_ON",
            truth_tier="OBSERVED",
        )
        await rel_repo.create(rel)

        found = await rel_repo.get_by_entity(src.id)
        assert len(found) >= 1


class TestFindingRepository:
    @pytest.mark.asyncio
    async def test_create_and_list_by_entity(self, db_session):
        entity_repo = EntityRepository(db_session)
        finding_repo = FindingRepository(db_session)

        entity = await entity_repo.create(Entity(**make_entity_kwargs(
            canonical_key=f"server:finding-{uuid.uuid4()}"
        )))

        finding = Finding(
            entity_id=entity.id,
            title="CVE-2024-1234",
            severity="HIGH",
            source="scanner",
        )
        await finding_repo.create(finding)

        findings = await finding_repo.list_by_entity(entity.id)
        assert len(findings) == 1
        assert findings[0].title == "CVE-2024-1234"


class TestAuditLogRepository:
    @pytest.mark.asyncio
    async def test_create(self, db_session):
        repo = AuditLogRepository(db_session)
        log = AuditLog(
            action="test.action",
            actor="test-user",
        )
        created = await repo.create(log)
        assert created.id is not None

    @pytest.mark.asyncio
    async def test_list_all(self, db_session):
        repo = AuditLogRepository(db_session)
        for i in range(3):
            await repo.create(AuditLog(action=f"test.action.{i}"))

        logs = await repo.list_all()
        assert len(logs) >= 3

    @pytest.mark.asyncio
    async def test_no_update_method(self):
        """AuditLogRepository must not expose update or delete."""
        assert not hasattr(AuditLogRepository, "update")
        assert not hasattr(AuditLogRepository, "delete")
