"""PostgreSQL integration tests for AuditLog.

Tests append-only behavior and immutability against real PostgreSQL.
"""

import uuid

import pytest

from app.domain.models import AuditLog
from app.storage.repositories import AuditLogRepository

pytestmark = pytest.mark.integration


class TestAuditLogPersistence:
    @pytest.mark.asyncio
    async def test_create_audit_entry(self, pg_session):
        repo = AuditLogRepository(pg_session)
        log = AuditLog(
            action="entity.created",
            entity_type="Entity",
            entity_id=str(uuid.uuid4()),
            actor="system",
            detail={"name": "test-server"},
        )
        created = await repo.create(log)

        assert created.id is not None
        assert created.action == "entity.created"
        assert created.timestamp is not None

    @pytest.mark.asyncio
    async def test_list_audit_entries(self, pg_session):
        repo = AuditLogRepository(pg_session)

        for i in range(5):
            await repo.create(AuditLog(
                action=f"test.action.{i}",
                actor="test-user",
            ))

        entries = await repo.list_all()
        assert len(entries) >= 5

    @pytest.mark.asyncio
    async def test_list_ordered_by_timestamp_desc(self, pg_session):
        repo = AuditLogRepository(pg_session)

        await repo.create(AuditLog(action="first"))
        await repo.create(AuditLog(action="second"))
        await repo.create(AuditLog(action="third"))

        entries = await repo.list_all()
        # Most recent should be first
        assert entries[0].action == "third"

    @pytest.mark.asyncio
    async def test_no_update_method(self):
        """AuditLogRepository must not provide update functionality."""
        assert not hasattr(AuditLogRepository, "update")

    @pytest.mark.asyncio
    async def test_no_delete_method(self):
        """AuditLogRepository must not provide delete functionality."""
        assert not hasattr(AuditLogRepository, "delete")

    @pytest.mark.asyncio
    async def test_list_by_entity(self, pg_session):
        repo = AuditLogRepository(pg_session)
        entity_id = str(uuid.uuid4())

        await repo.create(AuditLog(
            action="entity.updated",
            entity_type="Entity",
            entity_id=entity_id,
        ))
        await repo.create(AuditLog(
            action="entity.updated",
            entity_type="Entity",
            entity_id=str(uuid.uuid4()),  # different entity
        ))

        entries = await repo.list_by_entity(entity_id)
        assert len(entries) == 1
        assert entries[0].entity_id == entity_id

    @pytest.mark.asyncio
    async def test_detail_json_persistence(self, pg_session):
        repo = AuditLogRepository(pg_session)
        detail = {
            "changes": {"name": {"old": "server-1", "new": "server-2"}},
            "reason": "renamed",
        }
        log = AuditLog(
            action="entity.updated",
            detail=detail,
        )
        created = await repo.create(log)

        entries = await repo.list_all()
        found = next(e for e in entries if e.id == created.id)
        assert found.detail == detail
