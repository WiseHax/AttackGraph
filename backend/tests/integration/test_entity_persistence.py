"""PostgreSQL integration tests for Entity persistence.

Tests entity CRUD, unique constraints, enum persistence,
and NOT NULL enforcement against real PostgreSQL.
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.domain.models import Entity
from app.storage.repositories import EntityRepository
from tests.integration.conftest import make_pg_entity_kwargs

pytestmark = pytest.mark.integration


class TestEntityPersistence:
    @pytest.mark.asyncio
    async def test_create_and_read(self, pg_session):
        repo = EntityRepository(pg_session)
        entity = Entity(**make_pg_entity_kwargs(name="integration-server"))
        created = await repo.create(entity)

        loaded = await repo.get_by_id(created.id)
        assert loaded is not None
        assert loaded.name == "integration-server"
        assert loaded.entity_type == "SERVER"
        assert loaded.criticality == "MEDIUM"
        assert loaded.exposure == "INTERNAL"

    @pytest.mark.asyncio
    async def test_update_fields(self, pg_session):
        repo = EntityRepository(pg_session)
        entity = Entity(**make_pg_entity_kwargs())
        created = await repo.create(entity)

        created.name = "updated-name"
        created.criticality = "CRITICAL"
        await repo.update(created)

        loaded = await repo.get_by_id(created.id)
        assert loaded.name == "updated-name"
        assert loaded.criticality == "CRITICAL"

    @pytest.mark.asyncio
    async def test_delete(self, pg_session):
        repo = EntityRepository(pg_session)
        entity = Entity(**make_pg_entity_kwargs())
        created = await repo.create(entity)

        await repo.delete(created.id)
        loaded = await repo.get_by_id(created.id)
        assert loaded is None

    @pytest.mark.asyncio
    async def test_duplicate_canonical_key_rejected(self, pg_session):
        """PostgreSQL UNIQUE constraint on canonical_key must reject duplicates."""
        repo = EntityRepository(pg_session)
        key = f"server:duplicate-{uuid.uuid4()}"

        await repo.create(Entity(**make_pg_entity_kwargs(canonical_key=key)))

        with pytest.raises(IntegrityError):
            await repo.create(Entity(**make_pg_entity_kwargs(canonical_key=key)))

    @pytest.mark.asyncio
    async def test_null_name_rejected(self, pg_session):
        """NOT NULL constraint on name must reject null values."""
        repo = EntityRepository(pg_session)
        entity = Entity(
            entity_type="SERVER",
            name=None,
            canonical_key=f"server:null-name-{uuid.uuid4()}",
        )
        with pytest.raises(IntegrityError):
            await repo.create(entity)

    @pytest.mark.asyncio
    async def test_null_canonical_key_rejected(self, pg_session):
        """NOT NULL constraint on canonical_key."""
        entity = Entity(
            entity_type="SERVER",
            name="test",
            canonical_key=None,
        )
        pg_session.add(entity)
        with pytest.raises(IntegrityError):
            await pg_session.flush()

    @pytest.mark.asyncio
    async def test_entity_type_enum_persistence(self, pg_session):
        """All EntityType enum values must persist correctly."""
        repo = EntityRepository(pg_session)

        for etype in ["INTERNET", "HOST", "DATABASE", "USER", "SERVICE_ACCOUNT", "API"]:
            entity = Entity(**make_pg_entity_kwargs(
                entity_type=etype,
                canonical_key=f"{etype.lower()}:enum-test-{uuid.uuid4()}",
            ))
            created = await repo.create(entity)
            loaded = await repo.get_by_id(created.id)
            assert loaded.entity_type == etype

    @pytest.mark.asyncio
    async def test_criticality_enum_persistence(self, pg_session):
        """All criticality values must persist correctly."""
        repo = EntityRepository(pg_session)

        for crit in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            entity = Entity(**make_pg_entity_kwargs(
                criticality=crit,
                canonical_key=f"server:crit-{crit}-{uuid.uuid4()}",
            ))
            created = await repo.create(entity)
            loaded = await repo.get_by_id(created.id)
            assert loaded.criticality == crit

    @pytest.mark.asyncio
    async def test_exposure_enum_persistence(self, pg_session):
        """All exposure values must persist correctly."""
        repo = EntityRepository(pg_session)

        for exp in ["EXTERNAL", "INTERNAL", "RESTRICTED", "ISOLATED"]:
            entity = Entity(**make_pg_entity_kwargs(
                exposure=exp,
                canonical_key=f"server:exp-{exp}-{uuid.uuid4()}",
            ))
            created = await repo.create(entity)
            loaded = await repo.get_by_id(created.id)
            assert loaded.exposure == exp

    @pytest.mark.asyncio
    async def test_metadata_json_persistence(self, pg_session):
        """JSON metadata must round-trip correctly in PostgreSQL."""
        repo = EntityRepository(pg_session)
        metadata = {"os": "linux", "version": "22.04", "ports": [22, 80, 443]}
        entity = Entity(**make_pg_entity_kwargs(
            metadata_=metadata,
            canonical_key=f"server:meta-{uuid.uuid4()}",
        ))
        created = await repo.create(entity)

        loaded = await repo.get_by_id(created.id)
        assert loaded.metadata_ == metadata

    @pytest.mark.asyncio
    async def test_tags_json_persistence(self, pg_session):
        """JSON tags must round-trip correctly in PostgreSQL."""
        repo = EntityRepository(pg_session)
        tags = {"env": "production", "team": "platform"}
        entity = Entity(**make_pg_entity_kwargs(
            tags=tags,
            canonical_key=f"server:tags-{uuid.uuid4()}",
        ))
        created = await repo.create(entity)

        loaded = await repo.get_by_id(created.id)
        assert loaded.tags == tags

    @pytest.mark.asyncio
    async def test_timestamps(self, pg_session):
        """created_at and updated_at should be set."""
        repo = EntityRepository(pg_session)
        entity = Entity(**make_pg_entity_kwargs())
        created = await repo.create(entity)

        loaded = await repo.get_by_id(created.id)
        assert loaded.created_at is not None
        assert loaded.updated_at is not None
