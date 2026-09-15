"""PostgreSQL integration tests for Relationship persistence.

Tests FK constraints, TruthTier enforcement (including ANALYTICAL rejection),
enum persistence, and cascade behavior against real PostgreSQL.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, DataError, DBAPIError

from app.domain.models import (
    Entity,
    Evidence,
    Relationship,
    RelationshipEvidence,
)
from app.storage.repositories import (
    EntityRepository,
    EvidenceRepository,
    RelationshipRepository,
)
from tests.integration.conftest import make_pg_entity_kwargs, make_pg_evidence_kwargs

pytestmark = pytest.mark.integration


async def _create_entity_pair(pg_session):
    """Helper: create a source and target entity."""
    repo = EntityRepository(pg_session)
    src = await repo.create(Entity(**make_pg_entity_kwargs(
        entity_type="APPLICATION", name="src-app",
        canonical_key=f"app:src-{uuid.uuid4()}",
    )))
    tgt = await repo.create(Entity(**make_pg_entity_kwargs(
        entity_type="DATABASE", name="tgt-db",
        canonical_key=f"db:tgt-{uuid.uuid4()}",
    )))
    return src, tgt


class TestRelationshipPersistence:
    @pytest.mark.asyncio
    async def test_create_relationship(self, pg_session):
        src, tgt = await _create_entity_pair(pg_session)
        repo = RelationshipRepository(pg_session)

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
            confidence="HIGH",
        )
        created = await repo.create(rel)

        loaded = await repo.get_by_id(created.id)
        assert loaded is not None
        assert loaded.relationship_type == "HAS_PERMISSION_ON"
        assert loaded.truth_tier == "OBSERVED"
        assert loaded.confidence == "HIGH"

    @pytest.mark.asyncio
    async def test_fk_nonexistent_source_rejected(self, pg_session):
        """FK constraint: reject relationship with nonexistent source entity."""
        repo = RelationshipRepository(pg_session)
        _, tgt = await _create_entity_pair(pg_session)

        rel = Relationship(
            source_entity_id=uuid.uuid4(),  # nonexistent
            target_entity_id=tgt.id,
            relationship_type="EXPOSES",
            truth_tier="OBSERVED",
        )
        with pytest.raises(IntegrityError):
            await repo.create(rel)

    @pytest.mark.asyncio
    async def test_fk_nonexistent_target_rejected(self, pg_session):
        """FK constraint: reject relationship with nonexistent target entity."""
        repo = RelationshipRepository(pg_session)
        src, _ = await _create_entity_pair(pg_session)

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=uuid.uuid4(),  # nonexistent
            relationship_type="ROUTES_TO",
            truth_tier="OBSERVED",
        )
        with pytest.raises(IntegrityError):
            await repo.create(rel)

    @pytest.mark.asyncio
    async def test_relationship_type_enum_persistence(self, pg_session):
        """All RelationshipType values must persist correctly."""
        repo = RelationshipRepository(pg_session)

        for rtype in ["EXPOSES", "ROUTES_TO", "CAN_AUTHENTICATE_TO", "RUNS_AS",
                       "HAS_PERMISSION_ON", "MEMBER_OF", "CAN_ASSUME", "DEPENDS_ON",
                       "STORES", "TRUSTS", "COMMUNICATES_WITH"]:
            src, tgt = await _create_entity_pair(pg_session)
            rel = Relationship(
                source_entity_id=src.id,
                target_entity_id=tgt.id,
                relationship_type=rtype,
                truth_tier="OBSERVED",
            )
            created = await repo.create(rel)
            loaded = await repo.get_by_id(created.id)
            assert loaded.relationship_type == rtype


class TestTruthTierPersistence:
    @pytest.mark.asyncio
    async def test_observed_persists(self, pg_session):
        src, tgt = await _create_entity_pair(pg_session)
        repo = RelationshipRepository(pg_session)

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="EXPOSES",
            truth_tier="OBSERVED",
        )
        created = await repo.create(rel)
        loaded = await repo.get_by_id(created.id)
        assert loaded.truth_tier == "OBSERVED"

    @pytest.mark.asyncio
    async def test_inferred_persists(self, pg_session):
        src, tgt = await _create_entity_pair(pg_session)
        repo = RelationshipRepository(pg_session)

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="ROUTES_TO",
            truth_tier="INFERRED",
        )
        created = await repo.create(rel)
        loaded = await repo.get_by_id(created.id)
        assert loaded.truth_tier == "INFERRED"

    @pytest.mark.asyncio
    async def test_analytical_rejected_at_database(self, pg_session):
        """CRITICAL: ANALYTICAL must be rejected by the PostgreSQL enum constraint.

        This is the structural enforcement test. The PostgreSQL truthtier enum
        only contains OBSERVED and INFERRED. Attempting to insert ANALYTICAL
        must fail at the database level, not merely at the application level.
        """
        src, tgt = await _create_entity_pair(pg_session)

        # Bypass ORM to test raw SQL constraint
        stmt = text("""
            INSERT INTO relationships (
                id, source_entity_id, target_entity_id,
                relationship_type, truth_tier,
                created_at, updated_at
            ) VALUES (
                :id, :src, :tgt,
                'EXPOSES', 'ANALYTICAL',
                NOW(), NOW()
            )
        """)
        with pytest.raises((DataError, IntegrityError, DBAPIError)):
            await pg_session.execute(stmt, {
                "id": str(uuid.uuid4()),
                "src": str(src.id),
                "tgt": str(tgt.id),
            })


class TestRelationshipCascade:
    @pytest.mark.asyncio
    async def test_evidence_links_deleted_with_relationship(self, pg_session):
        """RelationshipEvidence should be deleted when relationship is deleted."""
        src, tgt = await _create_entity_pair(pg_session)
        ev_repo = EvidenceRepository(pg_session)
        rel_repo = RelationshipRepository(pg_session)

        ev = await ev_repo.create(Evidence(**make_pg_evidence_kwargs()))

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="EXPOSES",
            truth_tier="OBSERVED",
        )
        created = await rel_repo.create(rel, evidence_ids=[ev.id])

        # Delete relationship
        await rel_repo.delete(created.id)

        # Evidence link should be gone, but evidence itself should remain
        links = await rel_repo.get_evidence(created.id)
        assert len(links) == 0

        # Evidence itself should still exist (RESTRICT on evidence delete)
        evidence = await ev_repo.get_by_id(ev.id)
        assert evidence is not None
