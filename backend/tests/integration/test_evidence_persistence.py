"""PostgreSQL integration tests for Evidence persistence.

Tests evidence CRUD, multiple evidence sources, evidence independence,
and conflicting evidence preservation against real PostgreSQL.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.domain.models import (
    Entity,
    Evidence,
    Finding,
    FindingEvidence,
    Relationship,
    RelationshipEvidence,
)
from app.storage.repositories import (
    EntityRepository,
    EvidenceRepository,
    FindingRepository,
    RelationshipRepository,
)
from tests.integration.conftest import make_pg_entity_kwargs, make_pg_evidence_kwargs

pytestmark = pytest.mark.integration


class TestEvidencePersistence:
    @pytest.mark.asyncio
    async def test_create_and_read(self, pg_session):
        repo = EvidenceRepository(pg_session)
        ev = Evidence(**make_pg_evidence_kwargs())
        created = await repo.create(ev)

        loaded = await repo.get_by_id(created.id)
        assert loaded is not None
        assert loaded.source == "pg-test-scanner"
        assert loaded.source_type == "vulnerability_scanner"
        assert loaded.assertion == "PostgreSQL test assertion"
        assert loaded.confidence == "HIGH"

    @pytest.mark.asyncio
    async def test_json_raw_reference(self, pg_session):
        repo = EvidenceRepository(pg_session)
        raw = {"scan_id": "abc-123", "findings": [1, 2, 3]}
        ev = Evidence(**make_pg_evidence_kwargs(raw_reference=raw))
        created = await repo.create(ev)

        loaded = await repo.get_by_id(created.id)
        assert loaded.raw_reference == raw


class TestMultipleEvidenceSources:
    @pytest.mark.asyncio
    async def test_multiple_evidence_on_relationship(self, pg_session):
        """Multiple independent evidence sources can be linked to one relationship."""
        entity_repo = EntityRepository(pg_session)
        ev_repo = EvidenceRepository(pg_session)
        rel_repo = RelationshipRepository(pg_session)

        src = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"app:multi-ev-src-{uuid.uuid4()}", entity_type="APPLICATION", name="api",
        )))
        tgt = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"db:multi-ev-tgt-{uuid.uuid4()}", entity_type="DATABASE", name="db",
        )))

        ev1 = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(
            source="scanner-A", assertion="Scanner A found this",
        )))
        ev2 = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(
            source="scanner-B", assertion="Scanner B also found this",
        )))

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
        )
        created = await rel_repo.create(rel, evidence_ids=[ev1.id, ev2.id])

        links = await rel_repo.get_evidence(created.id)
        assert len(links) == 2

        evidence_ids = {link.evidence_id for link in links}
        assert ev1.id in evidence_ids
        assert ev2.id in evidence_ids

    @pytest.mark.asyncio
    async def test_multiple_evidence_on_finding(self, pg_session):
        """Multiple evidence sources can be linked to one finding."""
        entity_repo = EntityRepository(pg_session)
        ev_repo = EvidenceRepository(pg_session)
        finding_repo = FindingRepository(pg_session)

        entity = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"server:finding-ev-{uuid.uuid4()}",
        )))

        ev1 = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(
            source="source-1", assertion="Finding evidence 1",
        )))
        ev2 = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(
            source="source-2", assertion="Finding evidence 2",
        )))

        finding = Finding(
            entity_id=entity.id,
            title="CVE-2024-9999",
            severity="HIGH",
            source="scanner",
        )
        created = await finding_repo.create(finding, evidence_ids=[ev1.id, ev2.id])

        # Verify via direct query
        from sqlalchemy import select
        stmt = select(FindingEvidence).where(FindingEvidence.finding_id == created.id)
        result = await pg_session.execute(stmt)
        links = list(result.scalars().all())
        assert len(links) == 2


class TestEvidenceIndependence:
    @pytest.mark.asyncio
    async def test_deleting_one_evidence_link_preserves_others(self, pg_session):
        """Deleting one evidence link does not destroy other evidence on the same relationship."""
        entity_repo = EntityRepository(pg_session)
        ev_repo = EvidenceRepository(pg_session)
        rel_repo = RelationshipRepository(pg_session)

        src = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"app:ev-indep-src-{uuid.uuid4()}", entity_type="APPLICATION", name="api",
        )))
        tgt = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"db:ev-indep-tgt-{uuid.uuid4()}", entity_type="DATABASE", name="db",
        )))

        ev1 = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(source="scanner-1")))
        ev2 = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(source="scanner-2")))

        rel = Relationship(
            source_entity_id=src.id,
            target_entity_id=tgt.id,
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
        )
        created = await rel_repo.create(rel, evidence_ids=[ev1.id, ev2.id])

        # Delete one link
        from sqlalchemy import select, delete
        stmt = select(RelationshipEvidence).where(
            RelationshipEvidence.relationship_id == created.id,
            RelationshipEvidence.evidence_id == ev1.id,
        )
        result = await pg_session.execute(stmt)
        link = result.scalar_one()
        await pg_session.delete(link)
        await pg_session.flush()

        # Other link should remain
        remaining = await rel_repo.get_evidence(created.id)
        assert len(remaining) == 1
        assert remaining[0].evidence_id == ev2.id

        # Both evidence records should still exist
        assert await ev_repo.get_by_id(ev1.id) is not None
        assert await ev_repo.get_by_id(ev2.id) is not None


class TestConflictingEvidence:
    @pytest.mark.asyncio
    async def test_conflicting_evidence_both_preserved(self, pg_session):
        """When two sources disagree, both evidence records must persist.

        Source A says: account CAN access database.
        Source B says: account CANNOT access database.

        Both observations must be preserved. Neither is silently selected.
        """
        entity_repo = EntityRepository(pg_session)
        ev_repo = EvidenceRepository(pg_session)
        rel_repo = RelationshipRepository(pg_session)

        account = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            entity_type="SERVICE_ACCOUNT", name="svc-account",
            canonical_key=f"svc:conflict-{uuid.uuid4()}",
        )))
        database = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            entity_type="DATABASE", name="prod-db",
            canonical_key=f"db:conflict-{uuid.uuid4()}",
        )))

        # Evidence A: account CAN access database
        ev_a = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(
            source="audit-system-A",
            source_type="access_audit",
            assertion="Service account has SELECT permission on production database",
            confidence="HIGH",
        )))

        # Evidence B: account CANNOT access database
        ev_b = await ev_repo.create(Evidence(**make_pg_evidence_kwargs(
            source="audit-system-B",
            source_type="access_audit",
            assertion="Service account access to production database was revoked",
            confidence="MEDIUM",
        )))

        # Both evidence records attached to the same relationship
        rel = Relationship(
            source_entity_id=account.id,
            target_entity_id=database.id,
            relationship_type="HAS_PERMISSION_ON",
            truth_tier="OBSERVED",
        )
        created = await rel_repo.create(rel, evidence_ids=[ev_a.id, ev_b.id])

        # Verify both evidence sources are preserved
        links = await rel_repo.get_evidence(created.id)
        assert len(links) == 2

        evidence_ids = {link.evidence_id for link in links}
        assert ev_a.id in evidence_ids
        assert ev_b.id in evidence_ids

        # Verify the original evidence records have their original assertions
        loaded_a = await ev_repo.get_by_id(ev_a.id)
        loaded_b = await ev_repo.get_by_id(ev_b.id)
        assert "SELECT permission" in loaded_a.assertion
        assert "revoked" in loaded_b.assertion
