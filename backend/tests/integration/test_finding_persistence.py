"""PostgreSQL integration tests for Finding persistence.

Tests finding CRUD, FK constraints, severity enum persistence,
and evidence linking against real PostgreSQL.
"""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.domain.models import Entity, Evidence, Finding
from app.storage.repositories import (
    EntityRepository,
    EvidenceRepository,
    FindingRepository,
)
from tests.integration.conftest import make_pg_entity_kwargs, make_pg_evidence_kwargs

pytestmark = pytest.mark.integration


class TestFindingPersistence:
    @pytest.mark.asyncio
    async def test_create_and_read(self, pg_session):
        entity_repo = EntityRepository(pg_session)
        finding_repo = FindingRepository(pg_session)

        entity = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"server:finding-{uuid.uuid4()}",
        )))

        finding = Finding(
            entity_id=entity.id,
            title="CVE-2024-1234",
            description="Remote code execution vulnerability",
            severity="CRITICAL",
            source="vulnerability-scanner",
            source_type="scanner",
            confidence="HIGH",
        )
        created = await finding_repo.create(finding)

        loaded = await finding_repo.get_by_id(created.id)
        assert loaded is not None
        assert loaded.title == "CVE-2024-1234"
        assert loaded.severity == "CRITICAL"
        assert loaded.confidence == "HIGH"

    @pytest.mark.asyncio
    async def test_fk_nonexistent_entity_rejected(self, pg_session):
        """FK constraint: reject finding with nonexistent entity_id."""
        finding_repo = FindingRepository(pg_session)

        finding = Finding(
            entity_id=uuid.uuid4(),  # nonexistent
            title="Bad Finding",
            severity="LOW",
            source="scanner",
        )
        with pytest.raises(IntegrityError):
            await finding_repo.create(finding)

    @pytest.mark.asyncio
    async def test_severity_enum_persistence(self, pg_session):
        """All FindingSeverity values must persist correctly."""
        entity_repo = EntityRepository(pg_session)
        finding_repo = FindingRepository(pg_session)

        entity = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"server:sev-enum-{uuid.uuid4()}",
        )))

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            finding = Finding(
                entity_id=entity.id,
                title=f"Finding-{sev}",
                severity=sev,
                source="scanner",
            )
            created = await finding_repo.create(finding)
            loaded = await finding_repo.get_by_id(created.id)
            assert loaded.severity == sev

    @pytest.mark.asyncio
    async def test_finding_with_evidence(self, pg_session):
        entity_repo = EntityRepository(pg_session)
        ev_repo = EvidenceRepository(pg_session)
        finding_repo = FindingRepository(pg_session)

        entity = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"server:finding-ev-{uuid.uuid4()}",
        )))
        ev = await ev_repo.create(Evidence(**make_pg_evidence_kwargs()))

        finding = Finding(
            entity_id=entity.id,
            title="Finding with evidence",
            severity="HIGH",
            source="scanner",
        )
        created = await finding_repo.create(finding, evidence_ids=[ev.id])

        from sqlalchemy import select
        from app.domain.models import FindingEvidence
        stmt = select(FindingEvidence).where(FindingEvidence.finding_id == created.id)
        result = await pg_session.execute(stmt)
        links = list(result.scalars().all())
        assert len(links) == 1
        assert links[0].evidence_id == ev.id

    @pytest.mark.asyncio
    async def test_update_finding(self, pg_session):
        entity_repo = EntityRepository(pg_session)
        finding_repo = FindingRepository(pg_session)

        entity = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"server:finding-update-{uuid.uuid4()}",
        )))
        finding = Finding(
            entity_id=entity.id,
            title="Original Title",
            severity="LOW",
            source="scanner",
        )
        created = await finding_repo.create(finding)

        created.title = "Updated Title"
        created.severity = "HIGH"
        await pg_session.flush()

        loaded = await finding_repo.get_by_id(created.id)
        assert loaded.title == "Updated Title"
        assert loaded.severity == "HIGH"

    @pytest.mark.asyncio
    async def test_delete_finding(self, pg_session):
        entity_repo = EntityRepository(pg_session)
        finding_repo = FindingRepository(pg_session)

        entity = await entity_repo.create(Entity(**make_pg_entity_kwargs(
            canonical_key=f"server:finding-del-{uuid.uuid4()}",
        )))
        finding = Finding(
            entity_id=entity.id,
            title="To Delete",
            severity="INFO",
            source="scanner",
        )
        created = await finding_repo.create(finding)

        result = await finding_repo.delete(created.id)
        assert result is True

        loaded = await finding_repo.get_by_id(created.id)
        assert loaded is None
