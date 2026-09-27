"""Repository classes for domain model persistence.

Repositories encapsulate CRUD operations and enforce domain invariants
at the persistence boundary. Domain logic stays out of repositories.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import (
    AuditLog,
    Entity,
    Evidence,
    Finding,
    FindingEvidence,
    Relationship,
    RelationshipEvidence,
    Scope,
    ScopeDefinition,
)


class EntityRepository:
    """CRUD operations for Entity."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, entity: Entity) -> Entity:
        self.session.add(entity)
        await self.session.flush()
        return entity

    async def get_by_id(self, entity_id: uuid.UUID) -> Entity | None:
        return await self.session.get(Entity, entity_id)

    async def get_by_canonical_key(self, canonical_key: str) -> Entity | None:
        stmt = select(Entity).where(Entity.canonical_key == canonical_key)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[Entity]:
        stmt = select(Entity).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, entity: Entity) -> Entity:
        entity.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        return entity

    async def delete(self, entity_id: uuid.UUID) -> bool:
        entity = await self.get_by_id(entity_id)
        if entity is None:
            return False
        await self.session.delete(entity)
        await self.session.flush()
        return True


class EvidenceRepository:
    """CRUD operations for Evidence."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence: Evidence) -> Evidence:
        self.session.add(evidence)
        await self.session.flush()
        return evidence

    async def get_by_id(self, evidence_id: uuid.UUID) -> Evidence | None:
        return await self.session.get(Evidence, evidence_id)

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[Evidence]:
        stmt = select(Evidence).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class RelationshipRepository:
    """CRUD operations for Relationship with evidence linking."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        relationship: Relationship,
        evidence_ids: list[uuid.UUID] | None = None,
    ) -> Relationship:
        self.session.add(relationship)
        await self.session.flush()

        if evidence_ids:
            for eid in evidence_ids:
                link = RelationshipEvidence(
                    relationship_id=relationship.id,
                    evidence_id=eid,
                )
                self.session.add(link)
            await self.session.flush()

        return relationship

    async def get_by_id(self, relationship_id: uuid.UUID) -> Relationship | None:
        return await self.session.get(Relationship, relationship_id)

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[Relationship]:
        stmt = select(Relationship).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_entity(
        self, entity_id: uuid.UUID
    ) -> list[Relationship]:
        """Get all relationships where entity is source or target."""
        stmt = select(Relationship).where(
            (Relationship.source_entity_id == entity_id)
            | (Relationship.target_entity_id == entity_id)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete(self, relationship_id: uuid.UUID) -> bool:
        rel = await self.get_by_id(relationship_id)
        if rel is None:
            return False
        await self.session.delete(rel)
        await self.session.flush()
        return True

    async def add_evidence(
        self, relationship_id: uuid.UUID, evidence_id: uuid.UUID
    ) -> RelationshipEvidence:
        link = RelationshipEvidence(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
        )
        self.session.add(link)
        await self.session.flush()
        return link

    async def get_evidence(
        self, relationship_id: uuid.UUID
    ) -> list[RelationshipEvidence]:
        stmt = select(RelationshipEvidence).where(
            RelationshipEvidence.relationship_id == relationship_id
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class FindingRepository:
    """CRUD operations for Finding with evidence linking."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        finding: Finding,
        evidence_ids: list[uuid.UUID] | None = None,
    ) -> Finding:
        self.session.add(finding)
        await self.session.flush()

        if evidence_ids:
            for eid in evidence_ids:
                link = FindingEvidence(
                    finding_id=finding.id,
                    evidence_id=eid,
                )
                self.session.add(link)
            await self.session.flush()

        return finding

    async def get_by_id(self, finding_id: uuid.UUID) -> Finding | None:
        return await self.session.get(Finding, finding_id)

    async def list_by_entity(
        self, entity_id: uuid.UUID
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.entity_id == entity_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete(self, finding_id: uuid.UUID) -> bool:
        finding = await self.get_by_id(finding_id)
        if finding is None:
            return False
        await self.session.delete(finding)
        await self.session.flush()
        return True


class AuditLogRepository:
    """Append-only repository for AuditLog.

    This repository deliberately does NOT provide update or delete methods.
    Audit log entries are immutable once created.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, audit_log: AuditLog) -> AuditLog:
        self.session.add(audit_log)
        await self.session.flush()
        return audit_log

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[AuditLog]:
        stmt = (
            select(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_by_entity(
        self, entity_id: str
    ) -> list[AuditLog]:
        stmt = (
            select(AuditLog)
            .where(AuditLog.entity_id == entity_id)
            .order_by(AuditLog.timestamp.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class ScopeRepository:
    """CRUD operations for Scope.

    Deliberately omits a delete method to enforce the lifecycle invariant:
    Scopes cannot be deleted (protects snapshot references).
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, scope: Scope) -> Scope:
        self.session.add(scope)
        await self.session.flush()
        return scope

    async def get_by_id(self, scope_id: uuid.UUID) -> Scope | None:
        return await self.session.get(Scope, scope_id)

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[Scope]:
        stmt = select(Scope).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class ScopeDefinitionRepository:
    """CRUD operations for ScopeDefinition.

    Deliberately omits update and delete methods to enforce append-only immutability.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, scope_id: uuid.UUID, definition: ScopeDefinition) -> ScopeDefinition:
        """Create a new ScopeDefinition version.

        Uses SELECT FOR UPDATE on the parent Scope to ensure deterministic,
        concurrency-safe version allocation.
        """
        # Lock the scope row to prevent concurrent version increments
        stmt = select(Scope.id).where(Scope.id == scope_id).with_for_update()
        result = await self.session.execute(stmt)
        if not result.scalar_one_or_none():
            raise ValueError(f"Scope {scope_id} does not exist.")

        # Determine the next version
        version_stmt = select(ScopeDefinition.version).where(
            ScopeDefinition.scope_id == scope_id
        ).order_by(ScopeDefinition.version.desc()).limit(1)

        last_version_result = await self.session.execute(version_stmt)
        last_version = last_version_result.scalar_one_or_none()

        next_version = (last_version or 0) + 1

        # Enforce application-level schema validation for v1
        if definition.input_boundary_kind != 'UNIVERSAL':
            raise ValueError("v1 only supports UNIVERSAL input_boundary_kind")
        if definition.reporting_selector != 'ALL':
            raise ValueError("v1 only supports ALL reporting_selector")
        if definition.selector_parameters is not None:
            raise ValueError("v1 ALL selector requires selector_parameters to be None")
        if definition.declared_normalization is not None:
            raise ValueError("v1 ALL selector requires declared_normalization to be None")

        definition.scope_id = scope_id
        definition.version = next_version

        self.session.add(definition)
        await self.session.flush()
        return definition

    async def get_by_id(self, scope_id: uuid.UUID, version: int) -> ScopeDefinition | None:
        return await self.session.get(ScopeDefinition, (scope_id, version))

    async def get_latest_version(self, scope_id: uuid.UUID) -> ScopeDefinition | None:
        stmt = select(ScopeDefinition).where(
            ScopeDefinition.scope_id == scope_id
        ).order_by(ScopeDefinition.version.desc()).limit(1)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
