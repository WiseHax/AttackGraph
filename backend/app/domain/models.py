"""SQLAlchemy ORM models for AttackGraph domain objects.

These models define the persistent schema. PostgreSQL is the source of truth.
The graph (NetworkX, Phase 2) is a rebuildable analytical projection.

Key design rules:
- TruthTier on Relationship only allows OBSERVED / INFERRED (structural enforcement).
- Findings attach to entities; they are NOT graph nodes.
- Evidence is first-class and independently persisted.
- AuditLog is append-only.
- Analytical results (attack paths, risk scores) are NOT persisted here.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.orm import relationship as orm_relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ── Enum type definitions (shared across models) ──────────────────────────

_entitytype_enum = Enum(
    "INTERNET", "DOMAIN", "SUBDOMAIN", "IP", "HOST", "SERVER",
    "WORKSTATION", "CONTAINER", "CLOUD_RESOURCE", "APPLICATION",
    "API", "DATABASE", "USER", "SERVICE_ACCOUNT", "GROUP", "ROLE",
    "REPOSITORY", "NETWORK_SEGMENT",
    name="entitytype",
    create_constraint=True,
)

_criticality_enum = Enum(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    name="criticality",
    create_constraint=True,
)

_exposure_enum = Enum(
    "EXTERNAL", "INTERNAL", "RESTRICTED", "ISOLATED",
    name="exposure",
    create_constraint=True,
)

_confidence_enum = Enum(
    "HIGH", "MEDIUM", "LOW", "UNKNOWN",
    name="confidence",
    create_constraint=True,
)

_relationshiptype_enum = Enum(
    "EXPOSES", "ROUTES_TO", "CAN_AUTHENTICATE_TO", "RUNS_AS",
    "HAS_PERMISSION_ON", "MEMBER_OF", "CAN_ASSUME", "DEPENDS_ON",
    "STORES", "TRUSTS", "COMMUNICATES_WITH",
    name="relationshiptype",
    create_constraint=True,
)

_truthtier_enum = Enum(
    "OBSERVED", "INFERRED",
    name="truthtier",
    create_constraint=True,
)

_findingseverity_enum = Enum(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    name="findingseverity",
    create_constraint=True,
)


# ---------------------------------------------------------------------------
# Entity
# ---------------------------------------------------------------------------

class Entity(Base):
    """A persistent security-relevant object (host, user, database, etc.)."""

    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    entity_type: Mapped[str] = mapped_column(
        _entitytype_enum, nullable=False,
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    criticality: Mapped[str | None] = mapped_column(
        _criticality_enum, nullable=True,
    )
    owner: Mapped[str | None] = mapped_column(String(256), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(256), nullable=True)
    exposure: Mapped[str | None] = mapped_column(
        _exposure_enum, nullable=True,
    )
    tags: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    canonical_key: Mapped[str] = mapped_column(
        String(1024), nullable=False, unique=True
    )
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", JSON, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ORM navigation (back_populates set up against classes defined below)
    findings: Mapped[list["Finding"]] = orm_relationship(
        "Finding", back_populates="entity", cascade="all, delete-orphan"
    )
    source_relationships: Mapped[list["Relationship"]] = orm_relationship(
        "Relationship",
        foreign_keys="Relationship.source_entity_id",
        back_populates="source_entity",
        cascade="all, delete-orphan",
    )
    target_relationships: Mapped[list["Relationship"]] = orm_relationship(
        "Relationship",
        foreign_keys="Relationship.target_entity_id",
        back_populates="target_entity",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_entities_entity_type", "entity_type"),
        Index("ix_entities_canonical_key", "canonical_key", unique=True),
    )

    def __repr__(self) -> str:
        return f"<Entity(id={self.id}, type={self.entity_type}, name={self.name!r})>"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(Base):
    """First-class evidence entity.

    Evidence is independently persisted and referenced by relationships
    and findings. The user must be able to answer:
    "Why does AttackGraph believe this relationship exists?"

    Evidence must never be fabricated.
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    source: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str] = mapped_column(String(256), nullable=False)
    assertion: Mapped[str] = mapped_column(Text, nullable=False)
    collected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    confidence: Mapped[str | None] = mapped_column(
        _confidence_enum, nullable=True,
    )
    freshness_ttl_seconds: Mapped[int | None] = mapped_column(nullable=True)
    raw_reference: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", JSON, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return f"<Evidence(id={self.id}, source={self.source!r})>"


# ---------------------------------------------------------------------------
# Relationship
# ---------------------------------------------------------------------------

class Relationship(Base):
    """A directed, typed security relationship between two entities.

    truth_tier is constrained to OBSERVED / INFERRED only.
    ANALYTICAL is structurally excluded from this enum at the database level.
    """

    __tablename__ = "relationships"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_entity_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(
        _relationshiptype_enum, nullable=False,
    )
    truth_tier: Mapped[str] = mapped_column(
        _truthtier_enum, nullable=False,
    )
    confidence: Mapped[str | None] = mapped_column(
        Enum(
            "HIGH", "MEDIUM", "LOW", "UNKNOWN",
            name="confidence",
            create_constraint=True,
            create_type=False,  # Reuse the confidence type from Evidence
        ),
        nullable=True,
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    valid_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    valid_to: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", JSON, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # ORM navigation
    source_entity: Mapped["Entity"] = orm_relationship(
        "Entity", foreign_keys=[source_entity_id], back_populates="source_relationships"
    )
    target_entity: Mapped["Entity"] = orm_relationship(
        "Entity", foreign_keys=[target_entity_id], back_populates="target_relationships"
    )
    evidence_links: Mapped[list["RelationshipEvidence"]] = orm_relationship(
        "RelationshipEvidence", back_populates="relationship", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_relationships_source", "source_entity_id"),
        Index("ix_relationships_target", "target_entity_id"),
        Index("ix_relationships_type", "relationship_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<Relationship(id={self.id}, "
            f"type={self.relationship_type}, "
            f"truth={self.truth_tier})>"
        )


# ---------------------------------------------------------------------------
# RelationshipEvidence (association)
# ---------------------------------------------------------------------------

class RelationshipEvidence(Base):
    """Links a Relationship to one or more Evidence records.

    Multiple independent sources may assert the same relationship.
    This association preserves all independent evidence.
    """

    __tablename__ = "relationship_evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    relationship_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("relationships.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=False,
    )

    relationship: Mapped["Relationship"] = orm_relationship(
        "Relationship", back_populates="evidence_links"
    )
    evidence: Mapped["Evidence"] = orm_relationship("Evidence")

    __table_args__ = (
        UniqueConstraint(
            "relationship_id", "evidence_id",
            name="uq_relationship_evidence"
        ),
    )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(Base):
    """A security finding attached to an entity.

    A finding is NOT a graph node. It attaches to an entity and can
    influence analytical reasoning (Phase 4+).
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        _findingseverity_enum, nullable=False,
    )
    source: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    confidence: Mapped[str | None] = mapped_column(
        Enum(
            "HIGH", "MEDIUM", "LOW", "UNKNOWN",
            name="confidence",
            create_constraint=True,
            create_type=False,
        ),
        nullable=True,
    )
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", JSON, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ORM navigation
    entity: Mapped["Entity"] = orm_relationship("Entity", back_populates="findings")
    evidence_links: Mapped[list["FindingEvidence"]] = orm_relationship(
        "FindingEvidence", back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_findings_entity_id", "entity_id"),
        Index("ix_findings_severity", "severity"),
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, title={self.title!r}, severity={self.severity})>"


# ---------------------------------------------------------------------------
# FindingEvidence (association)
# ---------------------------------------------------------------------------

class FindingEvidence(Base):
    """Links a Finding to one or more Evidence records."""

    __tablename__ = "finding_evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=False,
    )

    finding: Mapped["Finding"] = orm_relationship("Finding", back_populates="evidence_links")
    evidence: Mapped["Evidence"] = orm_relationship("Evidence")

    __table_args__ = (
        UniqueConstraint(
            "finding_id", "evidence_id",
            name="uq_finding_evidence"
        ),
    )


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLog(Base):
    """Append-only audit trail.

    Records are created but never updated or deleted.
    This invariant is enforced at the repository layer.
    """

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    action: Mapped[str] = mapped_column(String(256), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_action", "action"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action!r})>"


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

class Snapshot(Base):
    """Point-in-time snapshot placeholder.

    Full snapshot functionality is Phase 9. This model reserves
    the schema for future use.
    """

    __tablename__ = "snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)

    def __repr__(self) -> str:
        return f"<Snapshot(id={self.id}, name={self.name!r})>"
