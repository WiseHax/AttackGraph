"""Initial schema - Phase 1 domain model

Revision ID: 0001_initial
Revises: None
Create Date: 2026-09-15

Creates all Phase 1 tables:
- entities
- evidence
- relationships
- relationship_evidence
- findings
- finding_evidence
- audit_log
- snapshots

PostgreSQL enums:
- entitytype
- criticality
- exposure
- confidence
- relationshiptype
- truthtier (OBSERVED, INFERRED only — ANALYTICAL is excluded)
- findingseverity
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# PostgreSQL enum types
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM

entitytype_enum = PG_ENUM(
    "INTERNET", "DOMAIN", "SUBDOMAIN", "IP", "HOST", "SERVER",
    "WORKSTATION", "CONTAINER", "CLOUD_RESOURCE", "APPLICATION",
    "API", "DATABASE", "USER", "SERVICE_ACCOUNT", "GROUP", "ROLE",
    "REPOSITORY", "NETWORK_SEGMENT",
    name="entitytype",
    create_type=False,
)

criticality_enum = PG_ENUM(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    name="criticality",
    create_type=False,
)

exposure_enum = PG_ENUM(
    "EXTERNAL", "INTERNAL", "RESTRICTED", "ISOLATED",
    name="exposure",
    create_type=False,
)

confidence_enum = PG_ENUM(
    "HIGH", "MEDIUM", "LOW", "UNKNOWN",
    name="confidence",
    create_type=False,
)

relationshiptype_enum = PG_ENUM(
    "EXPOSES", "ROUTES_TO", "CAN_AUTHENTICATE_TO", "RUNS_AS",
    "HAS_PERMISSION_ON", "MEMBER_OF", "CAN_ASSUME", "DEPENDS_ON",
    "STORES", "TRUSTS", "COMMUNICATES_WITH",
    name="relationshiptype",
    create_type=False,
)

# CRITICAL: truthtier contains ONLY OBSERVED and INFERRED.
# ANALYTICAL is deliberately excluded to structurally prevent
# analytical conclusions from being persisted as graph relationships.
truthtier_enum = PG_ENUM(
    "OBSERVED", "INFERRED",
    name="truthtier",
    create_type=False,
)

findingseverity_enum = PG_ENUM(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    name="findingseverity",
    create_type=False,
)


def upgrade() -> None:
    # Create enum types explicitly
    entitytype_enum.create(op.get_bind(), checkfirst=True)
    criticality_enum.create(op.get_bind(), checkfirst=True)
    exposure_enum.create(op.get_bind(), checkfirst=True)
    confidence_enum.create(op.get_bind(), checkfirst=True)
    relationshiptype_enum.create(op.get_bind(), checkfirst=True)
    truthtier_enum.create(op.get_bind(), checkfirst=True)
    findingseverity_enum.create(op.get_bind(), checkfirst=True)

    # entities
    op.create_table(
        "entities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", entitytype_enum, nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("criticality", criticality_enum, nullable=True),
        sa.Column("owner", sa.String(256), nullable=True),
        sa.Column("environment", sa.String(256), nullable=True),
        sa.Column("exposure", exposure_enum, nullable=True),
        sa.Column("tags", sa.JSON, nullable=True),
        sa.Column("canonical_key", sa.String(1024), nullable=False, unique=True),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_entities_entity_type", "entities", ["entity_type"])
    op.create_index("ix_entities_canonical_key", "entities", ["canonical_key"], unique=True)

    # evidence
    op.create_table(
        "evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(512), nullable=False),
        sa.Column("source_type", sa.String(256), nullable=False),
        sa.Column("assertion", sa.Text, nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", confidence_enum, nullable=True),
        sa.Column("freshness_ttl_seconds", sa.Integer, nullable=True),
        sa.Column("raw_reference", sa.JSON, nullable=True),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # relationships
    op.create_table(
        "relationships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "source_entity_id", UUID(as_uuid=True),
            sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "target_entity_id", UUID(as_uuid=True),
            sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("relationship_type", relationshiptype_enum, nullable=False),
        sa.Column("truth_tier", truthtier_enum, nullable=False),
        sa.Column("confidence", confidence_enum, nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_relationships_source", "relationships", ["source_entity_id"])
    op.create_index("ix_relationships_target", "relationships", ["target_entity_id"])
    op.create_index("ix_relationships_type", "relationships", ["relationship_type"])

    # relationship_evidence
    op.create_table(
        "relationship_evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "relationship_id", UUID(as_uuid=True),
            sa.ForeignKey("relationships.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "evidence_id", UUID(as_uuid=True),
            sa.ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False,
        ),
        sa.UniqueConstraint("relationship_id", "evidence_id", name="uq_relationship_evidence"),
    )

    # findings
    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "entity_id", UUID(as_uuid=True),
            sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", findingseverity_enum, nullable=False),
        sa.Column("source", sa.String(512), nullable=False),
        sa.Column("source_type", sa.String(256), nullable=True),
        sa.Column("source_reference", sa.String(1024), nullable=True),
        sa.Column("confidence", confidence_enum, nullable=True),
        sa.Column("status", sa.String(64), nullable=True),
        sa.Column("remediation_notes", sa.Text, nullable=True),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_findings_entity_id", "findings", ["entity_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    # finding_evidence
    op.create_table(
        "finding_evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "finding_id", UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "evidence_id", UUID(as_uuid=True),
            sa.ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False,
        ),
        sa.UniqueConstraint("finding_id", "evidence_id", name="uq_finding_evidence"),
    )

    # audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("action", sa.String(256), nullable=False),
        sa.Column("entity_type", sa.String(256), nullable=True),
        sa.Column("entity_id", sa.String(256), nullable=True),
        sa.Column("actor", sa.String(256), nullable=True),
        sa.Column("detail", sa.JSON, nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    # snapshots
    op.create_table(
        "snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("snapshot_data", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(256), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("finding_evidence")
    op.drop_table("findings")
    op.drop_table("relationship_evidence")
    op.drop_table("relationships")
    op.drop_table("evidence")
    op.drop_table("snapshots")
    op.drop_table("audit_log")
    op.drop_table("entities")

    # Drop enum types
    findingseverity_enum.drop(op.get_bind(), checkfirst=True)
    truthtier_enum.drop(op.get_bind(), checkfirst=True)
    relationshiptype_enum.drop(op.get_bind(), checkfirst=True)
    confidence_enum.drop(op.get_bind(), checkfirst=True)
    exposure_enum.drop(op.get_bind(), checkfirst=True)
    criticality_enum.drop(op.get_bind(), checkfirst=True)
    entitytype_enum.drop(op.get_bind(), checkfirst=True)
