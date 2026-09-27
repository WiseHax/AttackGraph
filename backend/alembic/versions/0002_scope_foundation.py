"""Scope Foundation

Revision ID: 0002_scope_foundation
Revises: 0001_initial
Create Date: 2026-09-27

Creates scopes and scope_definitions tables.
Adds DB-level immutability triggers.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision: str = "0002_scope_foundation"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # scopes
    op.create_table(
        "scopes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("display_name", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # scope_definitions
    op.create_table(
        "scope_definitions",
        sa.Column("scope_id", UUID(as_uuid=True), sa.ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("input_boundary_kind", sa.String(64), nullable=False),
        sa.Column("reporting_selector", sa.String(64), nullable=False),
        sa.Column("selector_parameters", sa.JSON(), nullable=True),
        sa.Column("declared_normalization", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("input_boundary_kind = 'UNIVERSAL'", name="chk_v1_input_boundary"),
        sa.CheckConstraint("reporting_selector = 'ALL'", name="chk_v1_reporting_selector"),
        sa.CheckConstraint("selector_parameters IS NULL", name="chk_v1_selector_parameters"),
        sa.CheckConstraint("declared_normalization IS NULL", name="chk_v1_declared_normalization"),
    )

    # Immutability triggers
    op.execute("""
    CREATE OR REPLACE FUNCTION prevent_modification()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'Modification of this record is strictly prohibited by architectural invariant.';
    END;
    $$ LANGUAGE plpgsql;
    """)

    op.execute("""
    CREATE TRIGGER trg_scope_def_immutable
    BEFORE UPDATE OR DELETE ON scope_definitions
    FOR EACH ROW EXECUTE FUNCTION prevent_modification();
    """)

    op.execute("""
    CREATE TRIGGER trg_scope_immutable_lifecycle
    BEFORE DELETE ON scopes
    FOR EACH ROW EXECUTE FUNCTION prevent_modification();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_scope_immutable_lifecycle ON scopes;")
    op.execute("DROP TRIGGER trg_scope_def_immutable ON scope_definitions;")
    op.execute("DROP FUNCTION prevent_modification();")
    op.drop_table("scope_definitions")
    op.drop_table("scopes")
