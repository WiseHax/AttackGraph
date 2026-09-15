"""PostgreSQL integration tests for Alembic migrations.

Tests migration correctness, idempotency, and schema verification
against real PostgreSQL.
"""

import os
import subprocess
import sys

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.integration.conftest import get_test_database_url, get_sync_url

pytestmark = pytest.mark.integration

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..")

EXPECTED_TABLES = {
    "entities",
    "evidence",
    "relationships",
    "relationship_evidence",
    "findings",
    "finding_evidence",
    "audit_log",
    "snapshots",
    "alembic_version",
}

EXPECTED_ENUMS = {
    "entitytype",
    "criticality",
    "exposure",
    "confidence",
    "relationshiptype",
    "truthtier",
    "findingseverity",
}


def _run_alembic(command: list[str], env: dict) -> subprocess.CompletedProcess:
    """Run an Alembic command and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "alembic"] + command,
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def alembic_env():
    """Environment variables for Alembic commands."""
    url = get_test_database_url()
    env = os.environ.copy()
    env["DATABASE_URL"] = get_sync_url(url)
    return env


class TestAlembicMigrationCorrectness:
    @pytest.mark.asyncio
    async def test_all_expected_tables_exist(self, pg_session):
        """After migration, all expected tables must exist."""
        result = await pg_session.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
        """))
        tables = {row[0] for row in result.fetchall()}

        for expected in EXPECTED_TABLES:
            assert expected in tables, f"Table '{expected}' missing after migration"

    @pytest.mark.asyncio
    async def test_all_expected_enums_exist(self, pg_session):
        """After migration, all expected PostgreSQL enum types must exist."""
        result = await pg_session.execute(text("""
            SELECT typname
            FROM pg_type
            WHERE typtype = 'e'
        """))
        enums = {row[0] for row in result.fetchall()}

        for expected in EXPECTED_ENUMS:
            assert expected in enums, f"Enum type '{expected}' missing after migration"

    @pytest.mark.asyncio
    async def test_truthtier_enum_values(self, pg_session):
        """The truthtier enum must contain only OBSERVED and INFERRED."""
        result = await pg_session.execute(text("""
            SELECT enumlabel
            FROM pg_enum
            JOIN pg_type ON pg_enum.enumtypid = pg_type.oid
            WHERE pg_type.typname = 'truthtier'
            ORDER BY enumsortorder
        """))
        values = [row[0] for row in result.fetchall()]
        assert values == ["OBSERVED", "INFERRED"], (
            f"truthtier enum has unexpected values: {values}"
        )

    @pytest.mark.asyncio
    async def test_entities_table_columns(self, pg_session):
        """Verify entities table has expected columns."""
        result = await pg_session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'entities' AND table_schema = 'public'
        """))
        columns = {row[0] for row in result.fetchall()}

        expected_columns = {
            "id", "entity_type", "name", "description", "criticality",
            "owner", "environment", "exposure", "tags", "canonical_key",
            "metadata", "created_at", "updated_at", "first_seen", "last_seen",
        }
        for col in expected_columns:
            assert col in columns, f"Column '{col}' missing from entities table"

    @pytest.mark.asyncio
    async def test_relationships_table_columns(self, pg_session):
        """Verify relationships table has expected columns."""
        result = await pg_session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'relationships' AND table_schema = 'public'
        """))
        columns = {row[0] for row in result.fetchall()}

        expected_columns = {
            "id", "source_entity_id", "target_entity_id",
            "relationship_type", "truth_tier", "confidence",
            "observed_at", "valid_from", "valid_to",
            "metadata", "created_at", "updated_at",
        }
        for col in expected_columns:
            assert col in columns, f"Column '{col}' missing from relationships table"

    @pytest.mark.asyncio
    async def test_canonical_key_unique_constraint(self, pg_session):
        """Verify the unique constraint on entities.canonical_key exists."""
        result = await pg_session.execute(text("""
            SELECT constraint_name
            FROM information_schema.table_constraints
            WHERE table_name = 'entities'
              AND constraint_type = 'UNIQUE'
              AND table_schema = 'public'
        """))
        constraints = {row[0] for row in result.fetchall()}
        # Look for our unique index/constraint on canonical_key
        assert any("canonical_key" in c for c in constraints), (
            f"No unique constraint on canonical_key. Found: {constraints}"
        )

    @pytest.mark.asyncio
    async def test_foreign_key_constraints_exist(self, pg_session):
        """Verify foreign key constraints exist on relationship tables."""
        result = await pg_session.execute(text("""
            SELECT tc.constraint_name, tc.table_name, kcu.column_name,
                   ccu.table_name AS foreign_table_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_schema = 'public'
        """))
        fks = result.fetchall()
        fk_info = [(row[1], row[2], row[3]) for row in fks]

        # relationships.source_entity_id -> entities
        assert any(
            t == "relationships" and c == "source_entity_id" and ft == "entities"
            for t, c, ft in fk_info
        ), "Missing FK: relationships.source_entity_id -> entities"

        # relationships.target_entity_id -> entities
        assert any(
            t == "relationships" and c == "target_entity_id" and ft == "entities"
            for t, c, ft in fk_info
        ), "Missing FK: relationships.target_entity_id -> entities"

        # findings.entity_id -> entities
        assert any(
            t == "findings" and c == "entity_id" and ft == "entities"
            for t, c, ft in fk_info
        ), "Missing FK: findings.entity_id -> entities"


class TestAlembicIdempotency:
    def test_upgrade_head_idempotent(self, alembic_env):
        """Running 'upgrade head' when already at head produces no errors."""
        # Already at head from session setup; running again should be fine
        result = _run_alembic(["upgrade", "head"], alembic_env)
        assert result.returncode == 0, (
            f"Alembic upgrade head failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_current_shows_head(self, alembic_env):
        """'alembic current' should show the head revision."""
        result = _run_alembic(["current"], alembic_env)
        assert result.returncode == 0
        assert "0001_initial" in result.stdout


class TestAlembicDowngrade:
    def test_downgrade_and_upgrade_roundtrip(self, alembic_env):
        """Downgrade then upgrade should round-trip cleanly."""
        # Downgrade
        result = _run_alembic(["downgrade", "base"], alembic_env)
        assert result.returncode == 0, (
            f"Alembic downgrade failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # Upgrade back
        result = _run_alembic(["upgrade", "head"], alembic_env)
        assert result.returncode == 0, (
            f"Alembic upgrade failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
