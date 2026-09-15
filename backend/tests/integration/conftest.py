"""PostgreSQL integration test fixtures.

These tests run against a real PostgreSQL instance using Alembic migrations
(NOT init_db()) to create the schema. This verifies the canonical schema
lifecycle.

Requirements:
  - Running PostgreSQL instance (same version as docker-compose.yml)
  - TEST_DATABASE_URL environment variable set

All tests are marked @pytest.mark.integration.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.domain.models import Base


def get_test_database_url() -> str:
    """Get the test database URL from environment."""
    url = os.environ.get("TEST_DATABASE_URL", "")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — skipping integration tests")
    return url


def get_sync_url(async_url: str) -> str:
    """Convert async URL to sync URL for Alembic."""
    return async_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")


@pytest.fixture(scope="session")
def pg_schema_setup():
    """Set up the PostgreSQL schema for integration tests.

    Uses Alembic migrations to create the schema, NOT init_db().
    This verifies the canonical schema lifecycle.
    """
    url = get_test_database_url()

    # Run Alembic migrations to set up schema
    import subprocess
    import sys
    from sqlalchemy import create_engine

    sync_url = get_sync_url(url)
    env = os.environ.copy()
    env["DATABASE_URL"] = sync_url

    # First, drop all tables for a clean state using a sync connection
    engine = create_engine(sync_url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()

    # Run Alembic upgrade
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=os.path.join(os.path.dirname(__file__), "..", ".."),
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Alembic migration failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")

    yield url


@pytest_asyncio.fixture(scope="function")
async def pg_engine(pg_schema_setup):
    """Create an async PostgreSQL engine for integration tests."""
    url = pg_schema_setup
    engine = create_async_engine(url, echo=False, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def pg_session(pg_engine):
    """Create a PostgreSQL test session with transaction rollback."""
    async with pg_engine.connect() as conn:
        await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)

        yield session

        await session.close()
        await conn.rollback()


def make_pg_entity_kwargs(**overrides):
    """Helper to create valid entity kwargs for PostgreSQL tests."""
    defaults = {
        "entity_type": "SERVER",
        "name": "pg-test-server",
        "canonical_key": f"server:{uuid.uuid4()}",
        "criticality": "MEDIUM",
        "exposure": "INTERNAL",
    }
    defaults.update(overrides)
    return defaults


def make_pg_evidence_kwargs(**overrides):
    """Helper to create valid evidence kwargs for PostgreSQL tests."""
    defaults = {
        "source": "pg-test-scanner",
        "source_type": "vulnerability_scanner",
        "assertion": "PostgreSQL test assertion",
        "confidence": "HIGH",
        "imported_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return defaults
