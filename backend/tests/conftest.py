"""Pytest configuration and shared fixtures.

Two test tiers:
  1. Unit tests (this conftest) — SQLite in-memory, fast, no external deps.
  2. Integration tests (tests/integration/conftest.py) — PostgreSQL, full constraint surface.

Unit tests here use SQLite for speed. They test basic model construction,
schema validation, and repository logic. PostgreSQL-specific constraints
(enums, CHECK constraints) are tested in the integration suite.
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.domain.models import Base


@pytest_asyncio.fixture(scope="function")
async def sqlite_engine():
    """Create an async SQLite engine for unit tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    # Enable foreign key support in SQLite
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(sqlite_engine):
    """Create a test database session with transaction rollback.

    Each test runs in its own transaction that is rolled back after the test,
    ensuring test isolation.
    """
    async with sqlite_engine.connect() as conn:
        await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)

        yield session

        await session.close()
        await conn.rollback()


def make_entity_kwargs(**overrides):
    """Helper to create valid entity keyword arguments."""
    defaults = {
        "entity_type": "SERVER",
        "name": "test-server",
        "canonical_key": f"server:{uuid.uuid4()}",
        "criticality": "MEDIUM",
        "exposure": "INTERNAL",
    }
    defaults.update(overrides)
    return defaults


def make_evidence_kwargs(**overrides):
    """Helper to create valid evidence keyword arguments."""
    defaults = {
        "source": "test-scanner",
        "source_type": "vulnerability_scanner",
        "assertion": "Test assertion",
        "confidence": "HIGH",
        "imported_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return defaults
