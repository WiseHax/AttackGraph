"""Async SQLAlchemy engine and session management.

Schema lifecycle authority:
    - Alembic is the canonical, authoritative schema lifecycle mechanism.
      All production deployments, CI pipelines, and Docker containers
      MUST use Alembic migrations.
    - init_db() is an OPTIONAL local development convenience ONLY.
      It must not introduce constraints, defaults, or behaviors that
      differ from Alembic migrations. It must not become a competing
      schema management system.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.domain.models import Base


def create_engine(database_url: str):
    """Create an async SQLAlchemy engine."""
    return create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
    )


def create_session_factory(engine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def init_db(engine) -> None:
    """Create all tables from ORM metadata.

    WARNING: This is a LOCAL DEVELOPMENT CONVENIENCE ONLY.
    Production and CI must use Alembic migrations.
    This function exists so developers can quickly stand up a local
    database without running Alembic. It must produce the same schema
    as Alembic migrations.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db(engine) -> None:
    """Drop all tables. For testing only."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
