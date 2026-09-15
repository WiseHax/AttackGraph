"""Optimized bulk queries for analytical graph projection.

These functions provide N+1-free bulk reads of the authoritative PostgreSQL
data, specifically tailored for initializing the in-memory GraphStore.
They bypass the standard CRUD repositories to avoid polluting them with
projection-specific optimization logic.
"""

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domain.models import Entity, Relationship, RelationshipEvidence


async def get_all_entities_for_projection(session: AsyncSession) -> Sequence[Entity]:
    """Fetch all entities efficiently for graph projection."""
    stmt = select(Entity)
    result = await session.execute(stmt)
    return result.scalars().all()


async def get_all_relationships_for_projection(session: AsyncSession) -> Sequence[Relationship]:
    """Fetch all relationships and eager-load their evidence references."""
    stmt = (
        select(Relationship)
        .options(selectinload(Relationship.evidence_links).joinedload(RelationshipEvidence.evidence))
    )
    result = await session.execute(stmt)
    return result.scalars().all()
