"""Projection service for building analytical graphs from PostgreSQL."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.graph_queries import (
    get_all_entities_for_projection,
    get_all_relationships_for_projection,
)
from .store import GraphStore


class GraphBuilder:
    """Service to project PostgreSQL source-of-truth into an analytical GraphStore."""

    def __init__(self, session: AsyncSession, store: GraphStore):
        self.session = session
        self.store = store

    async def build(self) -> None:
        """Clear and rebuild the graph projection from the database."""
        self.store.clear()

        # Project entities as nodes
        entities = await get_all_entities_for_projection(self.session)
        for entity in entities:
            self.store.add_entity(
                entity_id=entity.id,
                entity_type=entity.entity_type,
                name=entity.name,
                criticality=entity.criticality,
                exposure=entity.exposure,
                canonical_key=entity.canonical_key,
            )

        # Project relationships as edges
        relationships = await get_all_relationships_for_projection(self.session)
        for rel in relationships:
            # Extract evidence IDs from relationship.evidence_links
            evidence_ids = [link.evidence_id for link in rel.evidence_links]
            
            self.store.add_relationship(
                relationship_id=rel.id,
                source_id=rel.source_entity_id,
                target_id=rel.target_entity_id,
                relationship_type=rel.relationship_type,
                truth_tier=rel.truth_tier,
                confidence=rel.confidence,
                evidence_ids=evidence_ids,
            )
