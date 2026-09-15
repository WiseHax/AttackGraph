"""GraphStore abstraction for analytical graph projection.

This protocol defines the interface for interacting with the analytical graph,
allowing the underlying implementation (e.g., NetworkX, Neo4j) to be swapped
without affecting the application logic.

IMPORTANT: The GraphStore is a projection. It does NOT persist to PostgreSQL.
"""

import uuid
from typing import Any, Protocol


class GraphStore(Protocol):
    """Protocol defining the analytical graph store interface."""

    def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        ...

    def add_entity(
        self,
        entity_id: uuid.UUID,
        entity_type: str,
        name: str,
        **metadata: Any,
    ) -> None:
        """Add an entity as a node in the graph."""
        ...

    def add_relationship(
        self,
        relationship_id: uuid.UUID,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        relationship_type: str,
        truth_tier: str,
        confidence: str | None = None,
        evidence_ids: list[uuid.UUID] | None = None,
        **metadata: Any,
    ) -> None:
        """Add a directed relationship as an edge in the graph.

        truth_tier must be 'OBSERVED' or 'INFERRED'.
        'ANALYTICAL' truth tiers should be kept separate from the factual graph.
        """
        ...

    def get_entity(self, entity_id: uuid.UUID) -> dict[str, Any] | None:
        """Retrieve node attributes for a given entity ID."""
        ...

    def get_relationship(self, relationship_id: uuid.UUID) -> dict[str, Any] | None:
        """Retrieve edge attributes for a given relationship ID."""
        ...

    def get_neighbors(self, entity_id: uuid.UUID) -> list[uuid.UUID]:
        """Get the IDs of all entities targeted by outgoing relationships."""
        ...

    def get_outgoing_edges(self, entity_id: uuid.UUID) -> list[dict[str, Any]]:
        """Get all outgoing edges from the given entity.
        
        Returns a list of dictionaries, where each dictionary represents an edge
        and must contain at least:
        - target_id: The UUID of the target entity
        - relationship_id: The UUID of the relationship (edge key)
        - relationship_type: The string type of the relationship
        """
        ...

    def clone(self) -> "GraphStore":
        """Create an independent unlinked clone of the graph projection."""
        ...

    def remove_relationship(self, relationship_id: uuid.UUID) -> bool:
        """Remove a specific relationship (edge) by its UUID.
        
        Must preserve parallel edges.
        Returns True if removed, False if not found.
        """
        ...
