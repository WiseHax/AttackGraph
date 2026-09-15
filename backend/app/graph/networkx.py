"""NetworkX implementation of the GraphStore protocol."""

import uuid
from typing import Any

import networkx as nx

from .store import GraphStore


class NetworkXStore(GraphStore):
    """In-memory GraphStore implementation using NetworkX.

    Uses MultiDiGraph because the domain schema allows multiple relationships
    of the same type between the same two entities (e.g., differing by time or port).
    The relationship_id is used as the edge key to ensure uniqueness.
    """

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        self.graph.clear()

    def add_entity(
        self,
        entity_id: uuid.UUID,
        entity_type: str,
        name: str,
        **metadata: Any,
    ) -> None:
        """Add an entity as a node in the graph."""
        self.graph.add_node(
            entity_id,
            entity_type=entity_type,
            name=name,
            **metadata,
        )

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
        """Add a directed relationship as an edge in the graph."""
        if truth_tier == "ANALYTICAL":
            raise ValueError("ANALYTICAL truth tier cannot be persisted as a factual graph edge.")

        # Ensure nodes exist to prevent orphaned edges
        if not self.graph.has_node(source_id):
            self.graph.add_node(source_id)
        if not self.graph.has_node(target_id):
            self.graph.add_node(target_id)

        # Use relationship_id as the key to support MultiDiGraph distinct edges
        self.graph.add_edge(
            source_id,
            target_id,
            key=relationship_id,
            relationship_type=relationship_type,
            truth_tier=truth_tier,
            confidence=confidence,
            evidence_ids=evidence_ids or [],
            **metadata,
        )

    def get_entity(self, entity_id: uuid.UUID) -> dict[str, Any] | None:
        """Retrieve node attributes for a given entity ID."""
        if self.graph.has_node(entity_id):
            return dict(self.graph.nodes[entity_id])
        return None

    def get_relationship(self, relationship_id: uuid.UUID) -> dict[str, Any] | None:
        """Retrieve edge attributes for a given relationship ID."""
        # MultiDiGraph edges are accessed via (u, v, key)
        # Since we only have the relationship_id (key), we must scan the edges.
        # This is an O(E) operation in NetworkX, but typically we traverse from nodes.
        # For a more optimized lookup by edge ID, we'd maintain a separate dict map.
        for u, v, key, data in self.graph.edges(keys=True, data=True):
            if key == relationship_id:
                result = dict(data)
                result["source_id"] = u
                result["target_id"] = v
                return result
        return None

    def get_neighbors(self, entity_id: uuid.UUID) -> list[uuid.UUID]:
        """Get the IDs of all entities targeted by outgoing relationships."""
        if self.graph.has_node(entity_id):
            return list(self.graph.successors(entity_id))
        return []

    def get_outgoing_edges(self, entity_id: uuid.UUID) -> list[dict[str, Any]]:
        """Get all outgoing edges from the given entity."""
        edges = []
        if self.graph.has_node(entity_id):
            # out_edges(keys=True, data=True) yields (u, v, key, data)
            for _, target_id, key, data in self.graph.out_edges(entity_id, keys=True, data=True):
                edge_info = data.copy()
                edge_info["target_id"] = target_id
                edge_info["relationship_id"] = key
                edges.append(edge_info)
        return edges

    def clone(self) -> "NetworkXStore":
        """Create an independent unlinked clone of the graph projection."""
        cloned_store = NetworkXStore()
        # nx.MultiDiGraph.copy() creates a shallow copy, which is perfectly safe
        # since we only add/remove nodes and edges, not modify internal dicts.
        cloned_store.graph = self.graph.copy()
        return cloned_store

    def remove_relationship(self, relationship_id: uuid.UUID) -> bool:
        """Remove a specific relationship (edge) by its UUID."""
        # Find the specific edge (u, v, key)
        for u, v, key, data in self.graph.edges(keys=True, data=True):
            if key == relationship_id:
                self.graph.remove_edge(u, v, key=key)
                return True
        return False
