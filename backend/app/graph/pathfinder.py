"""Pathfinding engine for AttackGraph."""

import uuid
from typing import Any

from app.graph.store import GraphStore
from app.schemas.analytics import AttackPath, PathfindingResult


class Pathfinder:
    """Analytical engine for discovering paths within the GraphStore.
    
    This engine is read-only. It performs bounded, deterministic traversal
    and produces separate analytical result objects to ensure canonical
    graph facts are never mutated.
    """

    def __init__(self, store: GraphStore):
        self.store = store

    def find_paths(
        self,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        max_hops: int = 6,
        max_paths: int = 100,
        allowed_types: set[str] | list[str] | None = None,
    ) -> PathfindingResult:
        """Find attack paths from source to target.
        
        Args:
            source_id: Starting entity UUID
            target_id: Destination entity UUID
            max_hops: Maximum number of edges in any path
            max_paths: Maximum number of valid paths to discover before halting
            allowed_types: If provided, only traverse these relationship types
            
        Returns:
            PathfindingResult containing discovered paths.
        """
        if max_hops < 0:
            raise ValueError("max_hops must be >= 0")
        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")

        if allowed_types is not None and not isinstance(allowed_types, set):
            allowed_types = set(allowed_types)
            
        discovered_paths: list[AttackPath] = []
        
        # Zero-hop path if source == target
        if source_id == target_id:
            discovered_paths.append(
                AttackPath(node_ids=[source_id], edge_ids=[])
            )
            return PathfindingResult(
                source_id=source_id,
                target_id=target_id,
                paths=discovered_paths,
                max_hops=max_hops,
                max_paths=max_paths,
                paths_found=1
            )
        
        # DFS stack contains: (current_node_id, current_node_path, current_edge_path, visited_nodes)
        stack: list[tuple[uuid.UUID, list[uuid.UUID], list[uuid.UUID], set[uuid.UUID]]] = [
            (source_id, [source_id], [], {source_id})
        ]
        
        while stack and len(discovered_paths) < max_paths:
            current_node, node_path, edge_path, visited = stack.pop()
            
            # If we reached the target, save the path
            if current_node == target_id and len(node_path) > 1:
                discovered_paths.append(
                    AttackPath(node_ids=list(node_path), edge_ids=list(edge_path))
                )
                continue
                
            # Stop expanding if we reached max_hops
            if len(edge_path) >= max_hops:
                continue
                
            # Get outgoing edges
            edges = self.store.get_outgoing_edges(current_node)
            
            # Filter edges by allowed types
            if allowed_types is not None:
                edges = [e for e in edges if e["relationship_type"] in allowed_types]
                
            # Filter out cycles (path-local visited check)
            edges = [e for e in edges if e["target_id"] not in visited]
            
            # Sort edges for deterministic traversal: relationship_type, target_id, relationship_id
            # We reverse the sort before extending the stack so that the first item popped
            # is the one that would appear first in the sorted order (DFS left-to-right).
            edges.sort(
                key=lambda e: (
                    e["relationship_type"],
                    str(e["target_id"]),
                    str(e["relationship_id"])
                ),
                reverse=True
            )
            
            for edge in edges:
                next_node = edge["target_id"]
                new_visited = set(visited)
                new_visited.add(next_node)
                
                new_node_path = list(node_path)
                new_node_path.append(next_node)
                
                new_edge_path = list(edge_path)
                new_edge_path.append(edge["relationship_id"])
                
                stack.append((next_node, new_node_path, new_edge_path, new_visited))
                
        return PathfindingResult(
            source_id=source_id,
            target_id=target_id,
            paths=discovered_paths,
            max_hops=max_hops,
            max_paths=max_paths,
            paths_found=len(discovered_paths)
        )
