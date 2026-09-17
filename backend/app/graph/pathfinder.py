"""Pathfinding engine for AttackGraph."""



import uuid

from typing import Any



from app.graph.store import GraphStore

from app.schemas.analytics import AttackPath, PathfindingResult, TraversalPolicy





class TraversalEngine:

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

        policy: TraversalPolicy | None = None,

        max_hops: int = 6,

        max_paths: int = 100,

        allowed_types: set[str] | list[str] | None = None,

    ) -> PathfindingResult:

        """Find attack paths from source to target.



        Args:

            source_id: Starting entity UUID

            target_id: Destination entity UUID

            policy: TraversalPolicy for attacker-effort bounds. Overrides max_hops if provided.

            max_hops: Maximum computational depth if policy is not provided

            max_paths: Maximum number of valid paths to discover before halting

            allowed_types: If provided, only traverse these relationship types



        Returns:

            PathfindingResult containing discovered paths.

        """

        if policy is not None:

            max_hops = policy.max_hops



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

                policy=policy,

                max_hops=max_hops,

                max_paths=max_paths,

                paths_found=1,

                is_saturated=False,

                termination_reason="EXHAUSTED"

            )



        # DFS stack contains: (current_node_id, current_node_path, current_edge_path, visited_nodes, accumulated_cost)

        stack: list[tuple[uuid.UUID, list[uuid.UUID], list[uuid.UUID], set[uuid.UUID], int]] = [

            (source_id, [source_id], [], {source_id}, 0)

        ]



        while stack and len(discovered_paths) < max_paths:

            current_node, node_path, edge_path, visited, accumulated_cost = stack.pop()



            # Stop expanding if we exceed traversal_budget (Semantic bound)

            if policy is not None and accumulated_cost > policy.traversal_budget:

                continue



            # If we reached the target, save the path

            if current_node == target_id and len(node_path) > 1:

                discovered_paths.append(

                    AttackPath(node_ids=list(node_path), edge_ids=list(edge_path))

                )

                continue



            # Stop expanding if we reached max_hops (Computational bound)

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

            edges.sort(

                key=lambda e: (

                    e["relationship_type"],

                    str(e["target_id"]),

                    str(e["relationship_id"])

                ),

                reverse=True

            )



            for edge in edges:

                edge_type = edge["relationship_type"]



                # Check negative edge costs explicitly

                cost = 1 # default

                if policy is not None:

                    cost = policy.edge_costs.get(edge_type, 1)

                    if cost < 0:

                        raise ValueError(f"Edge cost for {edge_type} cannot be negative.")



                next_node = edge["target_id"]

                new_visited = set(visited)

                new_visited.add(next_node)



                new_node_path = list(node_path)

                new_node_path.append(next_node)



                new_edge_path = list(edge_path)

                new_edge_path.append(edge["relationship_id"])



                stack.append((next_node, new_node_path, new_edge_path, new_visited, accumulated_cost + cost))



        is_saturated = len(discovered_paths) >= max_paths

        termination_reason = "MAX_PATHS_REACHED" if is_saturated else "EXHAUSTED"



        return PathfindingResult(

            source_id=source_id,

            target_id=target_id,

            paths=discovered_paths,

            policy=policy,

            max_hops=max_hops,

            max_paths=max_paths,

            paths_found=len(discovered_paths),

            is_saturated=is_saturated,

            termination_reason=termination_reason

        )
