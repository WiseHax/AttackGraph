"""Path Overlap Analytics."""

import uuid
from pydantic import BaseModel, ConfigDict
from app.schemas.analytics import PathfindingResult


class PathOverlapResult(BaseModel):
    """The result of a bounded path overlap analysis."""
    unweighted_edge_participation: dict[uuid.UUID, int]
    risk_weighted_edge_participation: dict[uuid.UUID, float]
    node_choke_points: dict[uuid.UUID, int]
    top_k_jaccard_overlap: list[dict[str, float | str]]
    
    model_config = ConfigDict(frozen=True)


class PathOverlapAnalyzer:
    """Analyzes overlap across a bounded set of AttackPaths."""

    @staticmethod
    def analyze(
        path_result: PathfindingResult,
        path_risks: dict[str, float],
        top_k: int = 10
    ) -> PathOverlapResult:
        """Analyze edge participation and Jaccard overlap.
        
        Args:
            path_result: Bounded pathfinding result.
            path_risks: Mapping of canonical path ID to numeric_risk.
            top_k: Calculate Jaccard overlap for the top K highest-risk paths against others.
        """
        from app.schemas.analytics import generate_canonical_path_id
        
        edge_participation: dict[uuid.UUID, int] = {}
        risk_weighted_edge: dict[uuid.UUID, float] = {}
        node_choke_points: dict[uuid.UUID, int] = {}
        
        # O(P * L) traversal
        for path in path_result.paths:
            path_id = generate_canonical_path_id(path)
            risk = path_risks.get(path_id, 0.0)
            
            for edge_id in path.edge_ids:
                edge_participation[edge_id] = edge_participation.get(edge_id, 0) + 1
                risk_weighted_edge[edge_id] = risk_weighted_edge.get(edge_id, 0.0) + risk
                
            # Node choke points (exclude source and target)
            if len(path.node_ids) > 2:
                for node_id in path.node_ids[1:-1]:
                    node_choke_points[node_id] = node_choke_points.get(node_id, 0) + 1
                    
        # Jaccard Overlap for Top K
        # 1. Sort paths by risk
        sorted_paths = sorted(
            path_result.paths,
            key=lambda p: path_risks.get(generate_canonical_path_id(p), 0.0),
            reverse=True
        )
        
        top_k_paths = sorted_paths[:top_k]
        jaccard_results = []
        
        for p1 in top_k_paths:
            p1_id = generate_canonical_path_id(p1)
            set1 = set(p1.edge_ids)
            
            for p2 in path_result.paths:
                p2_id = generate_canonical_path_id(p2)
                if p1_id == p2_id:
                    continue
                    
                set2 = set(p2.edge_ids)
                intersection = set1.intersection(set2)
                union = set1.union(set2)
                
                jaccard_index = len(intersection) / len(union) if union else 0.0
                
                if jaccard_index > 0:
                    jaccard_results.append({
                        "path_a": p1_id,
                        "path_b": p2_id,
                        "overlap": jaccard_index
                    })
                    
        return PathOverlapResult(
            unweighted_edge_participation=edge_participation,
            risk_weighted_edge_participation=risk_weighted_edge,
            node_choke_points=node_choke_points,
            top_k_jaccard_overlap=jaccard_results
        )
