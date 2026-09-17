"""Analytical schemas for graph pathfinding and traversal results.

These models are strictly separated from canonical Domain entities
to ensure analytical inferences (such as 'paths' or 'exploitable routes')
do not pollute the source of truth in PostgreSQL.
"""

import uuid
from typing import Literal
from pydantic import BaseModel, ConfigDict, model_validator


class AttackPath(BaseModel):
    """Represents a single discovered path between two entities.
    
    Contains ordered lists of node UUIDs and edge (relationship) UUIDs.
    For a path of N nodes, there will be N-1 edges.
    """
    node_ids: list[uuid.UUID]
    edge_ids: list[uuid.UUID]
    
    model_config = ConfigDict(frozen=True)


class TraversalPolicy(BaseModel):
    """Declarative policy for semantic attacker-effort traversal.
    
    max_hops is a strict computational safety bound.
    traversal_budget is the semantic bound evaluated against accumulated edge costs.
    """
    version: Literal["traversal-policy-v1"] = "traversal-policy-v1"
    max_hops: int
    traversal_budget: int
    edge_costs: dict[str, int]
    
    model_config = ConfigDict(frozen=True)


class PathfindingResult(BaseModel):
    """The complete result of a bounded pathfinding query."""
    source_id: uuid.UUID
    target_id: uuid.UUID
    paths: list[AttackPath]
    
    # Metadata about the traversal
    policy: TraversalPolicy | None = None
    max_hops: int
    max_paths: int
    paths_found: int
    is_saturated: bool = False
    termination_reason: Literal["EXHAUSTED", "MAX_PATHS_REACHED"] | None = None
    
    model_config = ConfigDict(frozen=True)


class FindingRiskInput(BaseModel):
    finding_id: uuid.UUID
    entity_id: uuid.UUID
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class RiskInput(BaseModel):
    """Input payload for pure analytical risk calculation."""
    path: AttackPath
    target_criticality: str | None
    entry_exposure: str | None
    edge_types: list[str]
    edge_confidences: list[str | None]
    edge_truth_tiers: list[str]
    edge_sources: list[str]
    findings: list[FindingRiskInput]
    
    @model_validator(mode="after")
    def validate_edge_arrays(self) -> "RiskInput":
        expected_len = len(self.path.edge_ids)
        if len(self.edge_types) != expected_len:
            raise ValueError(f"edge_types length ({len(self.edge_types)}) must match path.edge_ids ({expected_len})")
        if len(self.edge_confidences) != expected_len:
            raise ValueError(f"edge_confidences length ({len(self.edge_confidences)}) must match path.edge_ids ({expected_len})")
        if len(self.edge_truth_tiers) != expected_len:
            raise ValueError(f"edge_truth_tiers length ({len(self.edge_truth_tiers)}) must match path.edge_ids ({expected_len})")
        if len(self.edge_sources) != expected_len:
            raise ValueError(f"edge_sources length ({len(self.edge_sources)}) must match path.edge_ids ({expected_len})")
        return self


class RiskFactor(BaseModel):
    """A normalized risk factor component."""
    value: float
    description: str


class RiskResult(BaseModel):
    """The computed deterministic risk for an AttackPath."""
    formula_version: str = "risk-v1"
    path: AttackPath
    finding_ids: list[uuid.UUID]
    numeric_risk: float
    category: str
    target_criticality: RiskFactor
    entry_exposure: RiskFactor
    edge_enablement: RiskFactor
    confidence: RiskFactor
    finding_amplifier: RiskFactor
    control_dampening: RiskFactor


import hashlib

def generate_canonical_path_id(path: AttackPath) -> str:
    """Generate a cross-process stable canonical path identity using SHA-256.
    
    Format: SHA256(canonical_node_ids_str + "|" + canonical_edge_ids_str)
    """
    nodes_str = ",".join(str(nid) for nid in path.node_ids)
    edges_str = ",".join(str(eid) for eid in path.edge_ids)
    canonical_str = f"{nodes_str}|{edges_str}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class CounterfactualRemediationResult(BaseModel):
    """The result of evaluating a single relationship removal."""
    target_relationship_id: uuid.UUID
    target_source_id: uuid.UUID
    target_target_id: uuid.UUID
    target_relationship_type: Literal[
        "EXPOSES", "ROUTES_TO", "CAN_AUTHENTICATE_TO", "RUNS_AS",
        "HAS_PERMISSION_ON", "MEMBER_OF", "CAN_ASSUME", "DEPENDS_ON",
        "STORES", "TRUSTS", "COMMUNICATES_WITH"
    ]
    
    baseline_environment_risk: float
    counterfactual_environment_risk: float
    risk_reduction: float
    
    baseline_path_count: int
    counterfactual_path_count: int
    
    removed_path_ids: list[str]
    remaining_path_ids: list[str]


class EnvironmentRiskRanking(BaseModel):
    """The complete ranked result of evaluating multiple remediation candidates."""
    aggregation_policy_version: str = "env-risk-v1"
    ranking_policy_version: str = "remediation-ranking-v1"
    analysis_policy_fingerprint: str | None = None
    is_saturated: bool = False
    
    baseline_environment_risk: float
    baseline_path_count: int
    
    candidates: list[CounterfactualRemediationResult]

