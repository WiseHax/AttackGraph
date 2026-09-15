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


class PathfindingResult(BaseModel):
    """The complete result of a bounded pathfinding query."""
    source_id: uuid.UUID
    target_id: uuid.UUID
    paths: list[AttackPath]
    
    # Metadata about the traversal
    max_hops: int
    max_paths: int
    paths_found: int
    
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

