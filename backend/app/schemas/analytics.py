"""Analytical schemas for graph pathfinding and traversal results.

These models are strictly separated from canonical Domain entities
to ensure analytical inferences (such as 'paths' or 'exploitable routes')
do not pollute the source of truth in PostgreSQL.
"""

import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator


def normalize_evaluation_time(value: datetime) -> datetime:
    """Validate an injected evaluation time and return it in canonical UTC.

    Evaluation time is an explicit analytical input (ANA-3): it must be a
    timezone-aware datetime. A naive datetime would be interpreted in the host's
    local timezone, making results environment-dependent, so it is rejected.
    There is deliberately no fallback to the current time.
    """
    if not isinstance(value, datetime):
        raise ValueError("evaluation_time must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evaluation_time must be timezone-aware; naive datetimes are rejected")
    return value.astimezone(timezone.utc)


class AnalyticalScope(BaseModel):
    """Immutable, resolved scope definition passed to the graph layer.

    v1 only supports UNIVERSAL input boundary and ALL reporting selector.

    Canonical identity (ARCH-28): scope_id and definition_version identify the
    exact immutable ScopeDefinition this scope was resolved from, and are set
    only by app.graph.scope_resolution.resolve_analytical_scope. They are
    present together or absent together. A scope without them is ad-hoc: valid
    for non-persisted analysis, but it has no canonical persisted identity and
    cannot back a persistable or comparable run.
    """
    input_boundary_kind: Literal["UNIVERSAL"]
    reporting_selector: Literal["ALL"]
    scope_id: uuid.UUID | None = None
    definition_version: Annotated[StrictInt, Field(ge=1)] | None = None

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def validate_identity_pair(self) -> "AnalyticalScope":
        if (self.scope_id is None) != (self.definition_version is None):
            raise ValueError(
                "scope_id and definition_version must both be present or both be absent"
            )
        return self


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
    """The result of evaluating a single relationship removal.

    removed_path_ids and remaining_path_ids are canonical path IDs
    (see generate_canonical_path_id) in ascending lexicographic order.
    This total order is part of the result (ANA-3) so that serialized
    output is byte-identical across processes.

    Saturation (ANA-7a): counterfactual_is_saturated / _termination_reason
    describe this candidate's enumeration. rankable is False when either the
    baseline or this candidate's enumeration saturated: a truncated path set
    is a lower bound, so its risk reduction is not a complete measurement.
    """
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

    counterfactual_is_saturated: bool
    counterfactual_termination_reason: Literal["EXHAUSTED", "MAX_PATHS_REACHED"]
    rankable: bool

    @model_validator(mode="after")
    def _saturation_is_consistent(self) -> "CounterfactualRemediationResult":
        # ANA-7a: the termination reason and the saturation flag describe the
        # same enumeration; a saturated candidate is never rankable. Whether an
        # unsaturated candidate is rankable also depends on the baseline and is
        # checked by EnvironmentRiskRanking.
        expected_reason = "MAX_PATHS_REACHED" if self.counterfactual_is_saturated else "EXHAUSTED"
        if self.counterfactual_termination_reason != expected_reason:
            raise ValueError(
                "counterfactual_termination_reason must be MAX_PATHS_REACHED exactly when "
                "counterfactual_is_saturated"
            )
        if self.counterfactual_is_saturated and self.rankable:
            raise ValueError("a saturated counterfactual candidate cannot be rankable")
        return self


# Fixed reason codes explaining why a ranking is not persistence-authoritative.
# Emitted in sorted order.
NON_AUTHORITATIVE_BASELINE_SATURATED = "BASELINE_SATURATED"
NON_AUTHORITATIVE_COUNTERFACTUAL_SATURATED = "COUNTERFACTUAL_SATURATED"
NON_AUTHORITATIVE_NO_ANALYSIS_CONTEXT = "NO_ANALYSIS_CONTEXT"
NON_AUTHORITATIVE_NON_CANONICAL_SCOPE = "NON_CANONICAL_SCOPE"
NonAuthoritativeReason = Literal[
    "BASELINE_SATURATED",
    "COUNTERFACTUAL_SATURATED",
    "NO_ANALYSIS_CONTEXT",
    "NON_CANONICAL_SCOPE",
]


class AnalysisProvenance(BaseModel):
    """What an analytical result was computed under (ANA-5, SEC-22).

    Pure data: no I/O, no engine identity. evaluation_time is canonical UTC
    and serializes with a 'Z' suffix. scope_id / scope_definition_version name
    the exact resolved ScopeDefinition (ARCH-28); both are absent for an
    ad-hoc, non-persistable scope.
    """
    policy_version: str
    policy_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    evaluation_time: datetime
    scope_id: uuid.UUID | None = None
    scope_definition_version: Annotated[StrictInt, Field(ge=1)] | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("evaluation_time", mode="before")
    @classmethod
    def _canonical_utc(cls, value: datetime | str) -> datetime:
        # A provenance record must survive its own JSON serialization (ISO 8601
        # with an explicit offset, e.g. "2026-01-15T12:00:00Z"). The parsed
        # value goes through the same check, so naive times are still rejected.
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError("evaluation_time must be an ISO 8601 datetime") from exc
        return normalize_evaluation_time(value)

    @model_validator(mode="after")
    def _scope_identity_pair(self) -> "AnalysisProvenance":
        if (self.scope_id is None) != (self.scope_definition_version is None):
            raise ValueError(
                "scope_id and scope_definition_version must both be present or both be absent"
            )
        return self


class EnvironmentRiskRanking(BaseModel):
    """The complete ranked result of evaluating multiple remediation candidates.

    Saturation (ANA-7a): is_saturated is True when the baseline or any
    candidate enumeration saturated. Numbers are still produced in that case,
    but they are lower bounds, not a complete remediation-ranking domain.

    persistence_authoritative is True only for an unsaturated run computed
    under an AnalysisContext (AnalysisPolicyV2, fingerprint, UTC evaluation
    time) with a canonically resolved scope; otherwise
    non_authoritative_reasons lists the fixed reason codes, sorted. Actually
    persisting a result additionally requires engine identity authorization
    (SEC-30), which is outside this pure result.
    """
    aggregation_policy_version: str = "env-risk-v1"
    ranking_policy_version: str = "remediation-ranking-v1"
    analysis_policy_fingerprint: str | None = None
    provenance: AnalysisProvenance | None = None

    baseline_is_saturated: bool
    baseline_termination_reason: Literal["EXHAUSTED", "MAX_PATHS_REACHED"]
    is_saturated: bool
    persistence_authoritative: bool
    non_authoritative_reasons: list[NonAuthoritativeReason]

    baseline_environment_risk: float
    baseline_path_count: int

    candidates: list[CounterfactualRemediationResult]

    @model_validator(mode="after")
    def _authority_is_consistent(self) -> "EnvironmentRiskRanking":
        # ANA-7a: every saturation and authority field is derived from the
        # recorded facts (baseline and candidate saturation, provenance), so a
        # ranking that contradicts those facts cannot be constructed.
        expected_baseline_reason = "MAX_PATHS_REACHED" if self.baseline_is_saturated else "EXHAUSTED"
        if self.baseline_termination_reason != expected_baseline_reason:
            raise ValueError(
                "baseline_termination_reason must be MAX_PATHS_REACHED exactly when baseline_is_saturated"
            )

        any_counterfactual_saturated = any(c.counterfactual_is_saturated for c in self.candidates)
        if any_counterfactual_saturated and not self.baseline_is_saturated:
            raise ValueError("a saturated counterfactual requires a saturated baseline")
        if self.is_saturated != (self.baseline_is_saturated or any_counterfactual_saturated):
            raise ValueError("is_saturated must equal baseline or any candidate saturation")
        for candidate in self.candidates:
            expected_rankable = not (self.baseline_is_saturated or candidate.counterfactual_is_saturated)
            if candidate.rankable != expected_rankable:
                raise ValueError(
                    "candidate rankable must be True exactly when neither the baseline nor the "
                    "candidate saturated"
                )

        expected_fingerprint = self.provenance.policy_fingerprint if self.provenance else None
        if self.analysis_policy_fingerprint != expected_fingerprint:
            raise ValueError("analysis_policy_fingerprint must match the provenance fingerprint")

        if self.non_authoritative_reasons != sorted(set(self.non_authoritative_reasons)):
            raise ValueError("non_authoritative_reasons must be unique and sorted")
        expected_reasons = set()
        if self.baseline_is_saturated:
            expected_reasons.add(NON_AUTHORITATIVE_BASELINE_SATURATED)
        if any_counterfactual_saturated:
            expected_reasons.add(NON_AUTHORITATIVE_COUNTERFACTUAL_SATURATED)
        if self.provenance is None:
            expected_reasons.add(NON_AUTHORITATIVE_NO_ANALYSIS_CONTEXT)
        elif self.provenance.scope_id is None:
            expected_reasons.add(NON_AUTHORITATIVE_NON_CANONICAL_SCOPE)
        if self.non_authoritative_reasons != sorted(expected_reasons):
            raise ValueError(
                f"non_authoritative_reasons must be exactly {sorted(expected_reasons)} "
                f"for the recorded saturation and provenance"
            )
        if self.persistence_authoritative != (not expected_reasons):
            raise ValueError("persistence_authoritative must be True exactly when there are no reasons")
        return self

