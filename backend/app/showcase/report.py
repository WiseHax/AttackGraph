"""Typed, serializable result of a showcase run.

The report embeds the engine's own contract types (AnalysisPolicyV2,
AnalysisProvenance, RiskResult, EnvironmentRiskRanking, EngineMetadata)
rather than re-describing them, so the serialized artifact carries exactly
what the engine produced. Lists are emitted in a fixed order, so the same
fixture and evaluation time always serialize to the same bytes.
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.analytics.engine_identity import EngineMetadata
from app.analytics.policy import AnalysisPolicyV2
from app.schemas.analytics import (
    AnalysisProvenance,
    EnvironmentRiskRanking,
    NonAuthoritativeReason,
    RiskResult,
)

SHOWCASE_SCHEMA_VERSION = "attackgraph-showcase-v1"

TerminationReason = Literal["EXHAUSTED", "MAX_PATHS_REACHED"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ProjectInfo(_Frozen):
    name: str
    version: str
    schema_version: str


class EngineIdentityReport(_Frozen):
    """Engine identity as verified at run time (SEC-29, SEC-30)."""

    status: str
    persistence_authorized: bool
    metadata: EngineMetadata | None


class ScopeReport(_Frozen):
    scope_id: uuid.UUID
    definition_version: int
    display_name: str
    input_boundary_kind: str
    reporting_selector: str


class EntityReport(_Frozen):
    id: uuid.UUID
    canonical_key: str
    entity_type: str
    name: str
    description: str | None
    criticality: str | None
    exposure: str | None
    address: str | None
    finding_ids: list[uuid.UUID]


class EvidenceReport(_Frozen):
    id: uuid.UUID
    source: str
    source_type: str
    assertion: str
    collected_at: datetime | None
    freshness_ttl_seconds: int | None
    recorded_confidence: str | None
    # Confidence after decay-policy-v1 at the evaluation time (analytical, ANA-10).
    confidence_at_evaluation: str
    record: str | None
    supports_relationship_ids: list[uuid.UUID]
    supports_finding_ids: list[uuid.UUID]


class RelationshipReport(_Frozen):
    id: uuid.UUID
    source_entity_id: uuid.UUID
    target_entity_id: uuid.UUID
    relationship_type: str
    truth_tier: str
    description: str | None
    evidence_ids: list[uuid.UUID]
    # Confidence and source resolved from the evidence at evaluation time,
    # exactly as risk-v1 consumes them.
    resolved_confidence: str
    resolved_source: str
    on_baseline_path: bool


class FindingReport(_Frozen):
    """A finding and its supporting evidence.

    risk-v1 consumes only the finding's severity; supporting evidence is
    shown for lineage and is not an analytical input (CIB-5).
    """

    id: uuid.UUID
    entity_id: uuid.UUID
    title: str
    severity: str
    description: str | None
    supporting_evidence_ids: list[uuid.UUID]


class EnvironmentReport(_Frozen):
    organisation: str
    notes: list[str]
    entities: list[EntityReport]
    relationships: list[RelationshipReport]
    evidence: list[EvidenceReport]
    findings: list[FindingReport]


class ProjectionReport(_Frozen):
    """The graph projection built from the canonical records of this run."""

    entity_count: int
    relationship_count: int
    all_canonical_records_projected: bool


class AnalysisReport(_Frozen):
    source_entity_id: uuid.UUID
    target_entity_id: uuid.UUID
    evaluation_time: datetime
    policy: AnalysisPolicyV2
    provenance: AnalysisProvenance


class PathStep(_Frozen):
    relationship_id: uuid.UUID
    relationship_type: str
    truth_tier: str
    from_entity_id: uuid.UUID
    to_entity_id: uuid.UUID
    resolved_confidence: str
    resolved_source: str
    evidence_ids: list[uuid.UUID]


class PathReport(_Frozen):
    path_id: str
    node_ids: list[uuid.UUID]
    relationship_ids: list[uuid.UUID]
    hop_count: int
    steps: list[PathStep]
    risk: RiskResult


class BaselineReport(_Frozen):
    """Bounded traversal and risk under the showcase policy.

    Paths are listed in the engine's deterministic traversal order, which is
    also the order in which env-risk-v1 aggregates them.
    """

    termination_reason: TerminationReason
    is_saturated: bool
    path_count: int
    environment_risk: float
    max_path_risk: float
    paths: list[PathReport]


class RiskState(_Frozen):
    path_count: int
    environment_risk: float
    max_path_risk: float | None
    path_ids: list[str]


class RemediationReport(_Frozen):
    """Counterfactual removal of relationships on the baseline paths."""

    candidate_relationship_ids: list[uuid.UUID]
    ranking: EnvironmentRiskRanking
    featured_relationship_id: uuid.UUID
    # Candidates with exactly the featured candidate's effect (same reduction
    # and same surviving paths), e.g. relationships in series.
    equivalent_relationship_ids: list[uuid.UUID]
    before: RiskState
    after: RiskState
    removed_path_ids: list[str]
    baseline_projection_unchanged: bool


class BoundSensitivityReport(_Frozen):
    """The same analysis under a tighter enumeration limit (ANA-7, ANA-7a)."""

    policy: AnalysisPolicyV2
    policy_fingerprint: str
    baseline_termination_reason: TerminationReason
    baseline_is_saturated: bool
    baseline_path_count: int
    is_saturated: bool
    rankable_candidate_count: int
    candidate_count: int
    persistence_authoritative: bool
    non_authoritative_reasons: list[NonAuthoritativeReason]
    comparable_with_primary: bool
    comparability_detail: str


class PersistenceAuthorityReport(_Frozen):
    """Whether the preconditions for persisting this result hold.

    Persistence of analytical results is not implemented (Phase 7B); this
    only reports the two gates a future persistence path must require.
    """

    ranking_persistence_authoritative: bool
    ranking_non_authoritative_reasons: list[NonAuthoritativeReason]
    engine_status: str
    engine_persistence_authorized: bool
    preconditions_met: bool


class ShowcaseReport(_Frozen):
    project: ProjectInfo
    disclaimer: list[str]
    engine_identity: EngineIdentityReport
    scope: ScopeReport
    analysis: AnalysisReport
    environment: EnvironmentReport
    projection: ProjectionReport
    baseline: BaselineReport
    remediation: RemediationReport
    bound_sensitivity: BoundSensitivityReport
    persistence: PersistenceAuthorityReport
