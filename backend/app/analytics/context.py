"""Analysis context: the explicit inputs that define an analytical run.

Lives in the analysis layer (not app.schemas) because it holds an
AnalysisPolicyV2; the projection layer imports app.schemas and must not
depend on analysis-layer modules (ARCH-1).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.analytics.policy import AnalysisPolicyV2, generate_policy_fingerprint
from app.schemas.analytics import AnalysisProvenance, AnalyticalScope, normalize_evaluation_time


class AnalysisContext(BaseModel):
    """Immutable carrier of policy, evaluation time and scope for one run.

    - policy: must be AnalysisPolicyV2 (legacy v1 is rejected).
    - evaluation_time: timezone-aware, normalized to canonical UTC; naive
      datetimes are rejected and there is no current-time fallback.
    - scope: canonically resolved (ARCH-28) for a persistable run; an ad-hoc
      scope is accepted for non-persisted analysis and yields provenance
      without scope identity.
    """

    policy: AnalysisPolicyV2
    evaluation_time: datetime
    scope: AnalyticalScope

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("policy", mode="before")
    @classmethod
    def _require_policy_instance(cls, value: object) -> AnalysisPolicyV2:
        # Never coerce a dict or another policy version into a V2 policy.
        if not isinstance(value, AnalysisPolicyV2):
            raise ValueError("policy must be an AnalysisPolicyV2 instance")
        return value

    @field_validator("scope", mode="before")
    @classmethod
    def _require_scope_instance(cls, value: object) -> AnalyticalScope:
        # Scope identity must come from a real AnalyticalScope (ARCH-28), not a dict.
        if not isinstance(value, AnalyticalScope):
            raise ValueError("scope must be an AnalyticalScope instance")
        return value

    @field_validator("evaluation_time", mode="before")
    @classmethod
    def _canonical_utc(cls, value: datetime) -> datetime:
        return normalize_evaluation_time(value)

    def provenance(self) -> AnalysisProvenance:
        """The provenance record for results computed under this context."""
        return AnalysisProvenance(
            policy_version=self.policy.version,
            policy_fingerprint=generate_policy_fingerprint(self.policy),
            evaluation_time=self.evaluation_time,
            scope_id=self.scope.scope_id,
            scope_definition_version=self.scope.definition_version,
        )
