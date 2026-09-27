"""Analytical policy definitions and deterministic fingerprinting."""



import hashlib

import json

from decimal import Decimal, ROUND_HALF_UP

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from app.domain.enums import RelationshipType





class AnalysisPolicy(BaseModel):

    """Global configuration governing all analytical derivations."""

    version: Literal["analysis-policy-v1"] = "analysis-policy-v1"



    # Traversal bounds

    traversal_policy_version: str

    max_hops: int

    traversal_budget: int

    max_paths: int

    allowed_edge_types: list[str] | None

    edge_costs: dict[str, int]



    # Risk parameters

    risk_formula_version: str

    env_risk_formula_version: str

    decay_policy_version: str



    # Normalization Mappings

    criticality_map: dict[str, float]

    exposure_map: dict[str, float]

    edge_enablement_map: dict[str, float]

    confidence_map: dict[str, float]

    finding_amp_map: dict[str, float]



    model_config = ConfigDict(frozen=True)





def _canonicalize_value(val: Any, precision: int = 4) -> Any:

    """Recursively canonicalize values for deterministic hashing."""

    if isinstance(val, dict):

        return {k: _canonicalize_value(v, precision) for k, v in sorted(val.items())}

    elif isinstance(val, list):

        return [_canonicalize_value(v, precision) for v in val]

    elif isinstance(val, float) or isinstance(val, int) and not isinstance(val, bool):

        # Lossless string representation up to declared precision

        dec = Decimal(str(val))

        quantizer = Decimal("1." + "0" * precision)

        canonical = dec.quantize(quantizer, rounding=ROUND_HALF_UP).normalize()

        # format removes scientific notation

        return format(canonical, "f")

    else:

        # UUIDs, enums, strings, bools, None

        return str(val) if val is not None else None





def generate_policy_fingerprint(policy: "AnalysisPolicy | AnalysisPolicyV2") -> str:

    """Generate a deterministic SHA-256 fingerprint of the policy.



    Guarantees cross-platform determinism by enforcing strict Decimal

    canonicalization on floats and alphabetical sorting on keys.

    """

    raw_dict = policy.model_dump(mode="json")

    canonical_dict = _canonicalize_value(raw_dict, precision=4)



    json_str = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))

    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()


class AnalysisPolicyV2(BaseModel):
    """Truthful analytical policy: only genuinely tunable parameters.

    A formula version identifier denotes that formula's complete sealed
    constant set (ANA-5a). For risk-v1 this includes the criticality,
    exposure, edge enablement, confidence and finding amplification tables,
    the unknown-key fallbacks, the INFERRED multiplier, the category
    thresholds and control dampening; decay-policy-v1 fixes the decay and
    evidence-resolution rules. None of these are fields here, and
    extra="forbid" rejects any attempt to supply them, so the fingerprint
    never claims control over a constant the computation does not read.

    Canonical form (one representation per semantic policy):
    - allowed_edge_types: sorted, de-duplicated RelationshipType values;
      None ("all types") is expanded to the explicit full list.
    - edge_costs: keyed by exactly the allowed types, in sorted key order,
      so TraversalEngine's implicit per-edge default cost is never used.

    Only this policy version can authorise persistence; legacy
    AnalysisPolicy (analysis-policy-v1) cannot.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal["analysis-policy-v2"] = "analysis-policy-v2"

    # Sealed formula / policy version selectors
    traversal_policy_version: Literal["traversal-policy-v1"]
    risk_formula_version: Literal["risk-v1"]
    env_risk_formula_version: Literal["env-risk-v1"]
    decay_policy_version: Literal["decay-policy-v1"]

    # Tunable traversal parameters (ARCH-12)
    max_hops: Annotated[StrictInt, Field(ge=0)]
    traversal_budget: Annotated[StrictInt, Field(ge=0)]
    max_paths: Annotated[StrictInt, Field(ge=1)]
    allowed_edge_types: list[RelationshipType] | None
    edge_costs: dict[RelationshipType, Annotated[StrictInt, Field(ge=0)]]

    @field_validator("allowed_edge_types")
    @classmethod
    def _canonicalize_allowed_edge_types(
        cls, value: list[RelationshipType] | None
    ) -> list[RelationshipType]:
        if value is None:
            return sorted(RelationshipType, key=lambda t: t.value)
        if not value:
            raise ValueError(
                "allowed_edge_types must not be empty; use None for all relationship types"
            )
        return sorted(set(value), key=lambda t: t.value)

    @field_validator("edge_costs")
    @classmethod
    def _canonicalize_edge_costs(
        cls, value: dict[RelationshipType, int]
    ) -> dict[RelationshipType, int]:
        return {key: value[key] for key in sorted(value, key=lambda t: t.value)}

    @model_validator(mode="after")
    def _edge_costs_cover_exactly_allowed_types(self) -> "AnalysisPolicyV2":
        allowed = set(self.allowed_edge_types)
        costed = set(self.edge_costs)
        missing = sorted(t.value for t in allowed - costed)
        extra = sorted(t.value for t in costed - allowed)
        if missing:
            raise ValueError(f"edge_costs missing allowed relationship types: {missing}")
        if extra:
            raise ValueError(f"edge_costs contains relationship types that are not allowed: {extra}")
        return self


def policy_authorizes_persistence(policy: AnalysisPolicy | AnalysisPolicyV2) -> bool:
    """Whether results computed under this policy may be persisted.

    Only AnalysisPolicyV2 qualifies: its version selectors admit only the
    sealed persistable formulas (risk-v1, env-risk-v1, decay-policy-v1,
    traversal-policy-v1). Legacy AnalysisPolicy v1 never qualifies.
    """
    return isinstance(policy, AnalysisPolicyV2)
