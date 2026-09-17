"""Analytical policy definitions and deterministic fingerprinting."""



import hashlib

import json

from decimal import Decimal, ROUND_HALF_UP

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict





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





def generate_policy_fingerprint(policy: AnalysisPolicy) -> str:

    """Generate a deterministic SHA-256 fingerprint of the policy.



    Guarantees cross-platform determinism by enforcing strict Decimal

    canonicalization on floats and alphabetical sorting on keys.

    """

    raw_dict = policy.model_dump(mode="json")

    canonical_dict = _canonicalize_value(raw_dict, precision=4)



    json_str = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))

    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()
