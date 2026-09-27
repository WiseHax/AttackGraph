"""Tests for AnalysisPolicyV2 policy truthfulness (C3, ANA-5, ANA-5a, ARCH-20).

Categories:
- Invariant: V2 cannot express sealed formula constants; unsupported version
  selectors and incomplete policies are rejected; v1 never authorises
  persistence; v1/v2 are never comparable.
- Determinism: canonical form and fingerprint are independent of input
  ordering and of the process hash seed; the canonical fingerprint is pinned.
- Invariant (drift guard): the constants RiskEngine / decay actually use equal
  the documented sealed identity of risk-v1 / decay-policy-v1.
"""

import os
import subprocess
import sys
import uuid

import pytest
from pydantic import ValidationError

from app.analytics import decay, risk_engine
from app.analytics.comparability import ComparabilityError, verify_comparability
from app.analytics.policy import (
    AnalysisPolicy,
    AnalysisPolicyV2,
    generate_policy_fingerprint,
    policy_authorizes_persistence,
)
from app.analytics.risk_engine import RiskEngine
from app.domain.enums import RelationshipType
from app.schemas.analytics import AttackPath, FindingRiskInput, RiskInput

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..")

ALL_RELATIONSHIP_TYPES = sorted(t.value for t in RelationshipType)

# Pinned fingerprint of canonical_kwargs(). A change here means the canonical
# serialization of AnalysisPolicyV2 changed, which silently breaks
# comparability with every previously recorded fingerprint.
CANONICAL_V2_FINGERPRINT = "03771a2f90993fda605a4ddc8ae90ef2dc434ba9296eb53ebd6fef1fa9ce66d4"


def canonical_kwargs(**overrides) -> dict:
    kwargs = {
        "traversal_policy_version": "traversal-policy-v1",
        "risk_formula_version": "risk-v1",
        "env_risk_formula_version": "env-risk-v1",
        "decay_policy_version": "decay-policy-v1",
        "max_hops": 6,
        "traversal_budget": 10,
        "max_paths": 100,
        "allowed_edge_types": ["EXPOSES", "ROUTES_TO"],
        "edge_costs": {"EXPOSES": 1, "ROUTES_TO": 2},
    }
    kwargs.update(overrides)
    return kwargs


def legacy_v1_policy() -> AnalysisPolicy:
    return AnalysisPolicy(
        traversal_policy_version="v1", max_hops=6, traversal_budget=10, max_paths=100,
        allowed_edge_types=["EXPOSES"], edge_costs={"EXPOSES": 1}, risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-v1",
        criticality_map={"CRITICAL": 1.0}, exposure_map={"EXTERNAL": 1.0},
        edge_enablement_map={"EXPOSES": 0.8}, confidence_map={"HIGH": 1.0},
        finding_amp_map={"CRITICAL": 0.5},
    )


# --- Acceptance and canonical form ------------------------------------------

def test_canonical_v2_policy_is_accepted():
    policy = AnalysisPolicyV2(**canonical_kwargs())
    assert policy.version == "analysis-policy-v2"
    assert [t.value for t in policy.allowed_edge_types] == ["EXPOSES", "ROUTES_TO"]
    assert {k.value: v for k, v in policy.edge_costs.items()} == {"EXPOSES": 1, "ROUTES_TO": 2}


def test_canonical_v2_fingerprint_is_pinned():
    assert generate_policy_fingerprint(AnalysisPolicyV2(**canonical_kwargs())) == CANONICAL_V2_FINGERPRINT


def test_v2_policy_is_immutable():
    policy = AnalysisPolicyV2(**canonical_kwargs())
    with pytest.raises(ValidationError):
        policy.max_hops = 7


# --- Rejection: unknown fields, sealed constants, selectors, components ------

def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AnalysisPolicyV2(**canonical_kwargs(max_depth=4))


@pytest.mark.parametrize(
    "sealed_field, value",
    [
        ("criticality_map", {"CRITICAL": 1.0}),
        ("exposure_map", {"EXTERNAL": 1.0}),
        ("edge_enablement_map", {"EXPOSES": 0.8}),
        ("confidence_map", {"HIGH": 1.0}),
        ("finding_amp_map", {"CRITICAL": 0.5}),
        ("inferred_confidence_multiplier", 0.8),
        ("category_thresholds", [0.25, 0.5, 0.75]),
        ("control_dampening", 1.0),
    ],
)
def test_sealed_formula_constant_override_is_rejected(sealed_field, value):
    """risk-v1 constants belong to the formula version identity, not to the policy."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AnalysisPolicyV2(**canonical_kwargs(**{sealed_field: value}))


@pytest.mark.parametrize(
    "selector, unsupported",
    [
        ("traversal_policy_version", "v1"),
        ("traversal_policy_version", "traversal-policy-v2"),
        ("risk_formula_version", "risk-v2"),
        ("risk_formula_version", "RISK-V1"),
        ("env_risk_formula_version", "env-risk-v2"),
        ("decay_policy_version", "decay-v1"),
        ("version", "analysis-policy-v1"),
    ],
)
def test_unsupported_version_selector_is_rejected(selector, unsupported):
    with pytest.raises(ValidationError):
        AnalysisPolicyV2(**canonical_kwargs(**{selector: unsupported}))


@pytest.mark.parametrize(
    "required_field",
    [
        "traversal_policy_version",
        "risk_formula_version",
        "env_risk_formula_version",
        "decay_policy_version",
        "max_hops",
        "traversal_budget",
        "max_paths",
        "allowed_edge_types",
        "edge_costs",
    ],
)
def test_missing_required_component_is_rejected(required_field):
    kwargs = canonical_kwargs()
    del kwargs[required_field]
    with pytest.raises(ValidationError, match="Field required"):
        AnalysisPolicyV2(**kwargs)


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_hops": -1},
        {"traversal_budget": -1},
        {"max_paths": 0},
        {"max_hops": "6"},
        {"max_hops": 6.0},
        {"max_paths": True},
        {"edge_costs": {"EXPOSES": -1, "ROUTES_TO": 2}},
        {"edge_costs": {"EXPOSES": 1.5, "ROUTES_TO": 2}},
        {"allowed_edge_types": []},
        {"allowed_edge_types": ["EXPOSES", "LATERAL_MOVE"], "edge_costs": {"EXPOSES": 1, "LATERAL_MOVE": 1}},
    ],
)
def test_invalid_tunable_values_are_rejected(overrides):
    with pytest.raises(ValidationError):
        AnalysisPolicyV2(**canonical_kwargs(**overrides))


def test_edge_costs_missing_an_allowed_type_is_rejected():
    """A missing cost would silently fall back to TraversalEngine's implicit default."""
    with pytest.raises(ValidationError, match="edge_costs missing allowed relationship types"):
        AnalysisPolicyV2(**canonical_kwargs(edge_costs={"EXPOSES": 1}))


def test_edge_costs_for_non_allowed_type_is_rejected():
    """A cost for a type that is never traversed would change the fingerprint but not the result."""
    with pytest.raises(ValidationError, match="not allowed"):
        AnalysisPolicyV2(**canonical_kwargs(edge_costs={"EXPOSES": 1, "ROUTES_TO": 2, "TRUSTS": 3}))


# --- Persistence authorisation ----------------------------------------------

def test_only_v2_authorizes_persistence():
    assert policy_authorizes_persistence(AnalysisPolicyV2(**canonical_kwargs())) is True
    assert policy_authorizes_persistence(legacy_v1_policy()) is False


def test_risk_v2_cannot_authorize_persistence():
    """risk-v2 is expressible only through legacy v1, which never authorises persistence."""
    with pytest.raises(ValidationError):
        AnalysisPolicyV2(**canonical_kwargs(risk_formula_version="risk-v2"))
    legacy_risk_v2 = legacy_v1_policy().model_copy(update={"risk_formula_version": "risk-v2"})
    assert policy_authorizes_persistence(legacy_risk_v2) is False


# --- Canonicalization and fingerprint determinism ---------------------------

def test_allowed_edge_types_canonicalization_is_order_independent():
    a = AnalysisPolicyV2(**canonical_kwargs(allowed_edge_types=["ROUTES_TO", "EXPOSES"]))
    b = AnalysisPolicyV2(**canonical_kwargs(allowed_edge_types=["EXPOSES", "ROUTES_TO", "EXPOSES"]))
    c = AnalysisPolicyV2(**canonical_kwargs(allowed_edge_types=[RelationshipType.ROUTES_TO, "EXPOSES"]))
    assert a.allowed_edge_types == b.allowed_edge_types == c.allowed_edge_types
    assert generate_policy_fingerprint(a) == generate_policy_fingerprint(b) == generate_policy_fingerprint(c)


def test_all_types_none_is_equivalent_to_explicit_full_list():
    costs = {t: 1 for t in ALL_RELATIONSHIP_TYPES}
    implicit = AnalysisPolicyV2(**canonical_kwargs(allowed_edge_types=None, edge_costs=costs))
    explicit = AnalysisPolicyV2(
        **canonical_kwargs(allowed_edge_types=list(reversed(ALL_RELATIONSHIP_TYPES)), edge_costs=costs)
    )
    assert [t.value for t in implicit.allowed_edge_types] == ALL_RELATIONSHIP_TYPES
    assert generate_policy_fingerprint(implicit) == generate_policy_fingerprint(explicit)


def test_edge_costs_canonicalization_is_deterministic():
    a = AnalysisPolicyV2(**canonical_kwargs(edge_costs={"ROUTES_TO": 2, "EXPOSES": 1}))
    b = AnalysisPolicyV2(**canonical_kwargs(edge_costs={"EXPOSES": 1, "ROUTES_TO": 2}))
    assert list(a.edge_costs) == list(b.edge_costs) == [RelationshipType.EXPOSES, RelationshipType.ROUTES_TO]
    assert a.model_dump_json() == b.model_dump_json()
    assert generate_policy_fingerprint(a) == generate_policy_fingerprint(b)


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_hops": 7},
        {"traversal_budget": 11},
        {"max_paths": 101},
        {"edge_costs": {"EXPOSES": 1, "ROUTES_TO": 3}},
        {"allowed_edge_types": ["EXPOSES"], "edge_costs": {"EXPOSES": 1}},
        {"allowed_edge_types": ["EXPOSES", "ROUTES_TO", "TRUSTS"],
         "edge_costs": {"EXPOSES": 1, "ROUTES_TO": 2, "TRUSTS": 1}},
    ],
)
def test_fingerprint_changes_for_every_material_field(overrides):
    base = generate_policy_fingerprint(AnalysisPolicyV2(**canonical_kwargs()))
    changed = generate_policy_fingerprint(AnalysisPolicyV2(**canonical_kwargs(**overrides)))
    assert changed != base


def test_v2_fingerprint_is_byte_identical_across_hash_seeds():
    script = (
        "import sys\n"
        "from app.analytics.policy import AnalysisPolicyV2, generate_policy_fingerprint\n"
        "p = AnalysisPolicyV2(traversal_policy_version='traversal-policy-v1', risk_formula_version='risk-v1',\n"
        "    env_risk_formula_version='env-risk-v1', decay_policy_version='decay-policy-v1',\n"
        "    max_hops=6, traversal_budget=10, max_paths=100,\n"
        "    allowed_edge_types=['ROUTES_TO', 'EXPOSES'], edge_costs={'ROUTES_TO': 2, 'EXPOSES': 1})\n"
        "sys.stdout.write(p.model_dump_json() + '\\n' + generate_policy_fingerprint(p))\n"
    )
    outputs = set()
    for seed in ["0", "1", "2", "12345"]:
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=BACKEND_DIR, env=env, capture_output=True
        )
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        outputs.add(result.stdout)
    assert len(outputs) == 1
    assert outputs.pop().decode("utf-8").endswith(CANONICAL_V2_FINGERPRINT)


# --- Comparability ------------------------------------------------------------

def test_matching_v2_policies_are_comparable():
    verify_comparability(
        AnalysisPolicyV2(**canonical_kwargs()),
        AnalysisPolicyV2(**canonical_kwargs(allowed_edge_types=["ROUTES_TO", "EXPOSES"])),
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_hops": 7},
        {"traversal_budget": 11},
        {"max_paths": 101},
        {"edge_costs": {"EXPOSES": 1, "ROUTES_TO": 3}},
        {"allowed_edge_types": ["EXPOSES"], "edge_costs": {"EXPOSES": 1}},
    ],
)
def test_v2_policy_mismatch_is_not_comparable(overrides):
    with pytest.raises(ComparabilityError, match="Fingerprint mismatch"):
        verify_comparability(
            AnalysisPolicyV2(**canonical_kwargs()),
            AnalysisPolicyV2(**canonical_kwargs(**overrides)),
        )


def test_v1_and_v2_are_not_comparable():
    v1, v2 = legacy_v1_policy(), AnalysisPolicyV2(**canonical_kwargs())
    with pytest.raises(ComparabilityError, match="Incompatible analytical policy versions"):
        verify_comparability(v1, v2)
    with pytest.raises(ComparabilityError, match="Incompatible analytical policy versions"):
        verify_comparability(v2, v1)


def test_unsupported_policy_type_fails_closed():
    with pytest.raises(ComparabilityError, match="Unsupported analytical policy type"):
        verify_comparability(AnalysisPolicyV2(**canonical_kwargs()), {"version": "analysis-policy-v2"})


# --- Sealed constant drift guard ------------------------------------------------

# Documented sealed identity of risk-v1 (ANALYTICAL_INTEGRITY_RULES ANA-5a).
RISK_V1_CRITICALITY = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4, "INFO": 0.2}
RISK_V1_EXPOSURE = {"EXTERNAL": 1.0, "INTERNAL": 0.8, "RESTRICTED": 0.5, "ISOLATED": 0.2}
RISK_V1_EDGE_ENABLEMENT = {
    "CAN_AUTHENTICATE_TO": 1.0, "RUNS_AS": 1.0, "HAS_PERMISSION_ON": 1.0, "CAN_ASSUME": 1.0,
    "TRUSTS": 0.9, "EXPOSES": 0.8, "STORES": 0.8, "ROUTES_TO": 0.6, "COMMUNICATES_WITH": 0.6,
    "DEPENDS_ON": 0.4, "MEMBER_OF": 0.4,
}
RISK_V1_CONFIDENCE = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5, "UNKNOWN": 0.2}
RISK_V1_FINDING_AMP = {"CRITICAL": 0.5, "HIGH": 0.4, "MEDIUM": 0.3, "LOW": 0.2, "INFO": 0.0}
DECAY_POLICY_V1_CONFIDENCE_TIERS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH"]


def test_risk_v1_constant_tables_match_sealed_identity():
    assert risk_engine.CRITICALITY_MAP == RISK_V1_CRITICALITY
    assert risk_engine.EXPOSURE_MAP == RISK_V1_EXPOSURE
    assert risk_engine.EDGE_ENABLEMENT_MAP == RISK_V1_EDGE_ENABLEMENT
    assert risk_engine.CONFIDENCE_MAP == RISK_V1_CONFIDENCE
    assert risk_engine.FINDING_AMP_MAP == RISK_V1_FINDING_AMP
    # Every canonical relationship type has a sealed enablement value, so the
    # unknown-type fallback is never reached for canonical data.
    assert sorted(risk_engine.EDGE_ENABLEMENT_MAP) == ALL_RELATIONSHIP_TYPES


def test_decay_policy_v1_confidence_tiers_match_sealed_identity():
    assert decay.CONFIDENCE_TIERS == DECAY_POLICY_V1_CONFIDENCE_TIERS


def _risk(crit, exp, edge_type="CAN_AUTHENTICATE_TO", conf="HIGH", tier="OBSERVED", findings=()):
    nodes = [uuid.UUID(int=1), uuid.UUID(int=2)]
    path = AttackPath(node_ids=nodes, edge_ids=[uuid.UUID(int=10)])
    return RiskEngine.calculate(RiskInput(
        path=path, target_criticality=crit, entry_exposure=exp, edge_types=[edge_type],
        edge_confidences=[conf], edge_truth_tiers=[tier], edge_sources=["synthetic"],
        findings=[FindingRiskInput(finding_id=uuid.UUID(int=100 + i), entity_id=nodes[0], severity=s)
                  for i, s in enumerate(findings)],
    ))


def test_risk_v1_inline_constants_match_sealed_identity():
    """Constants inlined in RiskEngine.calculate, pinned through their observable effect."""
    # Unknown-key fallbacks: criticality 0.1, exposure 0.1, edge enablement 0.4, confidence 0.2.
    fallback = _risk(None, None, edge_type="NOT_A_RELATIONSHIP_TYPE", conf=None)
    assert fallback.target_criticality.value == 0.1
    assert fallback.entry_exposure.value == 0.1
    assert fallback.edge_enablement.value == 0.4
    assert fallback.confidence.value == 0.2
    # INFERRED multiplier 0.8 and control dampening 1.0.
    inferred = _risk("CRITICAL", "EXTERNAL", tier="INFERRED")
    assert inferred.confidence.value == 0.8
    assert inferred.control_dampening.value == 1.0
    # Category thresholds 0.25 / 0.50 / 0.75 (lower bound inclusive).
    cases = [
        (_risk("CRITICAL", "EXTERNAL", edge_type="DEPENDS_ON", conf="LOW"), 0.2, "LOW"),
        (_risk("CRITICAL", "RESTRICTED", conf="LOW"), 0.25, "MEDIUM"),
        (_risk("CRITICAL", "EXTERNAL", edge_type="DEPENDS_ON"), 0.4, "MEDIUM"),
        (_risk("CRITICAL", "EXTERNAL", conf="LOW"), 0.5, "HIGH"),
        (_risk("CRITICAL", "EXTERNAL", conf="LOW", findings=["HIGH"]), 0.7, "HIGH"),
        (_risk("CRITICAL", "EXTERNAL", conf="LOW", findings=["CRITICAL"]), 0.75, "CRITICAL"),
    ]
    for result, expected_risk, expected_category in cases:
        assert result.numeric_risk == expected_risk
        assert result.category == expected_category
