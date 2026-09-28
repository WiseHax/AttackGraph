"""Tests for explicit, timezone-aware evaluation time and analysis provenance (N2, ANA-3, SEC-22).

Categories:
- Negative: naive or non-datetime evaluation times are rejected everywhere
  analytical code accepts one (normalizer, context, provenance, decay,
  counterfactual); there is no current-time fallback.
- Determinism: equivalent instants in different timezones produce identical
  decay decisions and byte-identical counterfactual output.
- Invariant: provenance records the V2 policy version and fingerprint, the
  canonical UTC evaluation time, and the resolved scope identity (or none for
  an ad-hoc scope).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.analytics.context import AnalysisContext
from app.analytics.counterfactual import CounterfactualEngine
from app.analytics.decay import apply_decay, resolve_edge_evidence
from app.analytics.policy import AnalysisPolicy, AnalysisPolicyV2, generate_policy_fingerprint
from app.graph.networkx import NetworkXStore
from app.schemas.analytics import AnalysisProvenance, AnalyticalScope, normalize_evaluation_time

UTC_TIME = datetime(2026, 1, 1, 4, 0, 0, tzinfo=timezone.utc)
PLUS_EIGHT = timezone(timedelta(hours=8))
PLUS_EIGHT_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=PLUS_EIGHT)  # same instant as UTC_TIME
NAIVE_TIME = datetime(2026, 1, 1, 4, 0, 0)

SCOPE_ID = uuid.UUID(int=77)
AD_HOC_SCOPE = AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL")
RESOLVED_SCOPE = AnalyticalScope(
    input_boundary_kind="UNIVERSAL", reporting_selector="ALL", scope_id=SCOPE_ID, definition_version=2
)


def _policy() -> AnalysisPolicyV2:
    return AnalysisPolicyV2(
        traversal_policy_version="traversal-policy-v1", risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-policy-v1",
        max_hops=6, traversal_budget=10, max_paths=100,
        allowed_edge_types=["EXPOSES", "ROUTES_TO"], edge_costs={"EXPOSES": 1, "ROUTES_TO": 2},
    )


# --- normalize_evaluation_time -------------------------------------------------

def test_naive_evaluation_time_is_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_evaluation_time(NAIVE_TIME)


@pytest.mark.parametrize("value", [None, "2026-01-01T04:00:00Z", 1767240000.0])
def test_non_datetime_evaluation_time_is_rejected(value):
    with pytest.raises(ValueError, match="must be a datetime"):
        normalize_evaluation_time(value)


def test_aware_evaluation_time_is_accepted_unchanged_in_utc():
    assert normalize_evaluation_time(UTC_TIME) == UTC_TIME
    assert normalize_evaluation_time(UTC_TIME).tzinfo == timezone.utc


def test_plus_eight_is_normalized_to_the_same_utc_instant():
    normalized = normalize_evaluation_time(PLUS_EIGHT_TIME)
    assert normalized.tzinfo == timezone.utc
    assert normalized == UTC_TIME
    assert (normalized.year, normalized.month, normalized.day, normalized.hour) == (2026, 1, 1, 4)


# --- AnalysisContext / AnalysisProvenance --------------------------------------

def test_context_normalizes_evaluation_time_to_utc():
    context = AnalysisContext(policy=_policy(), evaluation_time=PLUS_EIGHT_TIME, scope=RESOLVED_SCOPE)
    assert context.evaluation_time.tzinfo == timezone.utc
    assert context.evaluation_time == UTC_TIME


def test_context_rejects_naive_evaluation_time():
    with pytest.raises(ValidationError, match="timezone-aware"):
        AnalysisContext(policy=_policy(), evaluation_time=NAIVE_TIME, scope=RESOLVED_SCOPE)


def test_context_requires_v2_policy_and_real_instances():
    legacy = AnalysisPolicy(
        traversal_policy_version="v1", max_hops=6, traversal_budget=10, max_paths=100,
        allowed_edge_types=["EXPOSES"], edge_costs={"EXPOSES": 1}, risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-v1",
        criticality_map={}, exposure_map={}, edge_enablement_map={}, confidence_map={}, finding_amp_map={},
    )
    with pytest.raises(ValidationError):
        AnalysisContext(policy=legacy, evaluation_time=UTC_TIME, scope=RESOLVED_SCOPE)
    with pytest.raises(ValidationError):
        AnalysisContext(policy=_policy().model_dump(), evaluation_time=UTC_TIME, scope=RESOLVED_SCOPE)
    with pytest.raises(ValidationError):
        AnalysisContext(
            policy=_policy(), evaluation_time=UTC_TIME,
            scope={"input_boundary_kind": "UNIVERSAL", "reporting_selector": "ALL",
                   "scope_id": str(SCOPE_ID), "definition_version": 1},
        )


def test_context_is_immutable():
    context = AnalysisContext(policy=_policy(), evaluation_time=UTC_TIME, scope=RESOLVED_SCOPE)
    with pytest.raises(ValidationError):
        context.evaluation_time = PLUS_EIGHT_TIME


def test_provenance_records_policy_utc_time_and_resolved_scope_identity():
    provenance = AnalysisContext(
        policy=_policy(), evaluation_time=PLUS_EIGHT_TIME, scope=RESOLVED_SCOPE
    ).provenance()

    assert provenance.policy_version == "analysis-policy-v2"
    assert provenance.policy_fingerprint == generate_policy_fingerprint(_policy())
    assert provenance.evaluation_time == UTC_TIME
    assert provenance.evaluation_time.tzinfo == timezone.utc
    assert provenance.scope_id == SCOPE_ID
    assert provenance.scope_definition_version == 2
    assert '"evaluation_time":"2026-01-01T04:00:00Z"' in provenance.model_dump_json()


def test_provenance_for_ad_hoc_scope_has_no_scope_identity():
    provenance = AnalysisContext(policy=_policy(), evaluation_time=UTC_TIME, scope=AD_HOC_SCOPE).provenance()
    assert provenance.scope_id is None
    assert provenance.scope_definition_version is None


def test_provenance_is_identical_for_equivalent_instants():
    a = AnalysisContext(policy=_policy(), evaluation_time=UTC_TIME, scope=RESOLVED_SCOPE).provenance()
    b = AnalysisContext(policy=_policy(), evaluation_time=PLUS_EIGHT_TIME, scope=RESOLVED_SCOPE).provenance()
    assert a.model_dump_json() == b.model_dump_json()


@pytest.mark.parametrize(
    "overrides",
    [
        {"evaluation_time": NAIVE_TIME},
        {"policy_fingerprint": "not-a-sha256"},
        {"scope_id": SCOPE_ID},
        {"scope_definition_version": 1},
        {"unexpected": True},
    ],
)
def test_provenance_rejects_invalid_records(overrides):
    kwargs = {
        "policy_version": "analysis-policy-v2",
        "policy_fingerprint": "0" * 64,
        "evaluation_time": UTC_TIME,
        **overrides,
    }
    with pytest.raises(ValidationError):
        AnalysisProvenance(**kwargs)


# --- decay (J-3 evaluation clock) -----------------------------------------------

def test_decay_still_requires_an_evaluation_time():
    """J-3: evaluation time is mandatory; there is no current-time fallback."""
    with pytest.raises(ValueError, match="must be provided"):
        apply_decay({"confidence": "HIGH"}, None)


def test_decay_rejects_naive_evaluation_time():
    evidence = {"confidence": "HIGH", "collected_at": UTC_TIME - timedelta(days=1), "freshness_ttl_seconds": 60}
    with pytest.raises(ValueError, match="timezone-aware"):
        apply_decay(evidence, NAIVE_TIME)


def test_decay_rejects_naive_collected_at():
    evidence = {"confidence": "HIGH", "collected_at": NAIVE_TIME, "freshness_ttl_seconds": 60}
    with pytest.raises(ValueError, match="collected_at must be timezone-aware"):
        apply_decay(evidence, UTC_TIME)


@pytest.mark.parametrize(
    "age, ttl",
    [
        (timedelta(hours=1), 3600),                 # exact boundary: not stale
        (timedelta(hours=1, seconds=1), 3600),      # just stale
        (timedelta(days=10), 3600),                 # long stale
        (timedelta(days=1), None),                  # no TTL: exempt
    ],
)
def test_decay_is_identical_for_equivalent_timezone_aware_times(age, ttl):
    for confidence in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        evidence_utc = {"confidence": confidence, "collected_at": UTC_TIME - age, "freshness_ttl_seconds": ttl}
        evidence_local = {
            "confidence": confidence,
            "collected_at": (UTC_TIME - age).astimezone(PLUS_EIGHT),
            "freshness_ttl_seconds": ttl,
        }
        expected = apply_decay(evidence_utc, UTC_TIME)
        assert apply_decay(evidence_utc, PLUS_EIGHT_TIME) == expected
        assert apply_decay(evidence_local, PLUS_EIGHT_TIME) == expected
        assert apply_decay(evidence_local, UTC_TIME) == expected


def test_edge_resolution_is_identical_for_equivalent_timezone_aware_times():
    evidence = [
        {"confidence": "HIGH", "source": "scanner-a", "collected_at": UTC_TIME - timedelta(days=2),
         "freshness_ttl_seconds": 86400},
        {"confidence": "MEDIUM", "source": "scanner-b",
         "collected_at": (UTC_TIME - timedelta(days=1)).astimezone(PLUS_EIGHT), "freshness_ttl_seconds": 3600},
    ]
    assert resolve_edge_evidence(evidence, "e", "OBSERVED", UTC_TIME) == \
        resolve_edge_evidence(evidence, "e", "OBSERVED", PLUS_EIGHT_TIME)


# --- counterfactual ---------------------------------------------------------------

def _store() -> NetworkXStore:
    U = lambda i: uuid.UUID(int=i)
    store = NetworkXStore()
    store.add_entity(U(1), "HOST", "entry", exposure="EXTERNAL")
    store.add_entity(U(2), "HOST", "mid")
    store.add_entity(U(3), "DATABASE", "crown", criticality="CRITICAL")
    evidence = [{"id": U(900), "source": "synthetic", "source_type": "t",
                 "collected_at": UTC_TIME - timedelta(hours=2), "freshness_ttl_seconds": 3600,
                 "confidence": "HIGH"}]
    store.add_relationship(U(101), U(1), U(2), "EXPOSES", "OBSERVED", raw_evidence=evidence)
    store.add_relationship(U(102), U(2), U(3), "ROUTES_TO", "OBSERVED", raw_evidence=evidence)
    store.add_relationship(U(103), U(1), U(3), "CAN_AUTHENTICATE_TO", "OBSERVED")
    return store


def test_counterfactual_rejects_naive_evaluation_time():
    engine = CounterfactualEngine(_store(), {})
    with pytest.raises(ValueError, match="timezone-aware"):
        engine.evaluate_candidates(uuid.UUID(int=1), uuid.UUID(int=3), [uuid.UUID(int=101)], NAIVE_TIME)


def test_counterfactual_output_is_identical_for_equivalent_instants():
    candidates = [uuid.UUID(int=i) for i in (101, 102, 103)]
    utc = CounterfactualEngine(_store(), {}).evaluate_candidates(
        uuid.UUID(int=1), uuid.UUID(int=3), candidates, UTC_TIME
    )
    local = CounterfactualEngine(_store(), {}).evaluate_candidates(
        uuid.UUID(int=1), uuid.UUID(int=3), candidates, PLUS_EIGHT_TIME
    )
    assert utc.model_dump_json() == local.model_dump_json()
