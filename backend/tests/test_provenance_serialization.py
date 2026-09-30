"""Analytical results must survive their own JSON serialization (N2, ANA-5, SEC-22).

Categories:
- Invariant: an AnalysisProvenance, and a ranking that embeds one, round-trip
  through JSON unchanged.
- Negative: deserialization keeps the N2 guarantees: a naive or non-ISO time
  is rejected, and the value is normalized to UTC. Analysis inputs
  (normalize_evaluation_time, AnalysisContext) still accept only datetimes.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.analytics.context import AnalysisContext
from app.analytics.counterfactual import CounterfactualEngine
from app.analytics.policy import AnalysisPolicyV2
from app.graph.networkx import NetworkXStore
from app.schemas.analytics import AnalysisProvenance, AnalyticalScope, EnvironmentRiskRanking

EVAL_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
SCOPE_ID = uuid.UUID(int=9001)


def _provenance(**overrides) -> AnalysisProvenance:
    fields = {
        "policy_version": "analysis-policy-v2",
        "policy_fingerprint": "a" * 64,
        "evaluation_time": EVAL_TIME,
        "scope_id": SCOPE_ID,
        "scope_definition_version": 1,
    }
    fields.update(overrides)
    return AnalysisProvenance(**fields)


def test_provenance_round_trips_through_json():
    provenance = _provenance()
    payload = provenance.model_dump_json()
    assert '"evaluation_time":"2026-01-15T12:00:00Z"' in payload
    assert AnalysisProvenance.model_validate_json(payload) == provenance


def test_deserialized_provenance_is_normalized_to_utc():
    local = datetime(2026, 1, 15, 20, 0, tzinfo=timezone(timedelta(hours=8))).isoformat()
    restored = AnalysisProvenance.model_validate({**_provenance().model_dump(), "evaluation_time": local})
    assert restored.evaluation_time == EVAL_TIME
    assert restored.evaluation_time.tzinfo == timezone.utc


@pytest.mark.parametrize("value", ["2026-01-15T12:00:00", "15/01/2026 12:00", "", "not a time"])
def test_deserialization_rejects_naive_or_malformed_times(value):
    with pytest.raises(ValidationError):
        AnalysisProvenance.model_validate({**_provenance().model_dump(), "evaluation_time": value})


def test_analysis_inputs_still_accept_only_datetimes():
    policy = AnalysisPolicyV2(
        traversal_policy_version="traversal-policy-v1", risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-policy-v1",
        max_hops=4, traversal_budget=10, max_paths=10, allowed_edge_types=["ROUTES_TO"],
        edge_costs={"ROUTES_TO": 1},
    )
    scope = AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL")
    with pytest.raises(ValidationError, match="must be a datetime"):
        AnalysisContext(policy=policy, evaluation_time="2026-01-15T12:00:00Z", scope=scope)


def test_ranking_with_provenance_round_trips_through_json():
    U = lambda i: uuid.UUID(int=i)
    store = NetworkXStore()
    store.add_entity(U(1), "HOST", "entry", exposure="EXTERNAL")
    store.add_entity(U(2), "DATABASE", "crown", criticality="CRITICAL")
    store.add_relationship(U(10), U(1), U(2), "ROUTES_TO", "OBSERVED")
    policy = AnalysisPolicyV2(
        traversal_policy_version="traversal-policy-v1", risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-policy-v1",
        max_hops=4, traversal_budget=10, max_paths=10, allowed_edge_types=["ROUTES_TO"],
        edge_costs={"ROUTES_TO": 1},
    )
    scope = AnalyticalScope(
        input_boundary_kind="UNIVERSAL", reporting_selector="ALL", scope_id=SCOPE_ID, definition_version=1
    )
    ranking = CounterfactualEngine(store, {}).evaluate_candidates(
        U(1), U(2), [U(10)], context=AnalysisContext(policy=policy, evaluation_time=EVAL_TIME, scope=scope)
    )
    restored = EnvironmentRiskRanking.model_validate_json(ranking.model_dump_json())
    assert restored == ranking
    assert restored.model_dump_json() == ranking.model_dump_json()
