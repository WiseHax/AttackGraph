"""Counterfactual policy propagation and saturation semantics (C1, C4, ANA-7a, ARCH-12).

Categories:
- Invariant: saturation is recorded for the baseline and every candidate; a
  saturated counterfactual implies a saturated baseline; rankability and the
  ranking-level flag follow from them; persistence authority requires an
  unsaturated run under an AnalysisContext with canonical scope identity.
- Semantic: with an AnalysisContext, one AnalysisPolicyV2 bounds the baseline
  and every counterfactual, including traversal_budget.
- Negative: explicit bounds conflicting with an AnalysisContext are rejected.
- Regression: the legacy no-context path keeps its numbers and bounds.
- Determinism: context-mode output is byte-identical across hash seeds.
"""

import os
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import app.analytics.counterfactual as counterfactual_module
from app.analytics.context import AnalysisContext
from app.analytics.counterfactual import CounterfactualEngine
from app.analytics.policy import AnalysisPolicyV2, generate_policy_fingerprint
from app.domain.enums import RelationshipType
from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import TraversalEngine
from app.schemas.analytics import AnalyticalScope, EnvironmentRiskRanking

EVAL_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCOPE_ID = uuid.UUID(int=4242)
RESOLVED_SCOPE = AnalyticalScope(
    input_boundary_kind="UNIVERSAL", reporting_selector="ALL", scope_id=SCOPE_ID, definition_version=1
)
AD_HOC_SCOPE = AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL")
ALL_TYPES = sorted(t.value for t in RelationshipType)
BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..")


def U(i: int) -> uuid.UUID:
    return uuid.UUID(int=i)


# Seven simple paths from 1 to 5 through 2, 3 and 4.
MESH_EDGES = [
    (201, 1, 2, "ROUTES_TO"),
    (202, 1, 3, "EXPOSES"),
    (203, 1, 4, "CAN_AUTHENTICATE_TO"),
    (204, 2, 5, "ROUTES_TO"),
    (205, 3, 5, "TRUSTS"),
    (206, 4, 5, "STORES"),
    (207, 2, 3, "ROUTES_TO"),
    (208, 3, 4, "DEPENDS_ON"),
    (209, 2, 4, "MEMBER_OF"),
]
MESH_CANDIDATES = [U(rel_id) for rel_id, *_ in MESH_EDGES]


def mesh_store() -> NetworkXStore:
    store = NetworkXStore()
    for i in range(1, 6):
        store.add_entity(U(i), "HOST", f"host-{i}", criticality="HIGH", exposure="EXTERNAL")
    for rel_id, src, dst, rel_type in MESH_EDGES:
        store.add_relationship(U(rel_id), U(src), U(dst), rel_type, "OBSERVED")
    return store


def policy(**overrides) -> AnalysisPolicyV2:
    kwargs = {
        "traversal_policy_version": "traversal-policy-v1",
        "risk_formula_version": "risk-v1",
        "env_risk_formula_version": "env-risk-v1",
        "decay_policy_version": "decay-policy-v1",
        "max_hops": 6,
        "traversal_budget": 100,
        "max_paths": 100,
        "allowed_edge_types": None,
        "edge_costs": {t: 1 for t in ALL_TYPES},
    }
    kwargs.update(overrides)
    return AnalysisPolicyV2(**kwargs)


def context(analysis_policy=None, scope=RESOLVED_SCOPE) -> AnalysisContext:
    return AnalysisContext(policy=analysis_policy or policy(), evaluation_time=EVAL_TIME, scope=scope)


def legacy(store, max_paths=100, **kwargs) -> EnvironmentRiskRanking:
    return CounterfactualEngine(store, {}).evaluate_candidates(
        U(1), U(5), MESH_CANDIDATES, EVAL_TIME, max_paths=max_paths, **kwargs
    )


# --- C1: saturation recording and propagation -------------------------------

def test_unsaturated_run_records_exhausted_baseline_and_candidates():
    ranking = legacy(mesh_store())
    assert ranking.baseline_path_count == 7
    assert ranking.baseline_is_saturated is False
    assert ranking.baseline_termination_reason == "EXHAUSTED"
    assert ranking.is_saturated is False
    for c in ranking.candidates:
        assert c.counterfactual_is_saturated is False
        assert c.counterfactual_termination_reason == "EXHAUSTED"
        assert c.rankable is True


def test_baseline_saturation_propagates_to_every_candidate_and_the_ranking():
    ranking = legacy(mesh_store(), max_paths=2)
    assert ranking.baseline_is_saturated is True
    assert ranking.baseline_termination_reason == "MAX_PATHS_REACHED"
    assert ranking.is_saturated is True
    assert ranking.persistence_authoritative is False
    assert "BASELINE_SATURATED" in ranking.non_authoritative_reasons
    assert all(c.rankable is False for c in ranking.candidates)
    # Numbers are still produced for a saturated run.
    assert ranking.baseline_environment_risk > 0.0
    assert all(c.counterfactual_environment_risk >= 0.0 for c in ranking.candidates)


def test_counterfactual_saturation_is_recorded_per_candidate():
    # Unbounded, the 9 single-edge removals leave 3, 3, 5, 5, 5, 5, 6, 6, 6
    # paths, so max_paths=6 saturates exactly three candidates.
    max_paths = 6
    ranking = legacy(mesh_store(), max_paths=max_paths)
    flags = {c.target_relationship_id: c.counterfactual_is_saturated for c in ranking.candidates}
    assert sorted(flags.values()) == [False] * 6 + [True] * 3
    for c in ranking.candidates:
        assert c.counterfactual_is_saturated == (c.counterfactual_path_count >= max_paths)
        expected_reason = "MAX_PATHS_REACHED" if c.counterfactual_is_saturated else "EXHAUSTED"
        assert c.counterfactual_termination_reason == expected_reason
    assert "COUNTERFACTUAL_SATURATED" in ranking.non_authoritative_reasons


def test_rankability_and_ranking_level_saturation_follow_from_recorded_flags():
    for max_paths in (1, 2, 3, 4, 7, 8, 100):
        ranking = legacy(mesh_store(), max_paths=max_paths)
        any_cf = any(c.counterfactual_is_saturated for c in ranking.candidates)
        assert ranking.is_saturated == (ranking.baseline_is_saturated or any_cf)
        for c in ranking.candidates:
            assert c.rankable == (not (ranking.baseline_is_saturated or c.counterfactual_is_saturated))


def test_counterfactual_saturation_implies_baseline_saturation_on_generated_graphs():
    rng = random.Random(20260928)
    types = ["ROUTES_TO", "EXPOSES", "TRUSTS", "CAN_AUTHENTICATE_TO"]
    for _ in range(40):
        store = NetworkXStore()
        n = rng.randint(3, 7)
        for i in range(1, n + 1):
            store.add_entity(U(i), "HOST", f"h{i}", criticality="HIGH", exposure="EXTERNAL")
        rel_ids = []
        for k in range(rng.randint(n, 3 * n)):
            src, dst = rng.sample(range(1, n + 1), 2)
            rel_ids.append(U(1000 + k))
            store.add_relationship(rel_ids[-1], U(src), U(dst), rng.choice(types), "OBSERVED")
        ranking = CounterfactualEngine(store, {}).evaluate_candidates(
            U(1), U(n), rel_ids, EVAL_TIME, max_hops=n, max_paths=rng.randint(1, 6)
        )
        for c in ranking.candidates:
            if c.counterfactual_is_saturated:
                assert ranking.baseline_is_saturated


def test_violated_saturation_invariant_fails_closed(monkeypatch):
    baseline_store = mesh_store()

    class CounterfactualAlwaysSaturated(TraversalEngine):
        def find_paths(self, *args, **kwargs):
            result = super().find_paths(*args, **kwargs)
            if self.store is not baseline_store:
                return result.model_copy(update={"is_saturated": True, "termination_reason": "MAX_PATHS_REACHED"})
            return result

    monkeypatch.setattr(counterfactual_module, "TraversalEngine", CounterfactualAlwaysSaturated)
    with pytest.raises(RuntimeError, match="saturation invariant violated"):
        CounterfactualEngine(baseline_store, {}).evaluate_candidates(U(1), U(5), [U(201)], EVAL_TIME)


# --- C1: persistence authority --------------------------------------------------

def test_unsaturated_context_run_with_canonical_scope_is_authoritative():
    analysis_policy = policy()
    ranking = CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
        U(1), U(5), MESH_CANDIDATES, context=context(analysis_policy)
    )
    assert ranking.is_saturated is False
    assert ranking.persistence_authoritative is True
    assert ranking.non_authoritative_reasons == []
    assert ranking.analysis_policy_fingerprint == generate_policy_fingerprint(analysis_policy)
    assert ranking.provenance.policy_fingerprint == ranking.analysis_policy_fingerprint
    assert ranking.provenance.policy_version == "analysis-policy-v2"
    assert ranking.provenance.evaluation_time == EVAL_TIME
    assert ranking.provenance.evaluation_time.tzinfo == timezone.utc
    assert (ranking.provenance.scope_id, ranking.provenance.scope_definition_version) == (SCOPE_ID, 1)


@pytest.mark.parametrize(
    "run, expected_reasons",
    [
        (lambda: legacy(mesh_store()), ["NO_ANALYSIS_CONTEXT"]),
        (lambda: legacy(mesh_store(), max_paths=3),
         ["BASELINE_SATURATED", "COUNTERFACTUAL_SATURATED", "NO_ANALYSIS_CONTEXT"]),
        (lambda: CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
            U(1), U(5), MESH_CANDIDATES, context=context(scope=AD_HOC_SCOPE)),
         ["NON_CANONICAL_SCOPE"]),
        (lambda: CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
            U(1), U(5), MESH_CANDIDATES, context=context(policy(max_paths=3))),
         ["BASELINE_SATURATED", "COUNTERFACTUAL_SATURATED"]),
        (lambda: CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
            U(1), U(5), MESH_CANDIDATES, context=context(policy(max_paths=3), scope=AD_HOC_SCOPE)),
         ["BASELINE_SATURATED", "COUNTERFACTUAL_SATURATED", "NON_CANONICAL_SCOPE"]),
    ],
    ids=["legacy", "legacy-saturated", "ad-hoc-scope", "context-saturated", "context-saturated-ad-hoc"],
)
def test_non_authoritative_reasons_are_fixed_sorted_and_deterministic(run, expected_reasons):
    first, second = run(), run()
    assert first.non_authoritative_reasons == expected_reasons
    assert second.non_authoritative_reasons == expected_reasons
    assert first.persistence_authoritative is False
    assert first.model_dump_json() == second.model_dump_json()


def test_legacy_run_has_no_provenance_or_fingerprint():
    ranking = legacy(mesh_store())
    assert ranking.provenance is None
    assert ranking.analysis_policy_fingerprint is None


def _ranking_fields(**overrides) -> dict:
    fields = {
        "baseline_is_saturated": False,
        "baseline_termination_reason": "EXHAUSTED",
        "is_saturated": False,
        "persistence_authoritative": False,
        "non_authoritative_reasons": ["NO_ANALYSIS_CONTEXT"],
        "baseline_environment_risk": 0.0,
        "baseline_path_count": 0,
        "candidates": [],
    }
    fields.update(overrides)
    return fields


@pytest.mark.parametrize(
    "overrides",
    [
        {"non_authoritative_reasons": ["NO_ANALYSIS_CONTEXT", "BASELINE_SATURATED"]},   # unsorted
        {"non_authoritative_reasons": ["NO_ANALYSIS_CONTEXT", "NO_ANALYSIS_CONTEXT"]},  # duplicate
        {"non_authoritative_reasons": ["SOMETHING_ELSE"]},                               # unknown code
        {"persistence_authoritative": True},                                             # reasons present
        {"non_authoritative_reasons": []},                                               # no reasons, not authoritative
        {"is_saturated": True, "persistence_authoritative": True, "non_authoritative_reasons": []},
        {"analysis_policy_fingerprint": "0" * 64},                                       # no provenance
    ],
)
def test_ranking_rejects_inconsistent_authority_state(overrides):
    with pytest.raises(ValidationError):
        EnvironmentRiskRanking(**_ranking_fields(**overrides))


def test_saturation_fields_are_required_on_results():
    fields = _ranking_fields()
    del fields["baseline_is_saturated"]
    with pytest.raises(ValidationError):
        EnvironmentRiskRanking(**fields)


# --- C4: policy propagation -----------------------------------------------------

def budget_store() -> NetworkXStore:
    """1 -> 2 -> 3 costs 2 (two ROUTES_TO); 1 -> 3 direct costs 5 (TRUSTS)."""
    store = NetworkXStore()
    store.add_entity(U(1), "HOST", "entry", exposure="EXTERNAL")
    store.add_entity(U(2), "HOST", "mid")
    store.add_entity(U(3), "DATABASE", "crown", criticality="CRITICAL")
    store.add_relationship(U(301), U(1), U(2), "ROUTES_TO", "OBSERVED")
    store.add_relationship(U(302), U(2), U(3), "ROUTES_TO", "OBSERVED")
    store.add_relationship(U(303), U(1), U(3), "TRUSTS", "OBSERVED")
    return store


def test_traversal_budget_is_applied_to_baseline_and_counterfactuals():
    budget_policy = policy(
        traversal_budget=3,
        allowed_edge_types=["ROUTES_TO", "TRUSTS"],
        edge_costs={"ROUTES_TO": 1, "TRUSTS": 5},
    )
    candidates = [U(301), U(302), U(303)]
    bounded = CounterfactualEngine(budget_store(), {}).evaluate_candidates(
        U(1), U(3), candidates, context=context(budget_policy)
    )
    unbounded = CounterfactualEngine(budget_store(), {}).evaluate_candidates(
        U(1), U(3), candidates, EVAL_TIME
    )

    # The direct path (cost 5) exceeds the budget of 3.
    assert bounded.baseline_path_count == 1
    assert unbounded.baseline_path_count == 2
    by_id = {c.target_relationship_id: c for c in bounded.candidates}
    # Removing 1 -> 2 leaves only the over-budget direct path, which the
    # counterfactual must also exclude.
    assert by_id[U(301)].counterfactual_path_count == 0
    assert by_id[U(303)].counterfactual_path_count == 1
    unbounded_by_id = {c.target_relationship_id: c for c in unbounded.candidates}
    assert unbounded_by_id[U(301)].counterfactual_path_count == 1


def test_allowed_edge_types_from_policy_are_applied():
    routes_only = policy(allowed_edge_types=["ROUTES_TO"], edge_costs={"ROUTES_TO": 1})
    ranking = CounterfactualEngine(budget_store(), {}).evaluate_candidates(
        U(1), U(3), [U(301)], context=context(routes_only)
    )
    assert ranking.baseline_path_count == 1


def test_baseline_and_counterfactuals_use_the_identical_policy(monkeypatch):
    calls = []

    class RecordingTraversalEngine(TraversalEngine):
        def find_paths(self, source_id, target_id, **kwargs):
            calls.append(kwargs)
            return super().find_paths(source_id, target_id, **kwargs)

    monkeypatch.setattr(counterfactual_module, "TraversalEngine", RecordingTraversalEngine)
    analysis_policy = policy(
        max_hops=4, traversal_budget=9, max_paths=50,
        allowed_edge_types=["ROUTES_TO", "EXPOSES", "TRUSTS"],
        edge_costs={"ROUTES_TO": 1, "EXPOSES": 2, "TRUSTS": 3},
    )
    CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
        U(1), U(5), MESH_CANDIDATES, context=context(analysis_policy)
    )

    assert len(calls) == 1 + len(MESH_CANDIDATES)
    assert all(call == calls[0] for call in calls)
    first = calls[0]
    assert first["max_hops"] == 4 and first["max_paths"] == 50
    assert first["allowed_types"] == {"ROUTES_TO", "EXPOSES", "TRUSTS"}
    assert first["policy"].max_hops == 4
    assert first["policy"].traversal_budget == 9
    assert first["policy"].edge_costs == {"EXPOSES": 2, "ROUTES_TO": 1, "TRUSTS": 3}


@pytest.mark.parametrize(
    "explicit",
    [
        {"evaluation_time": EVAL_TIME},
        {"max_hops": 6},
        {"max_paths": 100},
        {"allowed_types": None},
        {"allowed_types": ["ROUTES_TO"]},
    ],
)
def test_explicit_bounds_conflicting_with_context_are_rejected(explicit):
    with pytest.raises(ValueError, match="AnalysisContext defines the analysis inputs"):
        CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
            U(1), U(5), MESH_CANDIDATES, context=context(), **explicit
        )


def test_context_must_be_an_analysis_context():
    with pytest.raises(ValueError, match="must be an AnalysisContext"):
        CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
            U(1), U(5), MESH_CANDIDATES, context={"policy": policy()}
        )


def test_legacy_mode_still_requires_evaluation_time():
    with pytest.raises(ValueError, match="evaluation_time is required"):
        CounterfactualEngine(mesh_store(), {}).evaluate_candidates(U(1), U(5), MESH_CANDIDATES)


# --- Legacy regression and policy consistency ----------------------------------

def _numbers(ranking):
    return (
        ranking.baseline_environment_risk,
        ranking.baseline_path_count,
        [(c.target_relationship_id, c.counterfactual_environment_risk, c.risk_reduction,
          c.counterfactual_path_count, c.removed_path_ids, c.remaining_path_ids)
         for c in ranking.candidates],
    )


def test_legacy_defaults_are_unchanged():
    default = legacy(mesh_store())
    explicit = CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
        U(1), U(5), MESH_CANDIDATES, EVAL_TIME, max_hops=6, max_paths=100, allowed_types=None
    )
    assert _numbers(default) == _numbers(explicit)


def test_context_mode_with_legacy_equivalent_bounds_matches_legacy_numbers():
    """Same bounds, all types, a budget that never binds: identical numbers, only provenance differs."""
    equivalent = policy(max_hops=6, max_paths=100, traversal_budget=1000,
                        edge_costs={t: 0 for t in ALL_TYPES})
    in_context = CounterfactualEngine(mesh_store(), {}).evaluate_candidates(
        U(1), U(5), MESH_CANDIDATES, context=context(equivalent)
    )
    assert _numbers(in_context) == _numbers(legacy(mesh_store()))


_CONTEXT_SCRIPT = """
import sys, uuid
from datetime import datetime, timezone
from app.analytics.context import AnalysisContext
from app.analytics.counterfactual import CounterfactualEngine
from app.analytics.policy import AnalysisPolicyV2
from app.graph.networkx import NetworkXStore
from app.schemas.analytics import AnalyticalScope

U = lambda i: uuid.UUID(int=i)
store = NetworkXStore()
for i in range(1, 6):
    store.add_entity(U(i), "HOST", f"host-{i}", criticality="HIGH", exposure="EXTERNAL")
edges = [(201, 1, 2, "ROUTES_TO"), (202, 1, 3, "EXPOSES"), (203, 1, 4, "CAN_AUTHENTICATE_TO"),
         (204, 2, 5, "ROUTES_TO"), (205, 3, 5, "TRUSTS"), (206, 4, 5, "STORES"),
         (207, 2, 3, "ROUTES_TO"), (208, 3, 4, "DEPENDS_ON"), (209, 2, 4, "MEMBER_OF")]
for rel_id, src, dst, rel_type in edges:
    store.add_relationship(U(rel_id), U(src), U(dst), rel_type, "OBSERVED")
policy = AnalysisPolicyV2(
    traversal_policy_version="traversal-policy-v1", risk_formula_version="risk-v1",
    env_risk_formula_version="env-risk-v1", decay_policy_version="decay-policy-v1",
    max_hops=6, traversal_budget=4, max_paths=5, allowed_edge_types=None,
    edge_costs={t: 1 for t in ["CAN_ASSUME", "CAN_AUTHENTICATE_TO", "COMMUNICATES_WITH", "DEPENDS_ON",
                               "EXPOSES", "HAS_PERMISSION_ON", "MEMBER_OF", "ROUTES_TO", "RUNS_AS",
                               "STORES", "TRUSTS"]},
)
context = AnalysisContext(
    policy=policy, evaluation_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    scope=AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL",
                          scope_id=uuid.UUID(int=4242), definition_version=1),
)
ranking = CounterfactualEngine(store, {}).evaluate_candidates(
    U(1), U(5), [U(rel_id) for rel_id, *_ in edges], context=context)
sys.stdout.write(ranking.model_dump_json())
"""


def test_context_mode_ranking_is_byte_identical_across_hash_seeds():
    outputs = set()
    for seed in ["0", "1", "12345"]:
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", _CONTEXT_SCRIPT], cwd=BACKEND_DIR, env=env, capture_output=True
        )
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        outputs.add(result.stdout)
    assert len(outputs) == 1
    assert b'"is_saturated":true' in outputs.pop()  # max_paths=5 < 7 paths: saturation is exercised
