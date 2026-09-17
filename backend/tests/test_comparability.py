import pytest
from app.analytics.policy import AnalysisPolicy
from app.analytics.comparability import verify_comparability, ComparabilityError

@pytest.fixture
def base_policy():
    return AnalysisPolicy(
        traversal_policy_version="v1", max_hops=6, traversal_budget=10, max_paths=100,
        allowed_edge_types=["EXPOSES"], edge_costs={"EXPOSES": 1}, risk_formula_version="risk-v1",
        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-v1",
        criticality_map={"CRITICAL": 1.0}, exposure_map={"EXTERNAL": 1.0}, edge_enablement_map={"EXPOSES": 0.8},
        confidence_map={"HIGH": 1.0}, finding_amp_map={"CRITICAL": 0.5}
    )

def test_verify_comparability_success(base_policy):
    # Same policy should pass
    verify_comparability(base_policy, base_policy.model_copy())

def test_verify_comparability_rejection_max_paths(base_policy):
    target = base_policy.model_copy(update={"max_paths": 200})
    with pytest.raises(ComparabilityError, match="Fingerprint mismatch"):
        verify_comparability(base_policy, target)

def test_verify_comparability_rejection_max_hops(base_policy):
    target = base_policy.model_copy(update={"max_hops": 7})
    with pytest.raises(ComparabilityError):
        verify_comparability(base_policy, target)

def test_verify_comparability_rejection_traversal_budget(base_policy):
    target = base_policy.model_copy(update={"traversal_budget": 11})
    with pytest.raises(ComparabilityError):
        verify_comparability(base_policy, target)

def test_verify_comparability_rejection_risk_version(base_policy):
    target = base_policy.model_copy(update={"risk_formula_version": "risk-v2"})
    with pytest.raises(ComparabilityError):
        verify_comparability(base_policy, target)

def test_verify_comparability_rejection_env_risk_version(base_policy):
    target = base_policy.model_copy(update={"env_risk_formula_version": "env-risk-v2"})
    with pytest.raises(ComparabilityError):
        verify_comparability(base_policy, target)
