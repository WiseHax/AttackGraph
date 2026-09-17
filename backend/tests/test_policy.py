import uuid

import pytest

from app.analytics.policy import AnalysisPolicy, generate_policy_fingerprint



def test_generate_policy_fingerprint_determinism():

    policy1 = AnalysisPolicy(

        traversal_policy_version="v1",

        max_hops=6,

        traversal_budget=10,

        max_paths=100,

        allowed_edge_types=["EXPOSES"],

        edge_costs={"EXPOSES": 1},

        risk_formula_version="risk-v1",

        env_risk_formula_version="env-risk-v1",

        decay_policy_version="decay-v1",

        criticality_map={"CRITICAL": 1.0, "HIGH": 0.8},

        exposure_map={"EXTERNAL": 1.0},

        edge_enablement_map={"EXPOSES": 0.8},

        confidence_map={"HIGH": 1.0},

        finding_amp_map={"CRITICAL": 0.5}

    )



    # Exact same structure, should have same hash

    policy2 = AnalysisPolicy(

        traversal_policy_version="v1",

        max_hops=6,

        traversal_budget=10,

        max_paths=100,

        allowed_edge_types=["EXPOSES"],

        edge_costs={"EXPOSES": 1},

        risk_formula_version="risk-v1",

        env_risk_formula_version="env-risk-v1",

        decay_policy_version="decay-v1",

        criticality_map={"CRITICAL": 1.0, "HIGH": 0.8},

        exposure_map={"EXTERNAL": 1.0},

        edge_enablement_map={"EXPOSES": 0.8},

        confidence_map={"HIGH": 1.0},

        finding_amp_map={"CRITICAL": 0.5}

    )



    fp1 = generate_policy_fingerprint(policy1)

    fp2 = generate_policy_fingerprint(policy2)

    assert fp1 == fp2



def test_generate_policy_fingerprint_precision_lossless():

    # 0.8000 vs 0.8 should be identical

    policy1 = AnalysisPolicy(

        traversal_policy_version="v1",

        max_hops=6,

        traversal_budget=10,

        max_paths=100,

        allowed_edge_types=["EXPOSES"],

        edge_costs={"EXPOSES": 1},

        risk_formula_version="risk-v1",

        env_risk_formula_version="env-risk-v1",

        decay_policy_version="decay-v1",

        criticality_map={"CRITICAL": 0.8000},

        exposure_map={"EXTERNAL": 1.0},

        edge_enablement_map={"EXPOSES": 0.8},

        confidence_map={"HIGH": 1.0},

        finding_amp_map={"CRITICAL": 0.5}

    )



    policy2 = AnalysisPolicy(

        traversal_policy_version="v1",

        max_hops=6,

        traversal_budget=10,

        max_paths=100,

        allowed_edge_types=["EXPOSES"],

        edge_costs={"EXPOSES": 1},

        risk_formula_version="risk-v1",

        env_risk_formula_version="env-risk-v1",

        decay_policy_version="decay-v1",

        criticality_map={"CRITICAL": 0.8},

        exposure_map={"EXTERNAL": 1.0},

        edge_enablement_map={"EXPOSES": 0.8},

        confidence_map={"HIGH": 1.0},

        finding_amp_map={"CRITICAL": 0.5}

    )



    assert generate_policy_fingerprint(policy1) == generate_policy_fingerprint(policy2)



    # 0.8 vs 0.8001 should be different

    policy3 = AnalysisPolicy(

        traversal_policy_version="v1",

        max_hops=6,

        traversal_budget=10,

        max_paths=100,

        allowed_edge_types=["EXPOSES"],

        edge_costs={"EXPOSES": 1},

        risk_formula_version="risk-v1",

        env_risk_formula_version="env-risk-v1",

        decay_policy_version="decay-v1",

        criticality_map={"CRITICAL": 0.8001},

        exposure_map={"EXTERNAL": 1.0},

        edge_enablement_map={"EXPOSES": 0.8},

        confidence_map={"HIGH": 1.0},

        finding_amp_map={"CRITICAL": 0.5}

    )



    assert generate_policy_fingerprint(policy1) != generate_policy_fingerprint(policy3)



def test_generate_policy_fingerprint_material_change():

    policy1 = AnalysisPolicy(

        traversal_policy_version="v1", max_hops=6, traversal_budget=10, max_paths=100,

        allowed_edge_types=["EXPOSES"], edge_costs={"EXPOSES": 1}, risk_formula_version="risk-v1",

        env_risk_formula_version="env-risk-v1", decay_policy_version="decay-v1",

        criticality_map={"CRITICAL": 1.0}, exposure_map={"EXTERNAL": 1.0}, edge_enablement_map={"EXPOSES": 0.8},

        confidence_map={"HIGH": 1.0}, finding_amp_map={"CRITICAL": 0.5}

    )



    # Change max_paths

    policy2 = policy1.model_copy(update={"max_paths": 200})

    assert generate_policy_fingerprint(policy1) != generate_policy_fingerprint(policy2)



    # Change risk_formula

    policy3 = policy1.model_copy(update={"risk_formula_version": "risk-v2"})

    assert generate_policy_fingerprint(policy1) != generate_policy_fingerprint(policy3)
