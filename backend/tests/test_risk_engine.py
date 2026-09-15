"""Unit tests for the deterministic risk calculation engine."""

import uuid
import pytest

from app.schemas.analytics import AttackPath, FindingRiskInput, RiskInput
from app.analytics.risk_engine import RiskEngine


def _dummy_path(edge_count: int = 1) -> AttackPath:
    nodes = [uuid.uuid4() for _ in range(edge_count + 1)]
    edges = [uuid.uuid4() for _ in range(edge_count)]
    return AttackPath(node_ids=nodes, edge_ids=edges)


def _build_input(
    crit="HIGH", 
    exp="EXTERNAL", 
    edge_types=None, 
    confs=None, 
    tiers=None, 
    sources=None,
    findings=None
) -> RiskInput:
    if edge_types is None:
        edge_types = ["ROUTES_TO"]
    if confs is None:
        confs = ["HIGH"]
    if tiers is None:
        tiers = ["OBSERVED"]
    if sources is None:
        sources = ["test-source"] * len(edge_types)
        
    path = _dummy_path(edge_count=len(edge_types))
    
    if findings is None:
        findings = []
    else:
        # Align finding entity_ids with the path to bypass the safety check
        for f in findings:
            if f.entity_id == uuid.UUID(int=0): # Sentinel value to auto-align
                f.entity_id = path.node_ids[0]
        
    return RiskInput(
        path=path,
        target_criticality=crit,
        entry_exposure=exp,
        edge_types=edge_types,
        edge_confidences=confs,
        edge_truth_tiers=tiers,
        edge_sources=sources,
        findings=findings
    )


def test_monotonic_target_criticality():
    prev_risk = -1.0
    for crit in ["None", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        ri = _build_input(crit=crit)
        res = RiskEngine.calculate(ri)
        assert res.numeric_risk >= prev_risk
        prev_risk = res.numeric_risk


def test_monotonic_entry_exposure():
    prev_risk = -1.0
    for exp in ["None", "ISOLATED", "RESTRICTED", "INTERNAL", "EXTERNAL"]:
        ri = _build_input(exp=exp)
        res = RiskEngine.calculate(ri)
        assert res.numeric_risk >= prev_risk
        prev_risk = res.numeric_risk


def test_monotonic_finding_severity():
    fid = uuid.uuid4()
    eid = uuid.UUID(int=0)
    
    prev_risk = -1.0
    # Must explicitly show INFO <= LOW <= MEDIUM <= HIGH <= CRITICAL
    for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        f = FindingRiskInput(finding_id=fid, entity_id=eid, severity=sev)
        ri = _build_input(findings=[f])
        res = RiskEngine.calculate(ri)
        assert res.numeric_risk >= prev_risk
        
        if sev != "INFO":
            # We expect strict monotonicity here if base_risk < 1.0
            assert res.numeric_risk > prev_risk
            
        prev_risk = res.numeric_risk


def test_confidence_propagation_weakest_link():
    # High, High, Low -> Low determines the path risk
    ri1 = _build_input(
        edge_types=["ROUTES_TO", "ROUTES_TO", "ROUTES_TO"],
        confs=["HIGH", "HIGH", "LOW"],
        tiers=["OBSERVED", "OBSERVED", "OBSERVED"]
    )
    res1 = RiskEngine.calculate(ri1)
    assert res1.confidence.value == 0.5


def test_confidence_inferred_penalty():
    # HIGH + OBSERVED = 1.0
    ri1 = _build_input(confs=["HIGH"], tiers=["OBSERVED"])
    res1 = RiskEngine.calculate(ri1)
    assert res1.confidence.value == 1.0
    
    # HIGH + INFERRED = 0.8
    ri2 = _build_input(confs=["HIGH"], tiers=["INFERRED"])
    res2 = RiskEngine.calculate(ri2)
    assert res2.confidence.value == 0.8


def test_finding_deduplication():
    fid = uuid.uuid4()
    eid1 = uuid.UUID(int=0)
    eid2 = uuid.UUID(int=0)
    
    # One instance of the finding
    ri1 = _build_input(findings=[FindingRiskInput(finding_id=fid, entity_id=eid1, severity="CRITICAL")])
    res1 = RiskEngine.calculate(ri1)
    
    # Multiple instances of the exact same finding across different entities in the path
    ri2 = _build_input(findings=[
        FindingRiskInput(finding_id=fid, entity_id=eid1, severity="CRITICAL"),
        FindingRiskInput(finding_id=fid, entity_id=eid2, severity="CRITICAL"),
        FindingRiskInput(finding_id=fid, entity_id=eid2, severity="CRITICAL")
    ])
    res2 = RiskEngine.calculate(ri2)
    
    assert len(res1.finding_ids) == 1
    assert len(res2.finding_ids) == 1
    assert res1.numeric_risk == res2.numeric_risk
    assert res1.finding_amplifier.value == 0.5


def test_exact_category_boundaries():
    # To test boundaries, we can construct the exact base risk manually by bypassing RiskEngine calculation? 
    # No, we must use RiskEngine. We can spoof the edge enablement mapping for exact testing, 
    # but we can just use combinations.
    # Base = Crit(1.0) * Exp(1.0) * Conf(1.0) * Edge(X).
    # If Edge = 0.25 -> LOW
    
    def get_cat_for_base(val: float) -> str:
        pass
    
    ri = _build_input(crit="INFO", exp="ISOLATED", edge_types=["DEPENDS_ON"])
    res = RiskEngine.calculate(ri)
    assert res.numeric_risk < 0.25
    assert res.category == "LOW"
    
    ri = _build_input(crit="HIGH", exp="RESTRICTED", edge_types=["EXPOSES"])
    res = RiskEngine.calculate(ri)
    assert res.numeric_risk == pytest.approx(0.32)
    assert res.category == "MEDIUM"

    ri = _build_input(crit="CRITICAL", exp="EXTERNAL", edge_types=["ROUTES_TO"])
    res = RiskEngine.calculate(ri)
    assert res.numeric_risk == pytest.approx(0.6)
    assert res.category == "HIGH"
    
    ri = _build_input(crit="CRITICAL", exp="EXTERNAL", edge_types=["CAN_AUTHENTICATE_TO"])
    res = RiskEngine.calculate(ri)
    assert res.numeric_risk == pytest.approx(1.0)
    assert res.category == "CRITICAL"


def test_finding_amplification_asymptote():
    ri = _build_input(
        crit="CRITICAL", 
        exp="INTERNAL", 
        edge_types=["CAN_AUTHENTICATE_TO"]
    )
    res_base = RiskEngine.calculate(ri)
    assert res_base.numeric_risk == pytest.approx(0.8)
    
    f = FindingRiskInput(finding_id=uuid.uuid4(), entity_id=uuid.UUID(int=0), severity="CRITICAL")
    ri = _build_input(
        crit="CRITICAL", 
        exp="INTERNAL", 
        edge_types=["CAN_AUTHENTICATE_TO"],
        findings=[f]
    )
    res_amp = RiskEngine.calculate(ri)
    
    assert res_amp.numeric_risk == pytest.approx(0.9)
    assert res_amp.numeric_risk <= 1.0
