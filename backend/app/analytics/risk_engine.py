"""Pure analytical risk calculation engine."""

import math
from app.schemas.analytics import RiskInput, RiskResult, RiskFactor

CRITICALITY_MAP = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4, "INFO": 0.2}
EXPOSURE_MAP = {"EXTERNAL": 1.0, "INTERNAL": 0.8, "RESTRICTED": 0.5, "ISOLATED": 0.2}

EDGE_ENABLEMENT_MAP = {
    "CAN_AUTHENTICATE_TO": 1.0,
    "RUNS_AS": 1.0,
    "HAS_PERMISSION_ON": 1.0,
    "CAN_ASSUME": 1.0,
    "TRUSTS": 0.9,
    "EXPOSES": 0.8,
    "STORES": 0.8,
    "ROUTES_TO": 0.6,
    "COMMUNICATES_WITH": 0.6,
    "DEPENDS_ON": 0.4,
    "MEMBER_OF": 0.4,
}

CONFIDENCE_MAP = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5, "UNKNOWN": 0.2}

FINDING_AMP_MAP = {"CRITICAL": 0.5, "HIGH": 0.4, "MEDIUM": 0.3, "LOW": 0.2, "INFO": 0.0}


class RiskEngine:
    """Pure mathematical engine for calculating path risk.
    
    This engine accepts already-resolved RiskInput objects and performs
    no database I/O, ensuring deterministic execution and Phase 5
    counterfactual compatibility.
    """

    @staticmethod
    def calculate(risk_input: RiskInput, formula_version: str = "risk-v1") -> RiskResult:
        if formula_version not in ("risk-v1", "risk-v2"):
            raise ValueError(f"Unsupported formula_version: {formula_version}")
            
        # Target Criticality
        tc_val = CRITICALITY_MAP.get(risk_input.target_criticality, 0.1)
        tc_desc = f"Target Criticality: {risk_input.target_criticality or 'None'}"
        tc_factor = RiskFactor(value=tc_val, description=tc_desc)
        
        # Entry Exposure
        ee_val = EXPOSURE_MAP.get(risk_input.entry_exposure, 0.1)
        ee_desc = f"Entry Exposure: {risk_input.entry_exposure or 'None'}"
        ee_factor = RiskFactor(value=ee_val, description=ee_desc)
        
        # Edge Enablement (Geometric Mean)
        edge_vals = [EDGE_ENABLEMENT_MAP.get(et, 0.4) for et in risk_input.edge_types]
        if edge_vals:
            product = math.prod(edge_vals)
            edge_mean = math.pow(product, 1.0 / len(edge_vals))
        else:
            edge_mean = 1.0  # 0-hop path
        edge_factor = RiskFactor(
            value=edge_mean,
            description=f"Path Enablement (Geometric Mean of {len(edge_vals)} edges)"
        )
        
        # Confidence
        if formula_version == "risk-v1":
            conf_vals = []
            for conf, tier in zip(risk_input.edge_confidences, risk_input.edge_truth_tiers):
                c_val = CONFIDENCE_MAP.get(conf, 0.2)
                if tier == "INFERRED":
                    c_val *= 0.8
                conf_vals.append(c_val)
                
            if conf_vals:
                min_conf = min(conf_vals)
            else:
                min_conf = 1.0
            conf_desc = "Minimum Path Confidence"
            
        elif formula_version == "risk-v2":
            source_groups: dict[str, list[float]] = {}
            for conf, tier, src in zip(risk_input.edge_confidences, risk_input.edge_truth_tiers, risk_input.edge_sources):
                c_val = CONFIDENCE_MAP.get(conf, 0.2)
                if tier == "INFERRED":
                    c_val *= 0.8
                
                if src not in source_groups:
                    source_groups[src] = []
                source_groups[src].append(c_val)
                
            if source_groups:
                # Joint Source Probability (Source-Grouped Multiplicative Confidence)
                source_confidences = []
                for src, vals in source_groups.items():
                    source_confidences.append(min(vals))
                min_conf = math.prod(source_confidences)
            else:
                min_conf = 1.0
            conf_desc = "Source-Grouped Multiplicative Confidence"
            
        conf_factor = RiskFactor(value=min_conf, description=conf_desc)
        
        # Control Dampening (Fixed 1.0 for Phase 4 MVP)
        control_factor = RiskFactor(
            value=1.0,
            description="Control Dampening (Not Supported)"
        )
        
        base_risk = tc_val * ee_val * edge_mean * min_conf * 1.0
        
        # Finding Amplification (Interpolation, Deduplicated)
        unique_findings = {}
        for f in risk_input.findings:
            if f.entity_id in risk_input.path.node_ids:
                if f.finding_id not in unique_findings:
                    unique_findings[f.finding_id] = f.severity
                
        finding_ids = list(unique_findings.keys())
        max_finding_val = 0.0
        for sev in unique_findings.values():
            val = FINDING_AMP_MAP.get(sev, 0.0)
            if val > max_finding_val:
                max_finding_val = val
                
        finding_factor = RiskFactor(
            value=max_finding_val,
            description=f"Finding Amplification (Max of {len(finding_ids)} unique findings)"
        )
        
        final_risk = base_risk + ((1.0 - base_risk) * max_finding_val)
        
        # Categories
        if final_risk < 0.25:
            cat = "LOW"
        elif final_risk < 0.50:
            cat = "MEDIUM"
        elif final_risk < 0.75:
            cat = "HIGH"
        else:
            cat = "CRITICAL"
            
        return RiskResult(
            formula_version=formula_version,
            path=risk_input.path,
            finding_ids=finding_ids,
            numeric_risk=final_risk,
            category=cat,
            target_criticality=tc_factor,
            entry_exposure=ee_factor,
            edge_enablement=edge_factor,
            confidence=conf_factor,
            finding_amplifier=finding_factor,
            control_dampening=control_factor
        )
