"""Environment Risk Aggregator.

This module provides the deterministic aggregation logic for combining
individual attack path risks into a single environment-level risk score.
"""

from typing import Iterable


class EnvironmentRiskAggregator:
    """Deterministic saturating aggregation of analytical path-risk scores.
    
    Implements the env-risk-v1 policy: 1 - Π(1 - path_risk_i).
    
    Rules:
    - Path risks are not assumed to be statistically independent.
    - Shared attack-path bottlenecks can cause double counting.
    - The result is an analytical score for comparative remediation ranking.
    - It must not be interpreted as a real-world probability of compromise.
    
    This function is mathematically bounded [0, 1] and monotonic:
    removing any path (where risk > 0) will strictly reduce the environment risk.
    """
    
    @staticmethod
    def calculate(path_risks: Iterable[float]) -> float:
        """Calculate the environment risk from a set of path risks.
        
        Args:
            path_risks: An iterable of risk scores [0.0, 1.0].
            
        Returns:
            The aggregated environment risk bounded [0.0, 1.0].
            Returns 0.0 if the iterable is empty.
        """
        risks = list(path_risks)
        if not risks:
            return 0.0
            
        # 1 - Π(1 - risk_i)
        product_of_complements = 1.0
        for risk in risks:
            if not (0.0 <= risk <= 1.0):
                raise ValueError(f"Path risk {risk} is out of bounds [0.0, 1.0]")
            product_of_complements *= (1.0 - risk)
            
        return 1.0 - product_of_complements
