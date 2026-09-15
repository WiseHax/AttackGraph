import pytest

from app.analytics.aggregator import EnvironmentRiskAggregator


def test_aggregator_empty_set():
    """Environment aggregation empty-set behavior."""
    assert EnvironmentRiskAggregator.calculate([]) == 0.0


def test_aggregator_single_path():
    """Single path risk is the environment risk."""
    assert EnvironmentRiskAggregator.calculate([0.5]) == 0.5
    assert EnvironmentRiskAggregator.calculate([0.0]) == 0.0
    assert EnvironmentRiskAggregator.calculate([1.0]) == 1.0


def test_aggregator_monotonicity():
    """Monotonicity (removing any path must strictly reduce risk).
    Adding paths strictly increases risk, unless existing risk is 1.0 or added risk is 0.0.
    """
    base = EnvironmentRiskAggregator.calculate([0.5])
    added = EnvironmentRiskAggregator.calculate([0.5, 0.2])
    assert added > base
    
    removed = EnvironmentRiskAggregator.calculate([0.5])
    assert removed < added


def test_aggregator_bounded():
    """Environment aggregation mathematically bounded [0,1]."""
    # Many high-risk paths should saturate towards 1.0 but never exceed it
    res = EnvironmentRiskAggregator.calculate([0.9, 0.9, 0.9, 0.9])
    assert 0.99 <= res <= 1.0


def test_aggregator_out_of_bounds():
    """Invalid bounds should raise ValueError."""
    with pytest.raises(ValueError):
        EnvironmentRiskAggregator.calculate([-0.1])
        
    with pytest.raises(ValueError):
        EnvironmentRiskAggregator.calculate([1.1])
