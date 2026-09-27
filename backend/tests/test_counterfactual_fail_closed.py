"""Fail-closed behaviour of CounterfactualEngine (CODE-18, SEC-21).

Categories:
- Negative: invalid GraphStore state must raise instead of producing a
  result with placeholder identities.
- Regression / golden: valid NetworkXStore results are pinned to exact values
  produced before the fail-closed hardening, so the hardening cannot have
  changed any number, count, identity, or ranking order.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.analytics.counterfactual import CounterfactualEngine
from app.graph.networkx import NetworkXStore
from app.schemas.analytics import FindingRiskInput

EVAL_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def U(i: int) -> uuid.UUID:
    return uuid.UUID(int=i)


def _evidence(i: int, confidence: str) -> list[dict]:
    return [{
        "id": U(900 + i),
        "source": "synthetic-scanner",
        "source_type": "synthetic",
        "collected_at": datetime(2025, 12, 31, tzinfo=timezone.utc),
        "freshness_ttl_seconds": 86400 * 30,
        "confidence": confidence,
    }]


def _populate(store: NetworkXStore) -> None:
    """Diamond with a parallel edge, an INFERRED edge, and a cross edge."""
    store.add_entity(U(1), "HOST", "entry", exposure="EXTERNAL")
    store.add_entity(U(2), "HOST", "mid-a")
    store.add_entity(U(3), "HOST", "mid-b")
    store.add_entity(U(4), "DATABASE", "crown", criticality="CRITICAL")
    store.add_relationship(U(101), U(1), U(2), "EXPOSES", "OBSERVED", raw_evidence=_evidence(1, "HIGH"))
    store.add_relationship(U(102), U(1), U(3), "ROUTES_TO", "OBSERVED", raw_evidence=_evidence(2, "MEDIUM"))
    store.add_relationship(U(103), U(2), U(4), "CAN_AUTHENTICATE_TO", "OBSERVED", raw_evidence=_evidence(3, "HIGH"))
    store.add_relationship(U(104), U(3), U(4), "HAS_PERMISSION_ON", "INFERRED")
    store.add_relationship(U(105), U(2), U(4), "TRUSTS", "OBSERVED", raw_evidence=_evidence(5, "LOW"))
    store.add_relationship(U(106), U(2), U(3), "COMMUNICATES_WITH", "OBSERVED", raw_evidence=_evidence(6, "HIGH"))


FINDINGS = {U(3): [FindingRiskInput(finding_id=U(700), entity_id=U(3), severity="HIGH")]}


class _EndpointDroppingStore(NetworkXStore):
    """Violates the GraphStore contract by omitting one endpoint key for one relationship."""

    def __init__(self, relationship_id: uuid.UUID, dropped_key: str) -> None:
        super().__init__()
        self._relationship_id = relationship_id
        self._dropped_key = dropped_key

    def get_relationship(self, relationship_id):
        data = super().get_relationship(relationship_id)
        if data is not None and relationship_id == self._relationship_id:
            data.pop(self._dropped_key)
        return data


class _NonRemovingStore(NetworkXStore):
    """Clones into a store whose remove_relationship reports failure."""

    def clone(self) -> "_NonRemovingStore":
        cloned = _NonRemovingStore()
        cloned.graph = self.graph.copy()
        return cloned

    def remove_relationship(self, relationship_id):
        return False


@pytest.mark.parametrize("dropped_key", ["source_id", "target_id"])
def test_missing_relationship_endpoint_raises(dropped_key):
    """A candidate without source_id / target_id must raise, never emit a nil UUID."""
    store = _EndpointDroppingStore(U(103), dropped_key)
    _populate(store)
    engine = CounterfactualEngine(store, FINDINGS)

    with pytest.raises(ValueError, match=f"missing '{dropped_key}'"):
        engine.evaluate_candidates(U(1), U(4), [U(103)], EVAL_TIME)


def test_failed_relationship_removal_raises():
    """If the clone does not remove the candidate, the counterfactual is invalid and must raise."""
    store = _NonRemovingStore()
    _populate(store)
    engine = CounterfactualEngine(store, FINDINGS)

    with pytest.raises(ValueError, match="could not be removed"):
        engine.evaluate_candidates(U(1), U(4), [U(103)], EVAL_TIME)


def test_valid_networkx_results_match_pre_hardening_golden_values():
    """Exact values captured from c700a29 (before C7) for a valid NetworkXStore."""
    store = NetworkXStore()
    _populate(store)
    engine = CounterfactualEngine(store, FINDINGS)

    ranking = engine.evaluate_candidates(
        U(1), U(4), [U(i) for i in range(101, 107)], EVAL_TIME
    )

    assert ranking.baseline_environment_risk == 0.9832318492366209
    assert ranking.baseline_path_count == 4

    # (relationship, cf_env_risk, risk_reduction, cf_path_count, removed, remaining,
    #  source, target, type) in ranked order.
    expected = [
        (101, 0.4743612802471825, 0.5088705689894384, 1, 3, 1, 1, 2, "EXPOSES"),
        (103, 0.8411697962553426, 0.14206205298127828, 3, 1, 3, 2, 4, "CAN_AUTHENTICATE_TO"),
        (104, 0.9392179404916389, 0.04401390874498201, 2, 2, 2, 3, 4, "HAS_PERMISSION_ON"),
        (106, 0.9680505960560855, 0.015181253180535426, 3, 1, 3, 2, 3, "COMMUNICATES_WITH"),
        (102, 0.9680994756792947, 0.015132373557326217, 3, 1, 3, 1, 3, "ROUTES_TO"),
        (105, 0.9708752748402129, 0.012356574396408027, 3, 1, 3, 2, 4, "TRUSTS"),
    ]
    actual = [
        (
            c.target_relationship_id.int,
            c.counterfactual_environment_risk,
            c.risk_reduction,
            c.counterfactual_path_count,
            len(c.removed_path_ids),
            len(c.remaining_path_ids),
            c.target_source_id.int,
            c.target_target_id.int,
            c.target_relationship_type,
        )
        for c in ranking.candidates
    ]
    assert actual == expected

    # The baseline projection is never mutated by counterfactual evaluation (ARCH-17).
    assert store.get_relationship(U(103)) is not None
    assert len(list(store.graph.edges(keys=True))) == 6
