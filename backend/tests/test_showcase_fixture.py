"""Tests for the synthetic showcase fixture and policy (no database).

Categories:
- Determinism: identifiers are uuid5 over a fixed namespace and never change.
- Invariant: the fixture has the shape the showcase promises and is internally
  consistent (every reference resolves).
- Security (SEC-6): the data is recognisably synthetic; no real-looking
  addresses, domains or credentials.
"""

import ipaddress
import re
import uuid
from datetime import timezone

from app.analytics.policy import generate_policy_fingerprint
from app.domain.enums import EntityType, RelationshipType
from app.showcase.fixture import (
    SHOWCASE_EVALUATION_TIME,
    SHOWCASE_FIXTURE as F,
    SHOWCASE_NAMESPACE,
    showcase_id,
)
from app.showcase.pipeline import BOUNDED_POLICY, SHOWCASE_POLICY, showcase_policy

DOCUMENTATION_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_identifiers_are_uuid5_over_the_fixed_namespace():
    assert showcase_id("entity", "internet") == uuid.uuid5(SHOWCASE_NAMESPACE, "attackgraph-showcase:entity:internet")
    assert showcase_id("entity", "internet") == showcase_id("entity", "internet")
    assert showcase_id("entity", "internet") != showcase_id("relationship", "internet")
    # Pinned: changing the namespace or the derivation changes every showcase identifier.
    assert str(SHOWCASE_NAMESPACE) == "6a1c3f0e-5b2d-4c8e-9f7a-3d2b1e0c9a84"
    assert str(F.entity("customer-db").id) == str(uuid.uuid5(SHOWCASE_NAMESPACE, "attackgraph-showcase:entity:customer-db"))


def test_identifiers_are_unique_within_each_kind():
    for records in (F.entities, F.relationships, F.evidence, F.findings):
        ids = [r.id for r in records]
        assert len(ids) == len(set(ids))
        keys = [r.key for r in records]
        assert len(keys) == len(set(keys))


def test_fixture_has_the_documented_size_and_types():
    assert len(F.entities) == 16
    assert len(F.relationships) == 22
    assert len(F.evidence) == 17
    assert len(F.findings) == 5
    assert all(e.entity_type in EntityType.__members__ for e in F.entities)
    assert all(r.relationship_type in RelationshipType.__members__ for r in F.relationships)
    assert len({e.entity_type for e in F.entities}) >= 10
    assert len({r.relationship_type for r in F.relationships}) >= 8


def test_fixture_contains_every_element_the_showcase_demonstrates():
    types = {r.relationship_type for r in F.relationships}
    assert F.entity(F.source_entity).exposure == "EXTERNAL"
    assert any(e.exposure == "EXTERNAL" and e.key != F.source_entity for e in F.entities)
    assert F.entity(F.target_entity).criticality == "CRITICAL"
    assert "CAN_AUTHENTICATE_TO" in types                          # authentication
    assert {"HAS_PERMISSION_ON", "CAN_ASSUME"} <= types            # privilege
    assert {"DEPENDS_ON", "MEMBER_OF"} <= types                    # dependency / trust
    assert any(r.truth_tier == "INFERRED" and not r.evidence for r in F.relationships)
    pairs = [(r.source, r.target) for r in F.relationships]
    assert any(pairs.count(p) > 1 for p in pairs)                  # parallel relationships (ARCH-15)
    assert any(len(r.evidence) > 1 for r in F.relationships)       # multiple evidence records
    stale = [e for e in F.evidence
             if e.freshness_ttl_seconds and e.age.total_seconds() > e.freshness_ttl_seconds]
    assert stale                                                   # decay is exercised
    assert all(f.evidence for f in F.findings)


def test_every_reference_in_the_fixture_resolves():
    entity_keys = {e.key for e in F.entities}
    evidence_keys = {e.key for e in F.evidence}
    assert {F.source_entity, F.target_entity} <= entity_keys
    for r in F.relationships:
        assert r.source in entity_keys and r.target in entity_keys
        assert set(r.evidence) <= evidence_keys
        assert (r.truth_tier == "OBSERVED") == bool(r.evidence)
    for f in F.findings:
        assert f.entity in entity_keys
        assert set(f.evidence) <= evidence_keys


def test_timestamps_are_fixed_and_timezone_aware():
    assert SHOWCASE_EVALUATION_TIME.tzinfo == timezone.utc
    for e in F.evidence:
        assert e.collected_at.tzinfo is not None
        assert e.collected_at < SHOWCASE_EVALUATION_TIME


def test_fixture_data_is_recognisably_synthetic():
    for e in F.entities:
        if e.address:
            address = ipaddress.ip_address(e.address)
            assert any(address in net for net in DOCUMENTATION_NETWORKS), e.address
        # Every hostname-like token uses the reserved .test TLD (RFC 6761).
        for token in re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", e.name):
            assert token.endswith(".test"), token
    for spec in (*F.entities, *F.relationships, *F.evidence, *F.findings):
        text = " ".join(str(v) for v in vars(spec).values()).lower()
        assert not re.search(r"(password|passwd|secret|token|api[_-]?key)\s*[:=]", text)
        assert not re.search(r"\b(akia[0-9a-z]{12,}|ghp_[0-9a-z]{20,}|-----begin)", text)
    assert "synthetic" in F.organisation.lower()


def test_showcase_policy_and_bounded_policy_differ_only_in_max_paths():
    assert SHOWCASE_POLICY == showcase_policy()
    assert BOUNDED_POLICY.max_paths < SHOWCASE_POLICY.max_paths
    assert BOUNDED_POLICY.model_copy(update={"max_paths": SHOWCASE_POLICY.max_paths}) == SHOWCASE_POLICY
    assert generate_policy_fingerprint(SHOWCASE_POLICY) != generate_policy_fingerprint(BOUNDED_POLICY)
    assert [t.value for t in SHOWCASE_POLICY.allowed_edge_types] == sorted(t.value for t in RelationshipType)
