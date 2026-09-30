"""Shared building blocks for path-level analysis.

Used by CounterfactualEngine and by any orchestration that needs per-path risk
(for example the showcase), so that the policy-to-traversal mapping and the
construction of risk inputs exist exactly once (no duplicated analytics).
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

from app.analytics.decay import resolve_edge_evidence
from app.analytics.policy import AnalysisPolicyV2
from app.graph.store import GraphStore
from app.schemas.analytics import AttackPath, FindingRiskInput, RiskInput, TraversalPolicy


@dataclass(frozen=True)
class TraversalBounds:
    """The complete traversal bounds for one analysis (ARCH-12, C4)."""

    policy: TraversalPolicy
    max_hops: int
    max_paths: int
    allowed_types: frozenset[str]


def traversal_bounds_for_policy(policy: AnalysisPolicyV2) -> TraversalBounds:
    """Derive traversal bounds from an AnalysisPolicyV2.

    max_hops, traversal_budget, edge costs, max_paths and the allowed
    relationship types all come from the one policy; nothing is defaulted.
    """
    return TraversalBounds(
        policy=TraversalPolicy(
            version=policy.traversal_policy_version,
            max_hops=policy.max_hops,
            traversal_budget=policy.traversal_budget,
            edge_costs={edge_type.value: cost for edge_type, cost in policy.edge_costs.items()},
        ),
        max_hops=policy.max_hops,
        max_paths=policy.max_paths,
        allowed_types=frozenset(edge_type.value for edge_type in policy.allowed_edge_types),
    )


def build_risk_input(
    path: AttackPath,
    store: GraphStore,
    findings_map: dict[uuid.UUID, list[FindingRiskInput]],
    evaluation_time: datetime,
) -> RiskInput:
    """Build the RiskInput for one path from the projection and findings.

    Edge confidence and source are resolved from the edge's evidence under
    decay-policy-v1 at the injected evaluation time; findings on any node of
    the path are included.
    """
    target_node = store.get_entity(path.node_ids[-1]) or {}
    source_node = store.get_entity(path.node_ids[0]) or {}

    edge_types = []
    edge_confs = []
    edge_tiers = []
    edge_sources = []

    for edge_id in path.edge_ids:
        edge_data = store.get_relationship(edge_id)
        if not edge_data:
            # Should not happen if path is valid for this store
            raise ValueError(f"Missing edge {edge_id} in graph store")

        raw_ev = edge_data.get("raw_evidence")
        truth_tier = edge_data["truth_tier"]

        resolved_conf, resolved_source = resolve_edge_evidence(
            raw_evidence_list=raw_ev,
            edge_id=str(edge_id),
            truth_tier=truth_tier,
            evaluation_time=evaluation_time
        )

        edge_types.append(edge_data["relationship_type"])
        edge_confs.append(resolved_conf)
        edge_tiers.append(truth_tier)
        edge_sources.append(resolved_source)

    path_findings = []
    for node_id in path.node_ids:
        if node_id in findings_map:
            path_findings.extend(findings_map[node_id])

    return RiskInput(
        path=path,
        target_criticality=target_node.get("criticality"),
        entry_exposure=source_node.get("exposure"),
        edge_types=edge_types,
        edge_confidences=edge_confs,
        edge_truth_tiers=edge_tiers,
        edge_sources=edge_sources,
        findings=path_findings
    )
