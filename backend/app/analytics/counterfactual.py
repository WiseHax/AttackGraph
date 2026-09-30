"""Counterfactual Analysis Engine for Remediation Ranking."""

import uuid
from datetime import datetime
from typing import Iterable

from app.graph.store import GraphStore
from app.graph.pathfinder import TraversalEngine
from app.analytics.context import AnalysisContext
from app.analytics.path_analysis import build_risk_input, traversal_bounds_for_policy
from app.analytics.risk_engine import RiskEngine
from app.analytics.aggregator import EnvironmentRiskAggregator
from app.schemas.analytics import (
    NON_AUTHORITATIVE_BASELINE_SATURATED,
    NON_AUTHORITATIVE_COUNTERFACTUAL_SATURATED,
    NON_AUTHORITATIVE_NO_ANALYSIS_CONTEXT,
    NON_AUTHORITATIVE_NON_CANONICAL_SCOPE,
    AttackPath,
    CounterfactualRemediationResult,
    EnvironmentRiskRanking,
    FindingRiskInput,
    RiskInput,
    generate_canonical_path_id,
    normalize_evaluation_time,
)

class _Unset:
    """Type of the _UNSET sentinel: "argument not supplied"."""

    def __repr__(self) -> str:
        return "<unset>"


# Marks a keyword argument the caller did not supply, so that explicit bounds
# can be rejected when an AnalysisContext defines them (C4).
_UNSET = _Unset()

# Bounds of the legacy (no AnalysisContext) call path, unchanged (D-L).
_LEGACY_MAX_HOPS = 6
_LEGACY_MAX_PATHS = 100


class CounterfactualEngine:
    """Evaluates the risk reduction of removing specific relationships.

    This engine operates strictly on analytical projections (GraphStore)
    and executes deterministic counterfactual pathfinding and risk scoring.
    """

    def __init__(
        self,
        store: GraphStore,
        findings_map: dict[uuid.UUID, list[FindingRiskInput]]
    ):
        """Initialize the engine with the baseline graph and findings context.

        Args:
            store: The canonical analytical GraphStore projection.
            findings_map: Pre-loaded findings mapped by entity UUID.
        """
        self.store = store
        self.findings_map = findings_map

    def _build_risk_input(
        self,
        path: AttackPath,
        current_store: GraphStore,
        evaluation_time: datetime
    ) -> RiskInput:
        """Build a RiskInput from an AttackPath by fetching attributes from the store."""
        return build_risk_input(path, current_store, self.findings_map, evaluation_time)

    def evaluate_candidates(
        self,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        candidate_relationship_ids: Iterable[uuid.UUID],
        evaluation_time: datetime | _Unset = _UNSET,
        max_hops: int | _Unset = _UNSET,
        max_paths: int | _Unset = _UNSET,
        allowed_types: set[str] | list[str] | None | _Unset = _UNSET,
        context: AnalysisContext | None = None,
    ) -> EnvironmentRiskRanking:
        """Evaluate a set of candidate relationship removals and rank them.

        Two call modes:
        - With `context` (persistable/comparable, C4): one AnalysisPolicyV2
          defines max_hops, traversal_budget, edge costs, max_paths and the
          allowed relationship types for the baseline and every candidate,
          and its risk_formula_version selects the risk formula;
          env_risk_formula_version and decay_policy_version each admit only
          the implemented version and are recorded through the policy
          fingerprint and provenance. Evaluation time and scope come from the
          context. Passing evaluation_time or any bound explicitly as well is
          rejected. Parameters left at `_UNSET` were not supplied.
        - Without `context` (legacy, non-persistable): evaluation_time is
          required; max_hops (default 6), max_paths (default 100) and
          allowed_types (default: all) apply, with no traversal budget.
          Numeric results are unchanged from earlier versions.

        Saturation (ANA-7a) is always reported, numbers are always produced,
        and persistence authority is derived from saturation, context and
        scope identity (see EnvironmentRiskRanking).

        Args:
            source_id: The attack origin entity.
            target_id: The attack destination entity.
            candidate_relationship_ids: Relationships to evaluate for removal.
            evaluation_time: Legacy mode only. Injected reference time for
                evidence decay (ANA-3); must be timezone-aware.
            max_hops: Legacy mode only. Computational bound.
            max_paths: Legacy mode only. Enumeration limit.
            allowed_types: Legacy mode only. Relationship types to traverse.
            context: AnalysisContext for a persistable/comparable run.

        Returns:
            EnvironmentRiskRanking containing ranked results.
        """
        if context is not None:
            if not isinstance(context, AnalysisContext):
                raise ValueError("context must be an AnalysisContext")
            explicit = sorted(
                name for name, value in (
                    ("allowed_types", allowed_types),
                    ("evaluation_time", evaluation_time),
                    ("max_hops", max_hops),
                    ("max_paths", max_paths),
                ) if value is not _UNSET
            )
            if explicit:
                raise ValueError(
                    f"AnalysisContext defines the analysis inputs; do not also pass {explicit}"
                )
            policy = context.policy
            bounds = traversal_bounds_for_policy(policy)
            traversal_policy = bounds.policy
            traversal_max_hops = bounds.max_hops
            traversal_max_paths = bounds.max_paths
            traversal_allowed_types = bounds.allowed_types
            risk_formula_version = policy.risk_formula_version
            evaluation_time = context.evaluation_time
            provenance = context.provenance()
        else:
            if evaluation_time is _UNSET:
                raise ValueError("evaluation_time is required when no AnalysisContext is supplied")
            # ANA-3: fail fast on a naive or non-datetime evaluation time, before
            # any computation; the value is used in canonical UTC.
            evaluation_time = normalize_evaluation_time(evaluation_time)
            traversal_policy = None
            traversal_max_hops = _LEGACY_MAX_HOPS if max_hops is _UNSET else max_hops
            traversal_max_paths = _LEGACY_MAX_PATHS if max_paths is _UNSET else max_paths
            traversal_allowed_types = None if allowed_types is _UNSET else allowed_types
            risk_formula_version = "risk-v1"
            provenance = None

        def find_paths(store: GraphStore):
            # ARCH-12 / C4: the baseline and every counterfactual are enumerated
            # with exactly the same bounds.
            return TraversalEngine(store).find_paths(
                source_id,
                target_id,
                policy=traversal_policy,
                max_hops=traversal_max_hops,
                max_paths=traversal_max_paths,
                allowed_types=traversal_allowed_types,
            )

        # 1. Baseline Evaluation
        baseline_result = find_paths(self.store)

        baseline_path_ids = set()
        baseline_risks = []

        for p in baseline_result.paths:
            path_id = generate_canonical_path_id(p)
            baseline_path_ids.add(path_id)
            r_input = self._build_risk_input(p, self.store, evaluation_time)
            r_result = RiskEngine.calculate(r_input, formula_version=risk_formula_version)
            baseline_risks.append(r_result.numeric_risk)

        baseline_env_risk = EnvironmentRiskAggregator.calculate(baseline_risks)

        results = []

        # 2. Evaluate Each Candidate
        for candidate_id in candidate_relationship_ids:
            # Validate candidate
            edge_data = self.store.get_relationship(candidate_id)
            if not edge_data:
                raise ValueError(f"Candidate {candidate_id} not found in GraphStore")

            if edge_data.get("truth_tier") == "ANALYTICAL":
                raise ValueError(f"Candidate {candidate_id} is ANALYTICAL and cannot be remediated")

            # Fail closed: the result must name the real endpoints of the
            # removed relationship, never a placeholder identity.
            for endpoint_key in ("source_id", "target_id"):
                if edge_data.get(endpoint_key) is None:
                    raise ValueError(
                        f"Candidate {candidate_id} is missing '{endpoint_key}' in GraphStore relationship data"
                    )

            # Clone and Mutate
            cloned_store = self.store.clone()
            if not cloned_store.remove_relationship(candidate_id):
                raise ValueError(f"Candidate {candidate_id} could not be removed from the cloned GraphStore")

            # Recompute Paths
            cf_result = find_paths(cloned_store)

            # ANA-7a: removing an edge only removes paths, and every bound is
            # path-local, so with identical bounds a complete (unsaturated)
            # baseline cannot yield a saturated counterfactual. A violation
            # means the enumeration is not what the semantics assume.
            if cf_result.is_saturated and not baseline_result.is_saturated:
                raise RuntimeError(
                    f"Counterfactual enumeration for candidate {candidate_id} saturated "
                    f"while the baseline did not; saturation invariant violated"
                )

            cf_path_ids = set()
            cf_risks = []

            for p in cf_result.paths:
                path_id = generate_canonical_path_id(p)
                cf_path_ids.add(path_id)
                # ANA-7: the counterfactual path set is a subset of the baseline
                # path set only when baseline enumeration is not saturated.
                r_input = self._build_risk_input(p, cloned_store, evaluation_time)
                r_result = RiskEngine.calculate(r_input, formula_version=risk_formula_version)
                cf_risks.append(r_result.numeric_risk)

            cf_env_risk = EnvironmentRiskAggregator.calculate(cf_risks)

            # Calculate metrics
            # ANA-3: set iteration order depends on the per-process hash seed,
            # so path-ID lists are emitted in ascending canonical path-ID order.
            removed = sorted(baseline_path_ids - cf_path_ids)
            remaining = sorted(baseline_path_ids.intersection(cf_path_ids))

            res = CounterfactualRemediationResult(
                target_relationship_id=candidate_id,
                target_source_id=edge_data["source_id"],
                target_target_id=edge_data["target_id"],
                target_relationship_type=edge_data["relationship_type"],
                baseline_environment_risk=baseline_env_risk,
                counterfactual_environment_risk=cf_env_risk,
                risk_reduction=baseline_env_risk - cf_env_risk,
                baseline_path_count=len(baseline_result.paths),
                counterfactual_path_count=len(cf_result.paths),
                removed_path_ids=removed,
                remaining_path_ids=remaining,
                counterfactual_is_saturated=cf_result.is_saturated,
                counterfactual_termination_reason=cf_result.termination_reason,
                rankable=not (baseline_result.is_saturated or cf_result.is_saturated),
            )
            results.append(res)

        # 3. Deterministic Ranking
        # Primary: risk_reduction (DESC)
        # Tie 1: cf_env_risk (ASC)
        # Tie 2: cf_path_count (ASC)
        # Tie 3: target_relationship_id (ASC lexicographical)
        results.sort(
            key=lambda r: (
                -r.risk_reduction,
                r.counterfactual_environment_risk,
                r.counterfactual_path_count,
                str(r.target_relationship_id)
            )
        )

        # 4. Saturation and persistence authority (ANA-7a)
        any_counterfactual_saturated = any(r.counterfactual_is_saturated for r in results)
        reasons = set()
        if baseline_result.is_saturated:
            reasons.add(NON_AUTHORITATIVE_BASELINE_SATURATED)
        if any_counterfactual_saturated:
            reasons.add(NON_AUTHORITATIVE_COUNTERFACTUAL_SATURATED)
        if context is None:
            # No AnalysisPolicyV2, fingerprint or recorded evaluation time.
            reasons.add(NON_AUTHORITATIVE_NO_ANALYSIS_CONTEXT)
        elif context.scope.scope_id is None:
            # ARCH-28: only a canonically resolved scope can back persistence.
            reasons.add(NON_AUTHORITATIVE_NON_CANONICAL_SCOPE)

        return EnvironmentRiskRanking(
            analysis_policy_fingerprint=provenance.policy_fingerprint if provenance else None,
            provenance=provenance,
            baseline_is_saturated=baseline_result.is_saturated,
            baseline_termination_reason=baseline_result.termination_reason,
            is_saturated=baseline_result.is_saturated or any_counterfactual_saturated,
            persistence_authoritative=not reasons,
            non_authoritative_reasons=sorted(reasons),
            baseline_environment_risk=baseline_env_risk,
            baseline_path_count=len(baseline_result.paths),
            candidates=results,
        )
