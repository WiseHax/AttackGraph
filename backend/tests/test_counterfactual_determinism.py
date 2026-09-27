"""Determinism tests for counterfactual remediation output (ANA-3, TEST-8).

Category: Determinism.

Path-ID lists in a CounterfactualRemediationResult were previously derived
from Python set iteration, whose order depends on the per-process string hash
seed. These tests require the serialized ranking to be byte-identical across
processes with different PYTHONHASHSEED values, and the path-ID lists to follow
the documented total order (ascending canonical path ID).
"""

import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from app.analytics.counterfactual import CounterfactualEngine
from app.graph.networkx import NetworkXStore
from app.graph.pathfinder import TraversalEngine
from app.schemas.analytics import generate_canonical_path_id

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..")

HASH_SEEDS = ["0", "1", "2", "3", "12345"]

# Builds a fixed synthetic graph with several overlapping paths from node 1 to
# node 5, evaluates every edge as a remediation candidate at a fixed evaluation
# time, and prints the serialized ranking. Kept as source text so it can run in
# a fresh interpreter under a chosen PYTHONHASHSEED.
_ANALYSIS_SCRIPT = """
import sys
import uuid
from datetime import datetime, timezone

from app.analytics.counterfactual import CounterfactualEngine
from app.graph.networkx import NetworkXStore


def U(i):
    return uuid.UUID(int=i)


store = NetworkXStore()
for i in range(1, 6):
    store.add_entity(U(i), "HOST", f"host-{i}", criticality="HIGH", exposure="EXTERNAL")

edges = [
    (201, 1, 2, "ROUTES_TO"),
    (202, 1, 3, "EXPOSES"),
    (203, 1, 4, "CAN_AUTHENTICATE_TO"),
    (204, 2, 5, "ROUTES_TO"),
    (205, 3, 5, "TRUSTS"),
    (206, 4, 5, "STORES"),
    (207, 2, 3, "ROUTES_TO"),
    (208, 3, 4, "DEPENDS_ON"),
    (209, 2, 4, "MEMBER_OF"),
]
for rel_id, src, dst, rel_type in edges:
    store.add_relationship(U(rel_id), U(src), U(dst), rel_type, "OBSERVED")

engine = CounterfactualEngine(store, {})
ranking = engine.evaluate_candidates(
    U(1),
    U(5),
    [U(rel_id) for rel_id, _, _, _ in edges],
    datetime(2026, 1, 1, tzinfo=timezone.utc),
)
sys.stdout.write(ranking.model_dump_json())
"""


def _run_analysis(hash_seed: str) -> bytes:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = hash_seed
    result = subprocess.run(
        [sys.executable, "-c", _ANALYSIS_SCRIPT],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result.stdout


def test_counterfactual_ranking_serialization_is_byte_identical_across_hash_seeds():
    """Same canonical input and evaluation time -> byte-identical serialized ranking."""
    outputs = {seed: _run_analysis(seed) for seed in HASH_SEEDS}

    reference = outputs[HASH_SEEDS[0]]
    assert reference, "analysis subprocess produced no output"
    for seed, output in outputs.items():
        assert output == reference, (
            f"Serialized counterfactual ranking under PYTHONHASHSEED={seed} "
            f"differs from PYTHONHASHSEED={HASH_SEEDS[0]}"
        )


def test_counterfactual_path_id_lists_follow_ascending_path_id_order():
    """removed_path_ids / remaining_path_ids are sorted ascending and partition the baseline."""
    U = lambda i: uuid.UUID(int=i)
    store = NetworkXStore()
    for i in range(1, 6):
        store.add_entity(U(i), "HOST", f"host-{i}", criticality="HIGH", exposure="EXTERNAL")
    edges = [
        (201, 1, 2), (202, 1, 3), (203, 1, 4), (204, 2, 5), (205, 3, 5),
        (206, 4, 5), (207, 2, 3), (208, 3, 4), (209, 2, 4),
    ]
    for rel_id, src, dst in edges:
        store.add_relationship(U(rel_id), U(src), U(dst), "ROUTES_TO", "OBSERVED")

    engine = CounterfactualEngine(store, {})
    ranking = engine.evaluate_candidates(
        U(1), U(5), [U(205)], datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    candidate = ranking.candidates[0]

    assert candidate.removed_path_ids == sorted(candidate.removed_path_ids)
    assert candidate.remaining_path_ids == sorted(candidate.remaining_path_ids)

    # Ordering must not alter membership: the two lists still partition the
    # baseline path set.
    baseline_ids = {
        generate_canonical_path_id(p)
        for p in TraversalEngine(store).find_paths(U(1), U(5)).paths
    }
    assert set(candidate.removed_path_ids) | set(candidate.remaining_path_ids) == baseline_ids
    assert not set(candidate.removed_path_ids) & set(candidate.remaining_path_ids)
    assert len(candidate.removed_path_ids) > 1
    assert len(candidate.remaining_path_ids) > 1
