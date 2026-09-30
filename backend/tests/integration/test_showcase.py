"""PostgreSQL integration tests for the showcase (end to end, real engines).

Categories:
- Semantic: the showcase result reflects the fixture as analysed by the real
  engines (paths, risk, counterfactual, saturation, provenance, identity).
- Determinism: repeated and cross-process runs produce byte-identical
  artifacts, equal to the committed examples in docs/showcase/.
- Invariant: the run leaves no canonical data behind, refuses unsafe
  databases, never mutates the baseline, and makes no network connections.
- Regression: results come from the engines, not from hard-coded values.
"""

import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.analytics.engine_identity import EngineIdentityService
from app.analytics.policy import generate_policy_fingerprint
from app.analytics.risk_engine import RiskEngine
from app.domain.models import Base, Entity
from app.schemas.analytics import generate_canonical_path_id
from app.showcase.artifacts import ARTIFACT_FILENAMES, render_artifacts
from app.showcase.fixture import SHOWCASE_EVALUATION_TIME, SHOWCASE_FIXTURE as F
from app.showcase.pipeline import (
    BOUNDED_POLICY,
    SHOWCASE_POLICY,
    ShowcaseDatabaseNotReady,
    analyze,
    run_showcase,
)

pytestmark = pytest.mark.integration

BACKEND_DIR = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = BACKEND_DIR.parent / "docs" / "showcase"
NO_ENGINE_METADATA = str(BACKEND_DIR / "tests" / "no-such-engine-metadata.json")


def _identity() -> EngineIdentityService:
    return EngineIdentityService(NO_ENGINE_METADATA)


@pytest.fixture
def database_url(pg_schema_setup) -> str:
    """The migrated, empty integration test database."""
    return pg_schema_setup


@pytest.fixture
async def report(database_url):
    return await run_showcase(database_url, _identity())


# --- End-to-end result ----------------------------------------------------------

def test_showcase_analyses_the_fixture_through_the_real_pipeline(report):
    assert report.projection.entity_count == len(F.entities)
    assert report.projection.relationship_count == len(F.relationships)
    assert report.projection.all_canonical_records_projected is True
    assert len(report.environment.evidence) == len(F.evidence)
    assert len(report.environment.findings) == len(F.findings)

    baseline = report.baseline
    assert baseline.path_count == 11
    assert baseline.termination_reason == "EXHAUSTED"
    assert baseline.is_saturated is False
    assert baseline.environment_risk == report.remediation.ranking.baseline_environment_risk
    for path in baseline.paths:
        assert path.node_ids[0] == F.entity(F.source_entity).id
        assert path.node_ids[-1] == F.entity(F.target_entity).id
        assert path.hop_count == len(path.relationship_ids) == len(path.steps)
        assert path.path_id == generate_canonical_path_id(path.risk.path)
        assert 0.0 < path.risk.numeric_risk <= 1.0


def test_scope_context_and_policy_propagate_into_the_result(report):
    assert report.scope.scope_id == F.scope_id
    assert report.scope.definition_version == 1
    assert (report.scope.input_boundary_kind, report.scope.reporting_selector) == ("UNIVERSAL", "ALL")
    provenance = report.analysis.provenance
    assert provenance.scope_id == F.scope_id
    assert provenance.scope_definition_version == 1
    assert provenance.evaluation_time == SHOWCASE_EVALUATION_TIME
    assert provenance.policy_version == "analysis-policy-v2"
    assert provenance.policy_fingerprint == generate_policy_fingerprint(SHOWCASE_POLICY)
    assert report.analysis.policy == SHOWCASE_POLICY
    ranking = report.remediation.ranking
    assert ranking.provenance == provenance
    assert ranking.analysis_policy_fingerprint == provenance.policy_fingerprint
    assert ranking.persistence_authoritative is True
    assert ranking.non_authoritative_reasons == []


def test_engine_identity_is_propagated_and_gates_persistence(report):
    assert report.engine_identity.status == "ENGINE_UNVERIFIABLE(missing_metadata)"
    assert report.engine_identity.persistence_authorized is False
    assert report.persistence.ranking_persistence_authoritative is True
    assert report.persistence.engine_status == report.engine_identity.status
    assert report.persistence.preconditions_met is False


def test_counterfactual_removes_the_exact_relationship_and_compares_before_and_after(report):
    remediation = report.remediation
    choke = F.relationship("svc-deploy-assume-db-admin").id
    in_series = F.relationship("db-admin-permission-db").id
    assert remediation.featured_relationship_id == choke
    assert remediation.equivalent_relationship_ids == [in_series]
    featured = remediation.ranking.candidates[0]
    assert featured.target_relationship_id == choke and featured.rankable
    assert remediation.before.path_count == 11 and remediation.after.path_count == 4
    assert remediation.after.environment_risk == featured.counterfactual_environment_risk
    assert remediation.after.environment_risk < remediation.before.environment_risk
    assert remediation.after.max_path_risk < remediation.before.max_path_risk
    # Every removed path used the removed relationship; no remaining path does.
    paths = {p.path_id: p for p in report.baseline.paths}
    assert len(remediation.removed_path_ids) == 7
    assert all(choke in paths[pid].relationship_ids for pid in remediation.removed_path_ids)
    assert all(choke not in paths[pid].relationship_ids for pid in remediation.after.path_ids)
    assert remediation.baseline_projection_unchanged is True
    assert remediation.candidate_relationship_ids == sorted(
        {r for p in report.baseline.paths for r in p.relationship_ids}, key=str
    )


def test_saturation_semantics_are_demonstrated_under_a_tighter_bound(report):
    bounded = report.bound_sensitivity
    assert bounded.policy == BOUNDED_POLICY
    assert bounded.baseline_path_count == BOUNDED_POLICY.max_paths
    assert bounded.baseline_termination_reason == "MAX_PATHS_REACHED"
    assert bounded.baseline_is_saturated is True and bounded.is_saturated is True
    assert bounded.rankable_candidate_count == 0
    assert bounded.persistence_authoritative is False
    assert "BASELINE_SATURATED" in bounded.non_authoritative_reasons
    assert bounded.comparable_with_primary is False
    assert bounded.policy_fingerprint != report.analysis.provenance.policy_fingerprint


def test_evidence_and_findings_remain_traceable(report):
    evidence = {e.id: e for e in report.environment.evidence}
    relationships = {r.id: r for r in report.environment.relationships}
    for path in report.baseline.paths:
        for step in path.steps:
            relationship = relationships[step.relationship_id]
            assert step.evidence_ids == relationship.evidence_ids
            assert step.resolved_confidence == relationship.resolved_confidence
            for evidence_id in step.evidence_ids:
                assert step.relationship_id in evidence[evidence_id].supports_relationship_ids
    for finding in report.environment.findings:
        for evidence_id in finding.supporting_evidence_ids:
            assert finding.id in evidence[evidence_id].supports_finding_ids
    stale = evidence[next(e.id for e in F.evidence if e.key == "edr-session")]
    assert (stale.recorded_confidence, stale.confidence_at_evaluation) == ("HIGH", "MEDIUM")
    inferred = relationships[F.relationship("web-runs-as-svc-deploy").id]
    assert (inferred.truth_tier, inferred.evidence_ids, inferred.resolved_confidence) == ("INFERRED", [], "UNKNOWN")


# --- Determinism and committed examples -------------------------------------------

async def test_repeated_runs_are_byte_identical(database_url, report):
    again = await run_showcase(database_url, _identity())
    assert again.model_dump_json() == report.model_dump_json()
    assert render_artifacts(again) == render_artifacts(report)


def test_committed_example_artifacts_match_a_fresh_run(report):
    """docs/showcase/ is generated output; it must never drift from the engine."""
    for name, content in render_artifacts(report).items():
        committed = (EXAMPLES_DIR / name).read_text(encoding="utf-8").replace("\r\n", "\n")
        assert committed == content, f"docs/showcase/{name} is stale; regenerate it with python -m app.showcase"


def test_json_artifact_round_trips_through_the_schema(report):
    from app.showcase.report import ShowcaseReport

    payload = render_artifacts(report)["showcase.json"]
    assert ShowcaseReport.model_validate_json(payload) == report
    assert json.loads(payload)["project"]["schema_version"] == "attackgraph-showcase-v1"


# --- Safety -----------------------------------------------------------------------

async def test_run_leaves_no_canonical_data_behind(database_url, report):
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            for table in Base.metadata.sorted_tables:
                assert (await connection.execute(select(table).limit(1))).first() is None, table.name
    finally:
        await engine.dispose()


async def test_refuses_a_database_that_already_contains_data(pg_session):
    pg_session.add(Entity(entity_type="HOST", name="pre-existing", canonical_key="host:pre-existing"))
    await pg_session.flush()
    with pytest.raises(ShowcaseDatabaseNotReady, match="not empty"):
        await analyze(pg_session, _identity())


async def test_refuses_a_database_not_at_the_alembic_head(pg_session):
    await pg_session.execute(text("UPDATE alembic_version SET version_num = '0001_initial'"))
    with pytest.raises(ShowcaseDatabaseNotReady, match="not the Alembic head"):
        await analyze(pg_session, _identity())


# --- The real engine, not hard-coded results ---------------------------------------

async def test_showcase_uses_the_real_risk_engine(database_url, report, monkeypatch):
    original = RiskEngine.calculate
    calls = []

    def halved(risk_input, formula_version="risk-v1"):
        result = original(risk_input, formula_version=formula_version)
        calls.append(formula_version)
        return result.model_copy(update={"numeric_risk": result.numeric_risk / 2})

    monkeypatch.setattr(RiskEngine, "calculate", staticmethod(halved))
    perturbed = await run_showcase(database_url, _identity())

    assert calls and set(calls) == {"risk-v1"}
    for before, after in zip(report.baseline.paths, perturbed.baseline.paths):
        assert after.path_id == before.path_id
        assert after.risk.numeric_risk == before.risk.numeric_risk / 2
    assert perturbed.baseline.environment_risk < report.baseline.environment_risk


async def test_showcase_results_follow_the_canonical_data(database_url, monkeypatch):
    without_choke = dataclasses.replace(
        F, relationships=tuple(r for r in F.relationships if r.key != "svc-deploy-assume-db-admin")
    )
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                from sqlalchemy.ext.asyncio import AsyncSession

                session = AsyncSession(bind=connection, expire_on_commit=False)
                result = await analyze(session, _identity(), fixture=without_choke)
                await session.close()
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
    assert result.baseline.path_count == 4
    assert result.remediation.featured_relationship_id != F.relationship("svc-deploy-assume-db-admin").id


# --- Command line -------------------------------------------------------------------

def _run_cli(database_url: str, output_dir: Path, hash_seed: str = "0", script: str | None = None):
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["PYTHONHASHSEED"] = hash_seed
    command = [sys.executable, "-c", script] if script else [sys.executable, "-m", "app.showcase"]
    return subprocess.run(
        command + ["--output-dir", str(output_dir), "--engine-metadata", NO_ENGINE_METADATA],
        cwd=BACKEND_DIR, env=env, capture_output=True, text=True,
    )


def test_showcase_command_succeeds_and_is_deterministic_across_processes(database_url, tmp_path):
    first = _run_cli(database_url, tmp_path / "a", hash_seed="0")
    second = _run_cli(database_url, tmp_path / "b", hash_seed="12345")
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "plausible paths:        11" in first.stdout
    password = make_url(database_url).password
    if password:
        assert password not in first.stdout + first.stderr
    for name in ARTIFACT_FILENAMES:
        a = (tmp_path / "a" / name).read_bytes()
        assert a == (tmp_path / "b" / name).read_bytes(), name
        assert b"\r\n" not in a
        committed = (EXAMPLES_DIR / name).read_bytes().replace(b"\r\n", b"\n")
        assert a == committed, name


_NETWORK_GUARD = r"""
import asyncio, os, sys
from sqlalchemy.engine import make_url

allowed = {"localhost", "127.0.0.1", "::1", make_url(os.environ["DATABASE_URL"]).host}
seen = []

def guard(event, args):
    if event == "socket.connect":
        address = args[1]
        host = address[0] if isinstance(address, tuple) else str(address)
        seen.append(host)
        if host not in allowed:
            raise RuntimeError(f"blocked network connection to {host}")
    elif event == "socket.getaddrinfo":
        host = args[0].decode() if isinstance(args[0], bytes) else args[0]
        if host is not None and host not in allowed:
            raise RuntimeError(f"blocked name resolution of {host}")

sys.addaudithook(guard)
if sys.platform == "win32":
    # The selector loop connects through socket.connect, which raises the audit event.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app.showcase.__main__ import main
code = main(sys.argv[1:])
if not seen:
    raise SystemExit("guard observed no connections; the check would be vacuous")
print("GUARDED CONNECTIONS:", sorted(set(seen)))
raise SystemExit(code)
"""


def test_showcase_needs_no_network_access_beyond_the_database(database_url, tmp_path):
    result = _run_cli(database_url, tmp_path, script=_NETWORK_GUARD)
    assert result.returncode == 0, result.stderr
    assert "GUARDED CONNECTIONS:" in result.stdout
