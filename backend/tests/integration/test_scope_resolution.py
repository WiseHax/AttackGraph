"""PostgreSQL integration tests for exact-version scope resolution (Q2, ARCH-28).

Categories:
- Invariant: resolution is exact-version only, never "latest", fails closed on
  a missing definition, and performs no database writes.
- Semantic: a projection built through a resolved scope is identical to one
  built through the equivalent ad-hoc v1 scope, and so are the analytical
  results computed over it.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.analytics.counterfactual import CounterfactualEngine
from app.domain.models import Scope, ScopeDefinition
from app.graph.builder import GraphBuilder
from app.graph.networkx import NetworkXStore
from app.graph.scope_resolution import ScopeResolutionError, resolve_analytical_scope
from app.schemas.analytics import AnalyticalScope
from app.storage.repositories import ScopeDefinitionRepository
from scripts.load_synthetic_data import load_synthetic_topology

pytestmark = pytest.mark.integration

AD_HOC_SCOPE = AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL")


async def _create_scope(session, versions: int) -> uuid.UUID:
    """Persist a scope with `versions` immutable v1 definitions, then clear the identity map."""
    scope = Scope(display_name="Resolution Test Scope")
    session.add(scope)
    await session.flush()
    repo = ScopeDefinitionRepository(session)
    for _ in range(versions):
        await repo.create(scope.id, ScopeDefinition(input_boundary_kind="UNIVERSAL", reporting_selector="ALL"))
    scope_id = scope.id
    # Force resolution to read from PostgreSQL rather than the session identity map.
    session.expunge_all()
    return scope_id


async def test_exact_version_resolves_with_identity_and_v1_semantics(pg_session):
    scope_id = await _create_scope(pg_session, versions=1)

    resolved = await resolve_analytical_scope(pg_session, scope_id, 1)

    assert isinstance(resolved, AnalyticalScope)
    assert resolved.scope_id == scope_id
    assert resolved.definition_version == 1
    assert resolved.input_boundary_kind == "UNIVERSAL"
    assert resolved.reporting_selector == "ALL"


async def test_older_version_resolves_when_newer_version_exists(pg_session):
    scope_id = await _create_scope(pg_session, versions=2)

    v1 = await resolve_analytical_scope(pg_session, scope_id, 1)
    v2 = await resolve_analytical_scope(pg_session, scope_id, 2)

    assert (v1.scope_id, v1.definition_version) == (scope_id, 1)
    assert (v2.scope_id, v2.definition_version) == (scope_id, 2)


async def test_missing_version_never_falls_back_to_latest(pg_session):
    scope_id = await _create_scope(pg_session, versions=2)

    with pytest.raises(ScopeResolutionError, match="does not exist"):
        await resolve_analytical_scope(pg_session, scope_id, 3)
    with pytest.raises(ScopeResolutionError):
        await resolve_analytical_scope(pg_session, scope_id, None)


async def test_missing_scope_raises(pg_session):
    await _create_scope(pg_session, versions=1)

    with pytest.raises(ScopeResolutionError, match="does not exist"):
        await resolve_analytical_scope(pg_session, uuid.UUID(int=0xDEAD), 1)


async def test_resolution_performs_no_database_mutation(pg_session):
    scope_id = await _create_scope(pg_session, versions=2)
    snapshot_sql = text(
        "SELECT "
        "(SELECT count(*) FROM scopes), "
        "(SELECT count(*) FROM scope_definitions), "
        "(SELECT md5(coalesce(string_agg(id::text || display_name || created_at::text || updated_at::text, ',' ORDER BY id), '')) FROM scopes), "
        "(SELECT md5(coalesce(string_agg(scope_id::text || ':' || version::text || input_boundary_kind || reporting_selector "
        "|| coalesce(selector_parameters::text, '-') || coalesce(declared_normalization, '-') || created_at::text, ',' "
        "ORDER BY scope_id, version), '')) FROM scope_definitions)"
    )
    before = (await pg_session.execute(snapshot_sql)).one()

    await resolve_analytical_scope(pg_session, scope_id, 1)
    await resolve_analytical_scope(pg_session, scope_id, 2)
    with pytest.raises(ScopeResolutionError):
        await resolve_analytical_scope(pg_session, scope_id, 3)

    assert not pg_session.new
    assert not pg_session.dirty
    assert not pg_session.deleted
    after = (await pg_session.execute(snapshot_sql)).one()
    assert after == before


async def test_resolved_scope_projection_and_analysis_match_ad_hoc_scope(pg_session):
    topology = await load_synthetic_topology(pg_session)
    entities, rels = topology["entities"], topology["relationships"]
    scope_id = await _create_scope(pg_session, versions=1)
    resolved = await resolve_analytical_scope(pg_session, scope_id, 1)

    resolved_store, ad_hoc_store = NetworkXStore(), NetworkXStore()
    await GraphBuilder(pg_session, resolved_store).build(resolved)
    await GraphBuilder(pg_session, ad_hoc_store).build(AD_HOC_SCOPE)

    def graph_state(store):
        nodes = sorted(store.graph.nodes(data=True), key=lambda n: str(n[0]))
        edges = sorted(store.graph.edges(keys=True, data=True), key=lambda e: str(e[2]))
        return nodes, edges

    assert graph_state(resolved_store) == graph_state(ad_hoc_store)
    assert resolved_store.graph.number_of_nodes() == 6
    assert resolved_store.graph.number_of_edges() == 3

    eval_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    candidates = sorted(rels.values(), key=str)
    rankings = [
        CounterfactualEngine(store, {}).evaluate_candidates(
            entities["admin"], entities["customer_data"], candidates, eval_time
        )
        for store in (resolved_store, ad_hoc_store)
    ]
    assert rankings[0].baseline_path_count == 1
    assert rankings[0].model_dump_json() == rankings[1].model_dump_json()


async def test_ad_hoc_scope_still_builds_projection(pg_session):
    await load_synthetic_topology(pg_session)
    store = NetworkXStore()

    await GraphBuilder(pg_session, store).build(AD_HOC_SCOPE)

    assert store.graph.number_of_nodes() == 6
    assert store.graph.number_of_edges() == 3
