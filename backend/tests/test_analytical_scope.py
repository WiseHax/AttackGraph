"""Unit tests for AnalyticalScope canonical identity and resolver fail-closed paths (Q2, ARCH-28).

Categories:
- Invariant: scope identity is both-or-neither; v1 semantics are UNIVERSAL/ALL
  only; ad-hoc (identity-less) scopes remain valid for non-persisted runs.
- Negative: the resolver rejects implicit or malformed versions before any
  database access, and fails closed on definitions outside v1.
"""

import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.graph import scope_resolution
from app.graph.scope_resolution import ScopeResolutionError, resolve_analytical_scope
from app.schemas.analytics import AnalyticalScope

SCOPE_ID = uuid.UUID(int=42)


def test_ad_hoc_scope_without_identity_is_valid():
    scope = AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL")
    assert scope.scope_id is None
    assert scope.definition_version is None


def test_scope_with_complete_identity_is_valid():
    scope = AnalyticalScope(
        input_boundary_kind="UNIVERSAL", reporting_selector="ALL",
        scope_id=SCOPE_ID, definition_version=3,
    )
    assert scope.scope_id == SCOPE_ID
    assert scope.definition_version == 3


@pytest.mark.parametrize(
    "identity",
    [{"scope_id": SCOPE_ID}, {"definition_version": 1}],
)
def test_partial_identity_is_rejected(identity):
    with pytest.raises(ValidationError, match="both be present or both be absent"):
        AnalyticalScope(input_boundary_kind="UNIVERSAL", reporting_selector="ALL", **identity)


@pytest.mark.parametrize("version", [0, -1, True, "1", 1.0])
def test_invalid_definition_version_is_rejected(version):
    with pytest.raises(ValidationError):
        AnalyticalScope(
            input_boundary_kind="UNIVERSAL", reporting_selector="ALL",
            scope_id=SCOPE_ID, definition_version=version,
        )


@pytest.mark.parametrize(
    "overrides",
    [{"input_boundary_kind": "ENVIRONMENT"}, {"reporting_selector": "ENVIRONMENT_EQUALS"}],
)
def test_only_v1_universal_all_semantics_are_accepted(overrides):
    kwargs = {"input_boundary_kind": "UNIVERSAL", "reporting_selector": "ALL", **overrides}
    with pytest.raises(ValidationError):
        AnalyticalScope(**kwargs)


def test_scope_is_immutable():
    scope = AnalyticalScope(
        input_boundary_kind="UNIVERSAL", reporting_selector="ALL",
        scope_id=SCOPE_ID, definition_version=1,
    )
    with pytest.raises(ValidationError):
        scope.definition_version = 2


@pytest.mark.parametrize(
    "scope_id, version",
    [
        (SCOPE_ID, None),     # no implicit "latest"
        (SCOPE_ID, 0),
        (SCOPE_ID, True),
        (SCOPE_ID, "1"),
        (str(SCOPE_ID), 1),
        (None, 1),
    ],
)
async def test_resolver_rejects_implicit_or_malformed_arguments_before_db_access(scope_id, version):
    # session=None: argument validation must fail before any session use.
    with pytest.raises(ScopeResolutionError):
        await resolve_analytical_scope(None, scope_id, version)


@pytest.mark.parametrize(
    "fields",
    [
        {"input_boundary_kind": "ENVIRONMENT"},
        {"reporting_selector": "ENVIRONMENT_EQUALS"},
        {"selector_parameters": {"environment": "production"}},
        {"declared_normalization": "PER_ASSET"},
    ],
)
async def test_resolver_fails_closed_on_non_v1_definition(monkeypatch, fields):
    """The DB CHECK constraints forbid these today; the resolver must not rely on that alone."""
    definition = SimpleNamespace(
        scope_id=SCOPE_ID, version=1, input_boundary_kind="UNIVERSAL", reporting_selector="ALL",
        selector_parameters=None, declared_normalization=None,
    )
    for key, value in fields.items():
        setattr(definition, key, value)

    async def fake_get_by_id(self, scope_id, version):
        return definition

    monkeypatch.setattr(scope_resolution.ScopeDefinitionRepository, "get_by_id", fake_get_by_id)

    with pytest.raises(ScopeResolutionError, match="unsupported by v1 resolution"):
        await resolve_analytical_scope(None, SCOPE_ID, 1)
