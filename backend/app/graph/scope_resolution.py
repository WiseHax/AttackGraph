"""Canonical resolution of persisted scope definitions into analytical scopes.

This is the only bridge from a persisted, immutable ScopeDefinition to the
runtime AnalyticalScope consumed by GraphBuilder (ARCH-28). A persistable or
comparable analysis must obtain its scope here, so that its provenance names
the exact (scope_id, definition_version) that was resolved.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.analytics import AnalyticalScope
from app.storage.repositories import ScopeDefinitionRepository


class ScopeResolutionError(ValueError):
    """Raised when a scope cannot be resolved to exactly one persisted definition."""


async def resolve_analytical_scope(
    session: AsyncSession,
    scope_id: uuid.UUID,
    definition_version: int,
) -> AnalyticalScope:
    """Resolve the exact ScopeDefinition (scope_id, definition_version).

    Never selects the latest version: definition_version is mandatory, and a
    missing definition fails closed rather than falling back to another
    version. Read-only: the session is used for a single primary-key lookup.

    Returns a detached, immutable AnalyticalScope carrying the resolved
    canonical identity and only the v1 fields (UNIVERSAL / ALL).
    """
    if not isinstance(scope_id, uuid.UUID):
        raise ScopeResolutionError("scope_id must be a UUID")
    if isinstance(definition_version, bool) or not isinstance(definition_version, int):
        raise ScopeResolutionError("definition_version must be an explicit integer version")
    if definition_version < 1:
        raise ScopeResolutionError("definition_version must be >= 1")

    definition = await ScopeDefinitionRepository(session).get_by_id(scope_id, definition_version)
    if definition is None:
        raise ScopeResolutionError(
            f"ScopeDefinition (scope_id={scope_id}, version={definition_version}) does not exist"
        )

    # v1 is exactly UNIVERSAL / ALL with no selector parameters or
    # normalization; anything else is a definition this resolver does not
    # understand, so fail closed rather than approximate it.
    if (
        definition.input_boundary_kind != "UNIVERSAL"
        or definition.reporting_selector != "ALL"
        or definition.selector_parameters is not None
        or definition.declared_normalization is not None
    ):
        raise ScopeResolutionError(
            f"ScopeDefinition (scope_id={scope_id}, version={definition_version}) "
            f"has fields unsupported by v1 resolution"
        )

    return AnalyticalScope(
        input_boundary_kind=definition.input_boundary_kind,
        reporting_selector=definition.reporting_selector,
        scope_id=definition.scope_id,
        definition_version=definition.version,
    )
