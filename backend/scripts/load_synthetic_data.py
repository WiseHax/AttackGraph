"""Synthetic dataset loader for AttackGraph.

Creates a minimal, deterministic topology to test graph projection logic.
Strictly adheres to the existing Phase 1 database constraints.
"""

import uuid
from typing import TypedDict

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import (
    Entity,
    Evidence,
    Finding,
    FindingEvidence,
    Relationship,
    RelationshipEvidence,
)


class SyntheticTopology(TypedDict):
    entities: dict[str, uuid.UUID]
    relationships: dict[str, uuid.UUID]


async def load_synthetic_topology(session: AsyncSession) -> SyntheticTopology:
    """Populates the database with a deterministic synthetic dataset.

    Creates:
    - 1 Network Segment (corp_lan)
    - 2 Identities (admin, analyst)
    - 3 Assets (jump_host, app_prod, customer_data)
    - 3 Relationships (CAN_AUTHENTICATE_TO, ROUTES_TO, DEPENDS_ON)
    - 1 Evidence item
    - 1 Finding on jump_host
    """
    # 1. Create Entities
    entities = {
        "corp_lan": Entity(
            entity_type="NETWORK_SEGMENT",
            name="corp_lan",
            canonical_key="segment:corp_lan",
        ),
        "admin": Entity(
            entity_type="USER",
            name="admin_user",
            canonical_key="user:admin",
        ),
        "analyst": Entity(
            entity_type="USER",
            name="analyst_user",
            canonical_key="user:analyst",
        ),
        "jump_host": Entity(
            entity_type="SERVER",
            name="jump_host",
            canonical_key="server:jump_host",
            criticality="HIGH",
        ),
        "app_prod": Entity(
            entity_type="SERVER",
            name="app_prod",
            canonical_key="server:app_prod",
            criticality="CRITICAL",
        ),
        "customer_data": Entity(
            entity_type="DATABASE",
            name="customer_data",
            canonical_key="db:customer_data",
            criticality="CRITICAL",
        ),
    }

    for ent in entities.values():
        session.add(ent)
    await session.flush()

    # 2. Create Evidence
    ev_scanner = Evidence(
        source="synthetic-scanner",
        source_type="vulnerability_scanner",
        assertion="Host routes to app_prod on port 443",
        confidence="HIGH",
    )
    session.add(ev_scanner)
    await session.flush()

    # 3. Create Relationships
    rels = {
        "admin_auth_jump": Relationship(
            source_entity_id=entities["admin"].id,
            target_entity_id=entities["jump_host"].id,
            relationship_type="CAN_AUTHENTICATE_TO",
            truth_tier="OBSERVED",
            confidence="HIGH",
        ),
        "jump_routes_app": Relationship(
            source_entity_id=entities["jump_host"].id,
            target_entity_id=entities["app_prod"].id,
            relationship_type="ROUTES_TO",
            truth_tier="OBSERVED",
            confidence="HIGH",
        ),
        "app_depends_db": Relationship(
            source_entity_id=entities["app_prod"].id,
            target_entity_id=entities["customer_data"].id,
            relationship_type="DEPENDS_ON",
            truth_tier="INFERRED",
        ),
    }

    for rel in rels.values():
        session.add(rel)
    await session.flush()

    # Link evidence to jump_routes_app
    rel_ev = RelationshipEvidence(
        relationship_id=rels["jump_routes_app"].id,
        evidence_id=ev_scanner.id,
    )
    session.add(rel_ev)

    # 4. Create Finding (attached to jump_host)
    finding = Finding(
        entity_id=entities["jump_host"].id,
        title="Outdated OpenSSH",
        severity="CRITICAL",
        source="synthetic-scanner",
        source_type="vulnerability_scanner",
        source_reference="CVE-2024-XXXX",
    )
    session.add(finding)
    await session.flush()

    # We do not strictly need to link the finding to the evidence here, 
    # but the domain supports it via FindingEvidence if we wanted.

    return {
        "entities": {k: v.id for k, v in entities.items()},
        "relationships": {k: v.id for k, v in rels.items()},
    }
