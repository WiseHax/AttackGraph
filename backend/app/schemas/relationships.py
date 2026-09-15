"""Pydantic schemas for Relationship validation.

IMPORTANT: truth_tier only accepts OBSERVED and INFERRED.
ANALYTICAL is rejected at the schema level, matching the DB constraint.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict

from app.domain.enums import Confidence, RelationshipType, TruthTier


class RelationshipCreate(BaseModel):
    """Schema for creating a new Relationship."""

    model_config = ConfigDict(extra="forbid")

    source_entity_id: uuid.UUID
    target_entity_id: uuid.UUID
    relationship_type: RelationshipType
    truth_tier: TruthTier  # Only OBSERVED / INFERRED accepted
    confidence: Confidence | None = None
    observed_at: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    metadata: dict | None = None
    evidence_ids: list[uuid.UUID] | None = None


class RelationshipResponse(BaseModel):
    """Schema for Relationship API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_entity_id: uuid.UUID
    target_entity_id: uuid.UUID
    relationship_type: RelationshipType
    truth_tier: TruthTier
    confidence: Confidence | None = None
    observed_at: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    metadata: dict | None = None
    created_at: datetime
    updated_at: datetime
