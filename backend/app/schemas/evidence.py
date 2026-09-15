"""Pydantic schemas for Evidence validation."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict

from app.domain.enums import Confidence


class EvidenceCreate(BaseModel):
    """Schema for creating a new Evidence record."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., min_length=1, max_length=512)
    source_type: str = Field(..., min_length=1, max_length=256)
    assertion: str = Field(..., min_length=1, max_length=4096)
    collected_at: datetime | None = None
    confidence: Confidence | None = None
    freshness_ttl_seconds: int | None = Field(default=None, ge=0)
    raw_reference: dict | None = None
    metadata: dict | None = None


class EvidenceResponse(BaseModel):
    """Schema for Evidence API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    source_type: str
    assertion: str
    collected_at: datetime | None = None
    imported_at: datetime
    confidence: Confidence | None = None
    freshness_ttl_seconds: int | None = None
    raw_reference: dict | None = None
    metadata: dict | None = None
    created_at: datetime
