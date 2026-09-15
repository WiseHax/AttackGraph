"""Pydantic schemas for Finding validation."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict

from app.domain.enums import Confidence, FindingSeverity


class FindingCreate(BaseModel):
    """Schema for creating a new Finding."""

    model_config = ConfigDict(extra="forbid")

    entity_id: uuid.UUID
    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    severity: FindingSeverity
    source: str = Field(..., min_length=1, max_length=512)
    source_type: str | None = Field(default=None, max_length=256)
    source_reference: str | None = Field(default=None, max_length=1024)
    confidence: Confidence | None = None
    status: str | None = Field(default=None, max_length=64)
    remediation_notes: str | None = Field(default=None, max_length=4096)
    metadata: dict | None = None
    evidence_ids: list[uuid.UUID] | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class FindingResponse(BaseModel):
    """Schema for Finding API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entity_id: uuid.UUID
    title: str
    description: str | None = None
    severity: FindingSeverity
    source: str
    source_type: str | None = None
    source_reference: str | None = None
    confidence: Confidence | None = None
    status: str | None = None
    remediation_notes: str | None = None
    metadata: dict | None = None
    created_at: datetime
    updated_at: datetime
    first_seen: datetime | None = None
    last_seen: datetime | None = None
