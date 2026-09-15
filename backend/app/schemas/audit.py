"""Pydantic schemas for AuditLog validation."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict


class AuditLogCreate(BaseModel):
    """Schema for creating an audit log entry."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(..., min_length=1, max_length=256)
    entity_type: str | None = Field(default=None, max_length=256)
    entity_id: str | None = Field(default=None, max_length=256)
    actor: str | None = Field(default=None, max_length=256)
    detail: dict | None = None


class AuditLogResponse(BaseModel):
    """Schema for AuditLog API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    action: str
    entity_type: str | None = None
    entity_id: str | None = None
    actor: str | None = None
    detail: dict | None = None
    timestamp: datetime
