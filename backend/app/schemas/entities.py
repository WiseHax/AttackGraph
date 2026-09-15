"""Pydantic schemas for Entity validation."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict

from app.domain.enums import Criticality, EntityType, Exposure


class EntityCreate(BaseModel):
    """Schema for creating a new Entity."""

    model_config = ConfigDict(extra="forbid")

    entity_type: EntityType
    name: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=256)
    exposure: Exposure | None = None
    tags: dict | None = None
    canonical_key: str = Field(..., min_length=1, max_length=1024)
    metadata: dict | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class EntityUpdate(BaseModel):
    """Schema for updating an existing Entity.

    All fields are optional; only provided fields are updated.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=256)
    exposure: Exposure | None = None
    tags: dict | None = None
    metadata: dict | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class EntityResponse(BaseModel):
    """Schema for Entity API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entity_type: EntityType
    name: str
    description: str | None = None
    criticality: Criticality | None = None
    owner: str | None = None
    environment: str | None = None
    exposure: Exposure | None = None
    tags: dict | None = None
    canonical_key: str
    metadata: dict | None = None
    created_at: datetime
    updated_at: datetime
    first_seen: datetime | None = None
    last_seen: datetime | None = None
