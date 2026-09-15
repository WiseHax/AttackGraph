"""Domain enumerations for AttackGraph.

These enums define the controlled vocabularies for the domain model.
They are used by SQLAlchemy models (as PostgreSQL enums) and Pydantic schemas.

IMPORTANT — Truth Tier Design:
    TruthTier contains ONLY 'OBSERVED' and 'INFERRED'.
    'ANALYTICAL' is deliberately excluded from the persistence enum.
    Analytical conclusions (attack paths, risk scores) are computed results
    and must NEVER be persisted as observed graph relationships.
    This is enforced structurally: the PostgreSQL enum type will not accept
    'ANALYTICAL', and the Pydantic schemas will reject it.
"""

import enum


class TruthTier(str, enum.Enum):
    """Truth tier for persisted relationships.

    OBSERVED: A source directly asserted or observed the relationship.
    INFERRED: The relationship was derived from known observations
              according to an explicit rule.

    ANALYTICAL is intentionally excluded. Analytical conclusions
    (e.g., "attack path exists") are NOT graph edges and must not
    be persisted as relationships. This exclusion is structural,
    not merely conventional.
    """

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"


class Confidence(str, enum.Enum):
    """Confidence level for relationships and evidence."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Criticality(str, enum.Enum):
    """Criticality level for entities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Exposure(str, enum.Enum):
    """Exposure level for entities."""

    EXTERNAL = "EXTERNAL"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"
    ISOLATED = "ISOLATED"


class EntityType(str, enum.Enum):
    """Types of security-relevant entities."""

    INTERNET = "INTERNET"
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    HOST = "HOST"
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    CONTAINER = "CONTAINER"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    APPLICATION = "APPLICATION"
    API = "API"
    DATABASE = "DATABASE"
    USER = "USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    GROUP = "GROUP"
    ROLE = "ROLE"
    REPOSITORY = "REPOSITORY"
    NETWORK_SEGMENT = "NETWORK_SEGMENT"


class RelationshipType(str, enum.Enum):
    """Types of directed security relationships."""

    EXPOSES = "EXPOSES"
    ROUTES_TO = "ROUTES_TO"
    CAN_AUTHENTICATE_TO = "CAN_AUTHENTICATE_TO"
    RUNS_AS = "RUNS_AS"
    HAS_PERMISSION_ON = "HAS_PERMISSION_ON"
    MEMBER_OF = "MEMBER_OF"
    CAN_ASSUME = "CAN_ASSUME"
    DEPENDS_ON = "DEPENDS_ON"
    STORES = "STORES"
    TRUSTS = "TRUSTS"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"


class FindingSeverity(str, enum.Enum):
    """Severity level for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
