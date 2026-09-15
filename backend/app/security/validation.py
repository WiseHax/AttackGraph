"""Input validation utilities for security-sensitive operations.

Provides size limits, safe JSON parsing, and string validation
used by schemas and ingestion.
"""

import json
from typing import Any

# --- Size limits ---
MAX_JSON_FIELD_BYTES = 1_048_576  # 1 MB
MAX_STRING_LENGTH = 4096
MAX_IMPORT_PAYLOAD_BYTES = 10_485_760  # 10 MB


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def validate_json_size(data: Any, field_name: str = "json_field") -> None:
    """Validate that a JSON-serializable object does not exceed size limits.

    Raises ValidationError if the serialized size exceeds MAX_JSON_FIELD_BYTES.
    """
    if data is None:
        return
    serialized = json.dumps(data, default=str)
    if len(serialized.encode("utf-8")) > MAX_JSON_FIELD_BYTES:
        raise ValidationError(
            f"{field_name} exceeds maximum size of {MAX_JSON_FIELD_BYTES} bytes"
        )


def validate_string_length(
    value: str | None,
    field_name: str = "field",
    max_length: int = MAX_STRING_LENGTH,
) -> None:
    """Validate string length.

    Raises ValidationError if the string exceeds max_length.
    """
    if value is not None and len(value) > max_length:
        raise ValidationError(
            f"{field_name} exceeds maximum length of {max_length} characters"
        )


def safe_parse_json(
    raw: str | bytes,
    max_size: int = MAX_IMPORT_PAYLOAD_BYTES,
    source: str = "input",
) -> Any:
    """Safely parse JSON with size limits.

    Raises ValidationError if the input exceeds max_size or is invalid JSON.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    else:
        raw_bytes = raw

    if len(raw_bytes) > max_size:
        raise ValidationError(
            f"{source} exceeds maximum payload size of {max_size} bytes"
        )

    try:
        return json.loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValidationError(f"Invalid JSON in {source}: {e}") from e
