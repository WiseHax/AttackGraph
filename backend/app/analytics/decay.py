"""Evidence decay and resolution policies."""

from datetime import datetime
from typing import Any


CONFIDENCE_TIERS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH"]


def _downgrade_confidence(confidence: str | None) -> str:
    if not confidence:
        return "UNKNOWN"

    try:
        idx = CONFIDENCE_TIERS.index(confidence)
        if idx > 0:
            return CONFIDENCE_TIERS[idx - 1]
        return "UNKNOWN"
    except ValueError:
        return "UNKNOWN"


def apply_decay(evidence: dict[str, Any], evaluation_time: datetime) -> str:
    """Apply decay-policy-v1 (threshold-based confidence downgrade)."""
    raw_confidence = evidence.get("confidence") or "UNKNOWN"

    if evaluation_time is None:
        raise ValueError("evaluation_time must be provided for deterministic analysis")

    collected_at = evidence.get("collected_at")
    ttl = evidence.get("freshness_ttl_seconds")

    if not collected_at or not ttl or ttl <= 0:
        return raw_confidence

    # Check if strictly stale
    expiration_time = collected_at.timestamp() + ttl
    if evaluation_time.timestamp() > expiration_time:
        return _downgrade_confidence(raw_confidence)

    return raw_confidence


def resolve_edge_evidence(
    raw_evidence_list: list[dict[str, Any]] | None,
    edge_id: str,
    truth_tier: str,
    evaluation_time: datetime,
) -> tuple[str, str]:
    """Resolve multiple evidence records on an edge to a single confidence and source.

    MVP Rule: Temporal Resolution (latest wins), pessimistic fallback.
    """
    if truth_tier == "INFERRED":
        return ("UNKNOWN", f"inference:{edge_id}")

    if not raw_evidence_list:
        return ("UNKNOWN", f"unknown-source:{edge_id}")

    # Apply decay
    resolved_list = []
    for ev in raw_evidence_list:
        dec_conf = apply_decay(ev, evaluation_time)
        resolved_list.append({
            "decayed_conf": dec_conf,
            "collected_at": ev.get("collected_at"),
            "source": ev.get("source") or f"unknown-source:{edge_id}"
        })

    # Sort by collected_at (descending) -> fallback to confidence (descending)
    def sort_key(item: dict[str, Any]) -> tuple[float, int]:
        cat = item["collected_at"]
        tstamp = cat.timestamp() if cat else 0.0

        conf = item["decayed_conf"]
        try:
            c_idx = CONFIDENCE_TIERS.index(conf)
        except ValueError:
            c_idx = 0

        # For pessimistic fallback, we want the MINIMUM confidence.
        # But wait, we sort descending to put the winner at index 0.
        # So we want highest timestamp. If timestamp ties, we want LOWEST confidence index to win!
        # Thus we return -c_idx so that smaller index (lower confidence) is greater (sorted earlier when reverse=True).
        return (tstamp, -c_idx)

    resolved_list.sort(key=sort_key, reverse=True)

    winning_ev = resolved_list[0]
    return (winning_ev["decayed_conf"], winning_ev["source"])
