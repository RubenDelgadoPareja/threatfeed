"""Timestamps shared by the feeds: UTC, with or without a ` UTC` suffix, date or datetime."""

from datetime import UTC, datetime

from threatfeed.ingest.errors import InvalidRow


def parse_utc(value: str) -> datetime:
    """Parse a feed timestamp. Raises `InvalidRow` when it is empty or unparseable."""
    cleaned = value.strip().removesuffix("UTC").strip()
    if not cleaned:
        raise InvalidRow("empty timestamp")

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    raise InvalidRow(f"unparseable timestamp: {value!r}")


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO 8601 timestamp with an offset, normalizing it to UTC."""
    cleaned = value.strip()
    if not cleaned:
        raise InvalidRow("empty timestamp")
    try:
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidRow(f"unparseable timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
