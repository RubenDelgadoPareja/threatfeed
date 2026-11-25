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
