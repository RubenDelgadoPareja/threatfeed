"""Extract matchable observables from nginx `combined` access log lines.

Only the client IP and absolute URLs in the request/referer are extracted: an origin-form path
(`GET /x HTTP/1.1`) has no host, and guessing it would produce false positives.
"""

import re
from dataclasses import dataclass

from threatfeed.classification import InvalidIndicator, classify_indicator
from threatfeed.models import IndicatorType

COMBINED = re.compile(
    r"^(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>.*)"$'
)


@dataclass(frozen=True)
class Observable:
    type: IndicatorType
    value: str
    field: str


def parse_line(line: str) -> list[Observable] | None:
    """Return the observables of one line, or None when it is not a combined log line."""
    match = COMBINED.match(line.rstrip("\r\n"))
    if match is None:
        return None

    observables: list[Observable] = []
    _add(observables, match["remote_addr"], "remote_addr")

    request_parts = match["request"].split()
    if len(request_parts) == 3:
        _add(observables, request_parts[1], "request", absolute_url_only=True)

    referer = match["referer"].strip()
    if referer and referer != "-":
        _add(observables, referer, "referer", absolute_url_only=True)

    return observables


def _add(
    observables: list[Observable],
    raw: str,
    field: str,
    *,
    absolute_url_only: bool = False,
) -> None:
    value = raw.strip()
    if not value or value == "-":
        return
    if absolute_url_only and not value.lower().startswith(("http://", "https://")):
        return

    try:
        indicator_type, normalized = classify_indicator(value)
    except InvalidIndicator:
        return

    observables.append(Observable(type=indicator_type, value=normalized, field=field))
