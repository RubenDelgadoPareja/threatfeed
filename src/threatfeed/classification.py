"""Infer the type of a user-supplied indicator and reduce it to its stored form.

The API cannot trust the caller to say whether a value is an IP, a domain, a URL or a hash, and
it must normalize the value with the same rules used at ingestion or lookups miss.
"""

import ipaddress
import re

from threatfeed.models import IndicatorType
from threatfeed.normalize import InvalidUrl, normalize_url

MAX_VALUE_LENGTH = 2_048

_MD5 = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InvalidIndicator(ValueError):
    """The value is not a recognizable indicator."""


def classify_indicator(raw: str) -> tuple[IndicatorType, str]:
    """Return `(type, normalized_value)` or raise `InvalidIndicator`."""
    value = raw.strip()
    if not value:
        raise InvalidIndicator("empty value")
    if len(value) > MAX_VALUE_LENGTH:
        raise InvalidIndicator(f"value exceeds {MAX_VALUE_LENGTH} characters")

    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        try:
            return IndicatorType.URL, normalize_url(value)
        except InvalidUrl as exc:
            raise InvalidIndicator(str(exc)) from exc

    try:
        return IndicatorType.IP, str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if _MD5.fullmatch(lowered):
        return IndicatorType.HASH_MD5, lowered
    if _SHA256.fullmatch(lowered):
        return IndicatorType.HASH_SHA256, lowered

    domain = value.rstrip(".").lower()
    if _is_domain(domain):
        return IndicatorType.DOMAIN, domain

    raise InvalidIndicator("not an IP, domain, URL or hash")


def _is_domain(domain: str) -> bool:
    if not domain.isascii() or len(domain) > 253:
        return False

    labels = domain.split(".")
    # A single label is not an internet domain; a numeric TLD is almost certainly not one.
    if len(labels) < 2 or labels[-1].isdigit():
        return False

    return all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
