"""Minimal URL canonicalization: enough to make equal observables compare equal, no more."""

from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidUrl(ValueError):
    """The value cannot be canonicalized into an absolute http(s) URL."""


def normalize_url(raw: str) -> str:
    """Lowercase scheme and host, drop the trailing dot, default port and fragment.

    Path and query are preserved byte for byte: they are case-sensitive and rewriting them can
    point at a different resource. Full RFC 3986 normalization is deliberately out of scope.
    """
    candidate = raw.strip()
    if not candidate:
        raise InvalidUrl("empty URL")

    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise InvalidUrl(str(exc)) from exc

    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidUrl(f"unsupported scheme {scheme or '(missing)'}")

    # `hostname` lowercases for us; only the trailing dot (absolute DNS name) needs removing.
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidUrl("missing host")

    if port == DEFAULT_PORTS[scheme]:
        port = None

    host_part = f"[{host}]" if ":" in host else host
    if parts.username is not None:
        credentials = parts.username
        if parts.password is not None:
            credentials += f":{parts.password}"
        host_part = f"{credentials}@{host_part}"
    netloc = host_part if port is None else f"{host_part}:{port}"

    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))
