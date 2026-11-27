"""Proxy-header trust: only a configured proxy may speak for the client.

The middleware is uvicorn's; these tests pin the wiring we choose (which peers are trusted and
which hop wins) so a settings change cannot silently let any client forge its address.
"""

import asyncio
from typing import Any

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from threatfeed.config import Settings
from threatfeed.serve import proxy_options

CADDY = ("172.28.0.2", 51234)
ELSEWHERE = ("203.0.113.50", 51234)


class Recorder:
    """Minimal ASGI app that records the scope the wrapped middleware produced."""

    def __init__(self) -> None:
        self.client: tuple[str, int] | None = None
        self.scheme: str | None = None

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.client = scope["client"]
        self.scheme = scope["scheme"]


def call(peer: tuple[str, int], headers: dict[str, str] | None = None) -> Recorder:
    recorder = Recorder()
    options = proxy_options(Settings(_env_file=None, trusted_proxies=CADDY[0]))
    app = ProxyHeadersMiddleware(recorder, trusted_hosts=options["forwarded_allow_ips"])

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (name.lower().encode("latin1"), value.encode("latin1"))
            for name, value in (headers or {}).items()
        ],
        "client": peer,
        "server": ("api", 8000),
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        return None

    asyncio.run(app(scope, receive, send))
    return recorder


def test_an_untrusted_peer_cannot_forge_its_address() -> None:
    recorder = call(ELSEWHERE, {"X-Forwarded-For": "198.51.100.9"})

    assert recorder.client == ELSEWHERE
    assert recorder.scheme == "http"


def test_the_trusted_proxy_speaks_for_the_client() -> None:
    recorder = call(CADDY, {"X-Forwarded-For": "198.51.100.9"})

    assert recorder.client is not None
    assert recorder.client[0] == "198.51.100.9"


def test_the_rightmost_untrusted_hop_wins() -> None:
    # A client that sends its own X-Forwarded-For gets appended to, not believed.
    recorder = call(CADDY, {"X-Forwarded-For": "192.0.2.1, 198.51.100.9"})

    assert recorder.client is not None
    assert recorder.client[0] == "198.51.100.9"


def test_the_trusted_proxy_can_report_https() -> None:
    recorder = call(CADDY, {"X-Forwarded-Proto": "https"})

    assert recorder.scheme == "https"


def test_an_untrusted_peer_cannot_report_https() -> None:
    recorder = call(ELSEWHERE, {"X-Forwarded-Proto": "https"})

    assert recorder.scheme == "http"
