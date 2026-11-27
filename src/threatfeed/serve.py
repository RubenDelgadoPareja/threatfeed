"""`python -m threatfeed.serve`: start the API with proxy trust taken from settings.

uvicorn trusts `127.0.0.1` by default and reads `FORWARDED_ALLOW_IPS` from the environment.
Both are implicit and easy to get wrong, so the server is launched from here instead: one
setting (`TRUSTED_PROXIES`) decides whether any forwarding header is believed, and an empty
value disables proxy headers entirely.
"""

import uvicorn

from threatfeed.config import Settings, get_settings

HOST = "0.0.0.0"
PORT = 8000


def proxy_options(settings: Settings) -> dict[str, object]:
    """The uvicorn options that wire `TRUSTED_PROXIES` to its ProxyHeadersMiddleware."""
    return {
        "proxy_headers": bool(settings.trusted_proxies),
        "forwarded_allow_ips": settings.trusted_proxies or None,
    }


def main() -> None:
    uvicorn.run("threatfeed.main:app", host=HOST, port=PORT, **proxy_options(get_settings()))


if __name__ == "__main__":
    main()
