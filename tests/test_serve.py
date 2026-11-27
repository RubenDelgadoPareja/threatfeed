"""How the API server is launched: proxy trust comes from settings, not from server defaults."""

from threatfeed.config import Settings
from threatfeed.serve import proxy_options


def test_proxy_headers_are_disabled_without_trusted_proxies() -> None:
    options = proxy_options(Settings(_env_file=None))

    assert options == {"proxy_headers": False, "forwarded_allow_ips": None}


def test_a_trusted_proxy_enables_proxy_headers() -> None:
    settings = Settings(_env_file=None, trusted_proxies="172.28.0.2")

    options = proxy_options(settings)

    assert options == {"proxy_headers": True, "forwarded_allow_ips": "172.28.0.2"}
