import pytest

from threatfeed.ingest.normalize import InvalidUrl, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.COM:80/Path?Q=1#frag", "http://example.com/Path?Q=1"),
        ("https://example.com.:443/", "https://example.com/"),
        ("https://example.com:8443/a", "https://example.com:8443/a"),
        ("http://user:pass@Example.com:8080/x", "http://user:pass@example.com:8080/x"),
        ("http://[2001:DB8::1]:80/x", "http://[2001:db8::1]/x"),
        ("http://example.com", "http://example.com"),
        ("  http://example.com/a  ", "http://example.com/a"),
    ],
)
def test_normalize_url_canonicalizes_what_varies_between_feeds(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "example.com/path",
        "ftp://example.com/file",
        "http://",
        "http://example.com:not-a-port/",
    ],
)
def test_normalize_url_rejects_unusable_values(raw: str) -> None:
    with pytest.raises(InvalidUrl):
        normalize_url(raw)
