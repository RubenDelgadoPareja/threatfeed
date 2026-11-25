import pytest

from threatfeed.classification import InvalidIndicator, classify_indicator
from threatfeed.models import IndicatorType


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_value"),
    [
        ("HTTP://Example.COM:80/a?b=1#frag", IndicatorType.URL, "http://example.com/a?b=1"),
        ("https://example.com./x", IndicatorType.URL, "https://example.com/x"),
        ("1.2.3.4", IndicatorType.IP, "1.2.3.4"),
        ("2001:0DB8::1", IndicatorType.IP, "2001:db8::1"),
        (
            "D41D8CD98F00B204E9800998ECF8427E",
            IndicatorType.HASH_MD5,
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        ("A" * 64, IndicatorType.HASH_SHA256, "a" * 64),
        ("Example.COM.", IndicatorType.DOMAIN, "example.com"),
        ("sub.example.co.uk", IndicatorType.DOMAIN, "sub.example.co.uk"),
        ("xn--bcher-kva.example", IndicatorType.DOMAIN, "xn--bcher-kva.example"),
    ],
)
def test_classify_indicator(raw: str, expected_type: IndicatorType, expected_value: str) -> None:
    assert classify_indicator(raw) == (expected_type, expected_value)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "example.com/path",
        "ftp://example.com/file",
        "1.2.3.4:8080",
        "localhost",
        "not a domain",
        "1.2.3.4.5",
        "256.1.1.1",
        "123.456",
        "münich.example",
        "a" * 31,
        "a" * 63,
        "http://",
        "a" * 2_049,
    ],
)
def test_classify_indicator_rejects_unusable_values(raw: str) -> None:
    with pytest.raises(InvalidIndicator):
        classify_indicator(raw)
