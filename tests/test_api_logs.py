from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from threatfeed.models import Indicator, IndicatorSource, IndicatorType

FIXTURE = Path(__file__).parent / "fixtures" / "nginx_access.log"


def _indicator(
    indicator_type: IndicatorType,
    value: str,
    *sources: str,
) -> Indicator:
    now = datetime.now(UTC)
    indicator = Indicator(
        type=indicator_type,
        value=value,
        first_seen=now,
        last_seen=now,
        raw={"id": value},
    )
    indicator.sources = [
        IndicatorSource(feed=feed, first_seen=now, last_seen=now) for feed in sources
    ]
    return indicator


@pytest.fixture
def log_indicators(db_session: Session) -> list[Indicator]:
    indicators = [
        _indicator(IndicatorType.IP, "1.2.3.4", "threatfox"),
        _indicator(IndicatorType.URL, "http://bad.example/payload", "threatfox", "urlhaus"),
        _indicator(IndicatorType.URL, "http://evil.example/ref", "urlhaus"),
    ]
    db_session.add_all(indicators)
    db_session.flush()
    return indicators


def _analyze(client: TestClient, *, filename: str = "access.log", max_matches: int | None = None):
    params = {} if max_matches is None else {"max_matches": max_matches}
    with FIXTURE.open("rb") as stream:
        return client.post(
            "/analyze/logs",
            params=params,
            files={"file": (filename, stream, "text/plain")},
        )


def test_analyze_logs_summarizes_matches(
    api_client: TestClient, log_indicators: list[Indicator]
) -> None:
    response = _analyze(api_client)

    assert response.status_code == 200
    body = response.json()
    assert body["lines_read"] == 5
    assert body["lines_skipped"] == 1
    assert body["unique_indicators"] == 3
    assert body["truncated"] is False

    matches = {match["indicator"]["value"]: match for match in body["matches"]}
    assert set(matches) == {"1.2.3.4", "http://bad.example/payload", "http://evil.example/ref"}

    ip = matches["1.2.3.4"]
    assert (ip["hits"], ip["first_line"], ip["last_line"]) == (2, 1, 4)
    assert ip["matched_on"] == ["remote_addr"]
    assert ip["indicator"]["confidence"]["score"] == 50

    request = matches["http://bad.example/payload"]
    assert (request["hits"], request["first_line"], request["last_line"]) == (1, 2, 2)
    assert request["matched_on"] == ["request"]
    assert request["indicator"]["confidence"]["score"] == 80

    referer = matches["http://evil.example/ref"]
    assert (referer["hits"], referer["first_line"], referer["last_line"]) == (2, 2, 4)
    assert referer["matched_on"] == ["referer"]


def test_analyze_logs_truncates_after_max_matches(
    api_client: TestClient, log_indicators: list[Indicator]
) -> None:
    response = _analyze(api_client, max_matches=1)

    assert response.status_code == 200
    body = response.json()
    assert body["unique_indicators"] == 3
    assert body["truncated"] is True
    assert len(body["matches"]) == 1


def test_analyze_logs_rejects_oversized_files(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("threatfeed.api.analyze.MAX_LOG_BYTES", 10)

    response = _analyze(api_client)

    assert response.status_code == 413
    assert "byte limit" in response.json()["detail"]


def test_analyze_logs_accepts_an_empty_file(
    api_client: TestClient, log_indicators: list[Indicator]
) -> None:
    response = api_client.post("/analyze/logs", files={"file": ("empty.log", b"", "text/plain")})

    assert response.status_code == 200
    assert response.json() == {
        "lines_read": 0,
        "lines_skipped": 0,
        "unique_indicators": 0,
        "truncated": False,
        "matches": [],
    }


def test_analyze_logs_counts_malformed_lines(
    api_client: TestClient, log_indicators: list[Indicator]
) -> None:
    response = api_client.post(
        "/analyze/logs",
        files={"file": ("broken.log", b"this is not a log\nnor is this\n", "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["lines_read"] == 2
    assert response.json()["lines_skipped"] == 2
    assert response.json()["matches"] == []
