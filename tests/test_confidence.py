from datetime import UTC, datetime, timedelta

import pytest

from threatfeed.confidence import SourceEvidence, score_confidence

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def _sources(*feeds: str, days_ago: int = 0) -> list[SourceEvidence]:
    return [SourceEvidence(feed=feed, last_seen=NOW - timedelta(days=days_ago)) for feed in feeds]


def test_no_sources_scores_zero() -> None:
    confidence = score_confidence([], now=NOW)

    assert confidence.score == 0
    assert confidence.level == "low"
    assert confidence.reasons == ("no sources",)


@pytest.mark.parametrize(
    ("feeds", "days_ago", "expected_score", "expected_level"),
    [
        (("urlhaus",), 0, 50, "medium"),
        (("urlhaus",), 20, 45, "low"),
        (("urlhaus",), 100, 40, "low"),
        (("urlhaus", "threatfox"), 0, 80, "high"),
        (("urlhaus", "threatfox"), 20, 75, "medium"),
        (("urlhaus", "threatfox"), 100, 70, "medium"),
        (("urlhaus", "threatfox", "third"), 0, 100, "high"),
        (("urlhaus", "threatfox", "third"), 100, 90, "high"),
    ],
)
def test_score_combines_agreement_and_freshness(
    feeds: tuple[str, ...], days_ago: int, expected_score: int, expected_level: str
) -> None:
    confidence = score_confidence(_sources(*feeds, days_ago=days_ago), now=NOW)

    assert confidence.score == expected_score
    assert confidence.level == expected_level
    assert confidence.reasons[0] == (
        "1 source" if len(feeds) == 1 else f"{len(feeds)} sources agree"
    )


def test_the_same_feed_twice_counts_once() -> None:
    confidence = score_confidence(_sources("urlhaus", "urlhaus"), now=NOW)

    assert confidence.score == 50
    assert confidence.reasons[0] == "1 source"


def test_future_last_seen_is_treated_as_today() -> None:
    sources = [SourceEvidence(feed="urlhaus", last_seen=NOW + timedelta(days=2))]

    confidence = score_confidence(sources, now=NOW)

    assert confidence.score == 50
    assert "seen today" in confidence.reasons


def test_freshness_reasons_are_human_readable() -> None:
    assert "seen today" in score_confidence(_sources("a"), now=NOW).reasons
    assert "seen yesterday" in score_confidence(_sources("a", days_ago=1), now=NOW).reasons
    assert "seen 3 days ago" in score_confidence(_sources("a", days_ago=3), now=NOW).reasons
    assert (
        "stale: last seen 100 days ago"
        in score_confidence(_sources("a", days_ago=100), now=NOW).reasons
    )
