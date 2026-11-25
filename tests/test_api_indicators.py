from fastapi.testclient import TestClient

from threatfeed.models import Indicator


def test_check_normalizes_urls_and_returns_provenance(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    response = api_client.get("/check", params={"value": "HTTP://Example.COM:80/a#frag"})

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "url"
    assert body["value"] == "http://example.com/a"
    assert body["first_seen"].startswith("2026-03-01")
    assert body["last_seen"].startswith("2026-03-05")
    sources = {source["feed"]: source for source in body["sources"]}
    assert set(sources) == {"feodotracker", "urlhaus"}
    assert sources["feodotracker"]["last_seen"].startswith("2026-03-05")
    assert body["confidence"]["score"] == 70
    assert body["confidence"]["level"] == "medium"
    assert "2 sources agree" in body["confidence"]["reasons"]
    assert "raw" not in body


def test_check_finds_ips(api_client: TestClient, seeded_indicators: list[Indicator]) -> None:
    response = api_client.get("/check", params={"value": "1.2.3.4"})

    assert response.status_code == 200
    assert response.json()["type"] == "ip"


def test_check_returns_404_for_unknown_values(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    response = api_client.get("/check", params={"value": "https://unknown.example/x"})

    assert response.status_code == 404
    assert response.json() == {"detail": "indicator not found"}


def test_check_rejects_unrecognizable_values(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    response = api_client.get("/check", params={"value": "example.com/path"})

    assert response.status_code == 422


def test_check_requires_a_value(api_client: TestClient) -> None:
    assert api_client.get("/check").status_code == 422


def test_indicators_are_paginated_newest_first(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    response = api_client.get("/indicators", params={"limit": 2, "offset": 0})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["limit"] == 2
    assert body["offset"] == 0
    assert [item["value"] for item in body["items"]] == ["1.2.3.4", "http://example.com/a"]
    assert body["items"][0]["confidence"]["score"] == 40
    assert body["items"][0]["confidence"]["level"] == "low"

    second_page = api_client.get("/indicators", params={"limit": 2, "offset": 2}).json()
    assert [item["value"] for item in second_page["items"]] == ["evil.example"]


def test_indicators_can_be_filtered_by_type(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    response = api_client.get("/indicators", params={"type": "ip"})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["value"] == "1.2.3.4"


def test_indicators_validate_query_parameters(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    assert api_client.get("/indicators", params={"type": "bogus"}).status_code == 422
    assert api_client.get("/indicators", params={"limit": 0}).status_code == 422
    assert api_client.get("/indicators", params={"limit": 201}).status_code == 422
    assert api_client.get("/indicators", params={"offset": -1}).status_code == 422


def test_stats_cover_every_type_and_source(
    api_client: TestClient, seeded_indicators: list[Indicator]
) -> None:
    response = api_client.get("/stats")

    assert response.status_code == 200
    assert response.json() == {
        "total": 3,
        "by_type": {
            "ip": 1,
            "domain": 1,
            "url": 1,
            "hash_sha256": 0,
            "hash_md5": 0,
        },
        "by_source": {"feodotracker": 2, "urlhaus": 2},
    }
