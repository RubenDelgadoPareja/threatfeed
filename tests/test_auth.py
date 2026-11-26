"""Bearer authentication at the HTTP seam."""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from threatfeed.api.rate_limit import RateLimits, get_rate_limits
from threatfeed.keys.service import create_key, revoke_key
from threatfeed.main import app
from threatfeed.models import ApiKey


def test_missing_or_malformed_credentials_are_rejected(anonymous_client: TestClient) -> None:
    attempts = [
        {},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer tf_not-a-real-key"},
    ]

    for headers in attempts:
        response = anonymous_client.get("/stats", headers=headers)

        assert response.status_code == 401, headers
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json()["detail"] == "invalid API key"


def test_a_valid_key_reaches_the_endpoint_and_records_its_use(
    api_client: TestClient, db_session: Session
) -> None:
    response = api_client.get("/stats")

    assert response.status_code == 200
    key = db_session.query(ApiKey).one()
    assert key.last_used_at is not None
    assert key.last_used_at > datetime.now(UTC) - timedelta(minutes=1)


def test_last_used_at_is_written_at_most_once_a_minute(
    api_client: TestClient, db_session: Session
) -> None:
    api_client.get("/stats")
    key = db_session.query(ApiKey).one()
    first = key.last_used_at

    api_client.get("/stats")
    db_session.refresh(key)

    assert key.last_used_at == first


def test_revoked_and_expired_keys_are_rejected(
    anonymous_client: TestClient, db_session: Session
) -> None:
    revoked, revoked_token = create_key(db_session, name="revoked")
    expired, expired_token = create_key(db_session, name="expired")
    revoke_key(db_session, revoked.prefix)
    expired.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    for token in (revoked_token, expired_token):
        response = anonymous_client.get("/stats", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid API key"


def test_health_and_documentation_stay_public(anonymous_client: TestClient) -> None:
    assert anonymous_client.get("/health").status_code == 200
    assert anonymous_client.get("/docs").status_code == 200
    assert anonymous_client.get("/openapi.json").status_code == 200


def test_the_quota_belongs_to_the_key(limited_client: TestClient) -> None:
    first = limited_client.get("/stats")
    second = limited_client.get("/stats")

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == second.headers["x-ratelimit-reset"]
    assert second.headers["x-ratelimit-limit"] == "1"


def test_each_key_has_its_own_bucket(anonymous_client: TestClient, db_session: Session) -> None:
    _, first = create_key(db_session, name="first")
    _, second = create_key(db_session, name="second")

    responses = [
        anonymous_client.get("/stats", headers={"Authorization": f"Bearer {token}"})
        for token in (first, second)
    ]

    assert [response.status_code for response in responses] == [200, 200]


def test_the_per_ip_guard_stops_many_fresh_keys(
    anonymous_client: TestClient, db_session: Session
) -> None:
    app.dependency_overrides[get_rate_limits] = lambda: RateLimits(1, 1, 10_000)
    tokens = [create_key(db_session, name=f"key-{n}")[1] for n in range(3)]

    statuses = [
        anonymous_client.get("/stats", headers={"Authorization": f"Bearer {token}"}).status_code
        for token in tokens
    ]

    assert statuses == [200, 200, 429]


def test_repeated_bad_keys_are_rate_limited(anonymous_client: TestClient) -> None:
    app.dependency_overrides[get_rate_limits] = lambda: RateLimits(10_000, 10_000, 2)

    responses = [
        anonymous_client.get("/stats", headers={"Authorization": "Bearer tf_wrong"})
        for _ in range(3)
    ]

    assert [response.status_code for response in responses] == [401, 401, 429]
    assert responses[-1].headers["www-authenticate"] == "Bearer"
    assert int(responses[-1].headers["retry-after"]) > 0
