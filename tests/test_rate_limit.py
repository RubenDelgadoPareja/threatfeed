from datetime import UTC, datetime, timedelta

from redis.exceptions import RedisError

from threatfeed.api.rate_limit import RateLimiter

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


class FakeRateRedis:
    def __init__(self) -> None:
        self.data: dict[str, int] = {}

    def incr(self, key: str) -> int:
        value = self.data.get(key, 0) + 1
        self.data[key] = value
        return value

    def expire(self, key: str, seconds: int) -> bool:
        return True


class BrokenRateRedis:
    def incr(self, key: str) -> int:
        raise RedisError("down")

    def expire(self, key: str, seconds: int) -> bool:
        raise RedisError("down")


def test_allows_the_limit_and_blocks_the_next_request() -> None:
    limiter = RateLimiter(FakeRateRedis())

    results = [limiter.check("default", "1.2.3.4", 2, now=NOW) for _ in range(3)]

    assert [result.allowed for result in results] == [True, True, False]
    assert [result.remaining for result in results] == [1, 0, 0]
    assert 0 < results[2].retry_after <= 60


def test_a_new_window_resets_the_counter() -> None:
    limiter = RateLimiter(FakeRateRedis())
    limiter.check("default", "1.2.3.4", 1, now=NOW)

    result = limiter.check("default", "1.2.3.4", 1, now=NOW + timedelta(minutes=1))

    assert result.allowed is True
    assert result.remaining == 0


def test_redis_failure_fails_open() -> None:
    limiter = RateLimiter(BrokenRateRedis())

    result = limiter.check("default", "1.2.3.4", 5, now=NOW)

    assert result.allowed is True
    assert result.remaining == 5
    assert result.retry_after == 0
