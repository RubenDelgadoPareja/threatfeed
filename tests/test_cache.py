from redis.exceptions import RedisError

from threatfeed.cache import VERSION_KEY, CheckCache
from threatfeed.models import IndicatorType

URL = IndicatorType.URL


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.last_ex: int | None = None

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def set(self, key: str, value: str, *, ex: int | None = None, nx: bool = False) -> bool | None:
        if nx and key in self.data:
            return None
        self.data[key] = value
        self.last_ex = ex
        return True

    def incr(self, key: str) -> int:
        value = int(self.data.get(key, "0")) + 1
        self.data[key] = str(value)
        return value


class BrokenRedis:
    def get(self, key: str) -> str | None:
        raise RedisError("down")

    def set(self, key: str, value: str, *, ex: int | None = None, nx: bool = False) -> None:
        raise RedisError("down")

    def incr(self, key: str) -> int:
        raise RedisError("down")


def test_hit_and_ttl() -> None:
    client = FakeRedis()
    cache = CheckCache(client, ttl_seconds=123)

    cache.set(URL, "http://example.com/x", {"value": "http://example.com/x"})

    lookup = cache.get(URL, "http://example.com/x")
    assert lookup.hit is True
    assert lookup.payload == {"value": "http://example.com/x"}
    assert client.last_ex == 123


def test_negative_hit_is_distinct_from_a_miss() -> None:
    cache = CheckCache(FakeRedis(), ttl_seconds=60)

    assert cache.get(URL, "http://missing.example/x").hit is False

    cache.set(URL, "http://missing.example/x", None)
    lookup = cache.get(URL, "http://missing.example/x")

    assert lookup.hit is True
    assert lookup.payload is None


def test_invalidate_bumps_the_version() -> None:
    client = FakeRedis()
    cache = CheckCache(client, ttl_seconds=60)
    cache.set(URL, "http://example.com/x", {"value": "http://example.com/x"})

    cache.invalidate()

    assert client.get(VERSION_KEY) == "1"
    assert cache.get(URL, "http://example.com/x").hit is False


def test_broken_redis_degrades_to_a_miss() -> None:
    cache = CheckCache(BrokenRedis(), ttl_seconds=60)

    assert cache.get(URL, "http://example.com/x").hit is False
    cache.set(URL, "http://example.com/x", {"value": "x"})
    cache.invalidate()
