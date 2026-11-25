"""Versioned Redis cache for `/check`.

Every ingestion bumps a global version key. Cache entries are namespaced by that version, so a
bump invalidates the whole cache without a SCAN; old entries die by TTL. A Redis outage degrades
to database lookups instead of failing the API.
"""

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol

import redis
from redis.exceptions import RedisError

from threatfeed.config import get_settings
from threatfeed.models import IndicatorType

logger = logging.getLogger(__name__)

VERSION_KEY = "threatfeed:check:version"
KEY_PREFIX = "threatfeed:check"


class CacheClient(Protocol):
    def get(self, key: str) -> str | bytes | None: ...

    def set(self, key: str, value: str, *, ex: int | None = None, nx: bool = False) -> Any: ...

    def incr(self, key: str) -> int: ...


@dataclass(frozen=True)
class CacheLookup:
    """`hit` distinguishes a cache miss from a cached negative (`payload is None`)."""

    hit: bool
    payload: dict[str, Any] | None


class CheckCache:
    def __init__(self, client: CacheClient, ttl_seconds: int) -> None:
        self._client = client
        self._ttl = ttl_seconds

    def get(self, indicator_type: IndicatorType, value: str) -> CacheLookup:
        try:
            version = self._version()
            raw = self._client.get(self._key(version, indicator_type, value))
            if raw is None:
                return CacheLookup(hit=False, payload=None)
            if isinstance(raw, bytes):
                raw = raw.decode()
            return CacheLookup(hit=True, payload=json.loads(raw))
        except (RedisError, ValueError, TypeError) as exc:
            logger.warning("check cache read failed; falling back to the database: %s", exc)
            return CacheLookup(hit=False, payload=None)

    def set(
        self, indicator_type: IndicatorType, value: str, payload: dict[str, Any] | None
    ) -> None:
        try:
            version = self._version()
            self._client.set(
                self._key(version, indicator_type, value),
                json.dumps(payload),
                ex=self._ttl,
            )
        except (RedisError, ValueError, TypeError) as exc:
            logger.warning("check cache write failed; continuing without it: %s", exc)

    def invalidate(self) -> None:
        try:
            self._client.incr(VERSION_KEY)
        except RedisError as exc:
            logger.warning("check cache invalidation failed: %s", exc)

    def _version(self) -> int:
        raw = self._client.get(VERSION_KEY)
        if raw is None:
            self._client.set(VERSION_KEY, "0", nx=True)
            raw = self._client.get(VERSION_KEY)
        if isinstance(raw, bytes):
            raw = raw.decode()
        return int(raw or 0)

    @staticmethod
    def _key(version: int, indicator_type: IndicatorType, value: str) -> str:
        return f"{KEY_PREFIX}:v{version}:{indicator_type.value}:{value}"


@lru_cache
def get_check_cache() -> CheckCache:
    settings = get_settings()
    client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return CheckCache(client, settings.check_cache_ttl_seconds)


def invalidate_check_cache() -> None:
    """Best-effort bump used by the CLI and the Celery task after every attempted run."""
    try:
        get_check_cache().invalidate()
    except Exception as exc:  # noqa: BLE001 - the cache must never block an ingestion
        logger.warning("could not invalidate the check cache: %s", exc)
