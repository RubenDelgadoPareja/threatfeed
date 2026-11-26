"""Per-client fixed-window rate limiting backed by Redis.

The window number is part of the key, so a new window starts with a new counter. Redis failures
fail open: a rate limiter must not take the API down with its own store.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Protocol

import redis
from fastapi import Request
from redis.exceptions import RedisError

from threatfeed.config import get_settings

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60
KEY_PREFIX = "threatfeed:ratelimit"


class RateLimitClient(Protocol):
    def incr(self, key: str) -> int: ...

    def expire(self, key: str, seconds: int) -> bool: ...


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


@dataclass(frozen=True)
class RateLimits:
    default_per_minute: int
    logs_per_minute: int
    auth_failure_per_minute: int


class RateLimiter:
    def __init__(self, client: RateLimitClient) -> None:
        self._client = client

    def check(
        self,
        scope: str,
        client_ip: str,
        limit: int,
        *,
        now: datetime | None = None,
    ) -> RateLimitResult:
        current = now or datetime.now(UTC)
        timestamp = int(current.timestamp())
        window = timestamp // WINDOW_SECONDS
        key = f"{KEY_PREFIX}:{scope}:{client_ip}:{window}"
        retry_after = WINDOW_SECONDS - (timestamp % WINDOW_SECONDS)

        try:
            count = int(self._client.incr(key))
            self._client.expire(key, WINDOW_SECONDS)
        except RedisError as exc:
            logger.warning("rate limit store unavailable; allowing the request: %s", exc)
            return RateLimitResult(allowed=True, limit=limit, remaining=limit, retry_after=0)

        return RateLimitResult(
            allowed=count <= limit,
            limit=limit,
            remaining=max(0, limit - count),
            retry_after=retry_after,
        )


@lru_cache
def get_rate_limiter() -> RateLimiter:
    settings = get_settings()
    client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return RateLimiter(client)


@lru_cache
def get_rate_limits() -> RateLimits:
    settings = get_settings()
    return RateLimits(
        default_per_minute=settings.rate_limit_per_minute,
        logs_per_minute=settings.rate_limit_logs_per_minute,
        auth_failure_per_minute=settings.auth_failure_per_minute,
    )


def client_ip(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"
