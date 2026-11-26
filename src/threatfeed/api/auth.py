"""Bearer authentication and the quotas that depend on the authenticated key.

`/health`, `/docs` and `/openapi.json` stay public: probes need the first, and the last two
only describe the API. Every endpoint that returns or analyses data requires a key.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from threatfeed.api.rate_limit import (
    RateLimiter,
    RateLimitResult,
    RateLimits,
    client_ip,
    get_rate_limiter,
    get_rate_limits,
)
from threatfeed.db.session import get_db
from threatfeed.keys.service import authenticate
from threatfeed.models import ApiKey

logger = logging.getLogger(__name__)

INVALID_KEY = "invalid API key"
# One write per key per minute is enough to answer "is this key still in use?".
LAST_USED_UPDATE = timedelta(minutes=1)
# The per-IP guard is a backstop for many keys on one host, so it allows more than a key.
IP_GUARD_MULTIPLIER = 2

bearer_scheme = HTTPBearer(
    auto_error=False,
    description="API key from `python -m threatfeed.keys create`.",
)


@dataclass(frozen=True)
class ApiKeyIdentity:
    """What the rest of the request needs to know: never the token itself."""

    id: uuid.UUID
    name: str
    prefix: str


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=INVALID_KEY,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _charge_failure(request: Request, limiter: RateLimiter, limits: RateLimits) -> None:
    """Make guessing keys expensive. Runs before the 401, so ten tries fit in a minute."""
    result = limiter.check("auth-fail", client_ip(request), limits.auth_failure_per_minute)
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="too many failed authentication attempts",
            headers={
                "Retry-After": str(result.retry_after),
                "WWW-Authenticate": "Bearer",
            },
        )


def _touch(db: Session, key_id: uuid.UUID, last_used_at: datetime | None) -> None:
    """Record usage, at most once a minute. Failing to do so must never reject a request."""
    now = datetime.now(UTC)
    if last_used_at is not None and now - last_used_at < LAST_USED_UPDATE:
        return
    try:
        db.execute(update(ApiKey).where(ApiKey.id == key_id).values(last_used_at=now))
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.warning("could not record API key usage: %s", exc)


def require_api_key(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    limits: Annotated[RateLimits, Depends(get_rate_limits)],
) -> ApiKeyIdentity:
    token = credentials.credentials if credentials is not None else ""
    key = authenticate(db, token) if token else None
    if key is None:
        _charge_failure(request, limiter, limits)
        raise _unauthorized()

    identity = ApiKeyIdentity(id=key.id, name=key.name, prefix=key.prefix)
    _touch(db, key.id, key.last_used_at)
    return identity


def _headers(result: RateLimitResult) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset": str(result.retry_after),
    }


def _enforce(
    request: Request,
    response: Response,
    limiter: RateLimiter,
    identity: ApiKeyIdentity,
    *,
    scope: str,
    limit: int,
) -> None:
    """Two counters: the key's own quota, and a looser per-IP backstop."""
    key_result = limiter.check(f"{scope}:key", str(identity.id), limit)
    ip_result = limiter.check(f"{scope}:ip", client_ip(request), limit * IP_GUARD_MULTIPLIER)
    blocking = key_result if not key_result.allowed else ip_result

    response.headers.update(_headers(key_result if key_result.allowed else ip_result))
    if not blocking.allowed:
        raise HTTPException(
            status_code=429,
            detail="rate limit exceeded",
            headers={
                "Retry-After": str(blocking.retry_after),
                **_headers(blocking),
            },
        )


def default_rate_limit(
    request: Request,
    response: Response,
    identity: Annotated[ApiKeyIdentity, Depends(require_api_key)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    limits: Annotated[RateLimits, Depends(get_rate_limits)],
) -> None:
    _enforce(
        request,
        response,
        limiter,
        identity,
        scope="default",
        limit=limits.default_per_minute,
    )


def logs_rate_limit(
    request: Request,
    response: Response,
    identity: Annotated[ApiKeyIdentity, Depends(require_api_key)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    limits: Annotated[RateLimits, Depends(get_rate_limits)],
) -> None:
    _enforce(
        request,
        response,
        limiter,
        identity,
        scope="logs",
        limit=limits.logs_per_minute,
    )
