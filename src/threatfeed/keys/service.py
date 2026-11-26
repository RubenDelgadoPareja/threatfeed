"""Create, look up and revoke API keys.

The token is returned exactly once, by `create_key`. Nothing else in the application can
recover it: the database holds a SHA-256 hash and a short prefix.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatfeed.models import ApiKey

TOKEN_PREFIX = "tf_"
TOKEN_BYTES = 32
# tf_ (3) + nine characters. Long enough to identify one key among dozens, short enough to
# stay readable in a log line.
PREFIX_LENGTH = 12


class ApiKeyNotFound(Exception):
    """No key starts with the given prefix."""


class ApiKeyAlreadyRevoked(Exception):
    """The key was already revoked; revoking twice is a mistake, not a no-op."""


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_key(
    session: Session, *, name: str, expires_in_days: int | None = None
) -> tuple[ApiKey, str]:
    token = generate_token()
    expires_at = datetime.now(UTC) + timedelta(days=expires_in_days) if expires_in_days else None
    record = ApiKey(
        name=name,
        prefix=token[:PREFIX_LENGTH],
        key_hash=hash_token(token),
        expires_at=expires_at,
    )
    session.add(record)
    session.commit()
    return record, token


def authenticate(session: Session, token: str) -> ApiKey | None:
    """The active key matching this token, if any. Revoked and expired keys never match."""
    now = datetime.now(UTC)
    return session.scalar(
        select(ApiKey).where(
            ApiKey.key_hash == hash_token(token),
            ApiKey.revoked_at.is_(None),
            (ApiKey.expires_at.is_(None)) | (ApiKey.expires_at > now),
        )
    )


def revoke_key(session: Session, prefix: str) -> ApiKey:
    record = session.scalar(select(ApiKey).where(ApiKey.prefix == prefix))
    if record is None:
        raise ApiKeyNotFound(prefix)
    if record.revoked_at is not None:
        raise ApiKeyAlreadyRevoked(prefix)
    record.revoked_at = datetime.now(UTC)
    session.commit()
    return record
