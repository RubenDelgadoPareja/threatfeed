"""API keys. Only the hash is stored; the secret is printed once when it is created."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatfeed.db.base import Base


class ApiKey(Base):
    """A bearer key. The visible fragment identifies it in logs without revealing it."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()")
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    # tf_ plus the first nine random characters: enough to say "this is the reporting key",
    # not enough to brute force the remaining 256 bits.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    # SHA-256 hex of the whole token. With 256 bits of entropy a fast hash is correct here;
    # bcrypt would only add latency to every request.
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and (
            self.expires_at is None or self.expires_at > datetime.now(self.expires_at.tzinfo)
        )
