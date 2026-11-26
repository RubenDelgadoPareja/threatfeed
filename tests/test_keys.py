"""API key lifecycle: creation, hashing and revocation."""

import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from threatfeed.keys.__main__ import main
from threatfeed.keys.service import (
    ApiKeyAlreadyRevoked,
    ApiKeyNotFound,
    authenticate,
    create_key,
    hash_token,
    revoke_key,
)
from threatfeed.models import ApiKey


def test_create_returns_a_token_that_only_exists_hashed(db_session: Session) -> None:
    record, token = create_key(db_session, name="reporting")

    assert token.startswith("tf_")
    assert record.name == "reporting"
    assert record.key_hash == hash_token(token)
    assert record.prefix == token[:12]
    assert token not in (record.key_hash, record.prefix)
    assert record.revoked_at is None
    assert record.expires_at is None


def test_authenticate_finds_the_active_key(db_session: Session) -> None:
    record, token = create_key(db_session, name="reporting")

    assert authenticate(db_session, token) is record


def test_authenticate_rejects_unknown_revoked_and_expired_tokens(db_session: Session) -> None:
    _, token = create_key(db_session, name="active")
    revoked, revoked_token = create_key(db_session, name="revoked")
    expired, expired_token = create_key(db_session, name="expired")

    revoke_key(db_session, revoked.prefix)
    expired.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    assert authenticate(db_session, "tf_not-a-real-token") is None
    assert authenticate(db_session, revoked_token) is None
    assert authenticate(db_session, expired_token) is None
    assert authenticate(db_session, token) is not None


def test_revoke_is_reported_and_not_repeated(db_session: Session) -> None:
    record, _ = create_key(db_session, name="reporting")

    revoked = revoke_key(db_session, record.prefix)

    assert revoked.revoked_at is not None
    with pytest.raises(ApiKeyAlreadyRevoked):
        revoke_key(db_session, record.prefix)
    with pytest.raises(ApiKeyNotFound):
        revoke_key(db_session, "tf_missing")


@pytest.fixture
def cli_session(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Session:
    """Point the CLI at the test transaction instead of the real database."""

    class _Context:
        def __enter__(self) -> Session:
            return db_session

        def __exit__(self, *exc: object) -> bool:
            return False

    monkeypatch.setattr("threatfeed.keys.__main__.get_session_factory", lambda: _Context)
    return db_session


def test_cli_create_prints_the_token_once(cli_session: Session, capsys) -> None:
    assert main(["create", "--name", "reporting"]) == 0

    output = capsys.readouterr().out
    token = next(line.strip() for line in output.splitlines() if line.startswith("tf_"))
    assert hash_token(token) in {key.key_hash for key in cli_session.query(ApiKey)}
    assert "will not be shown again" in output


def test_cli_list_shows_prefixes_but_never_tokens(cli_session: Session, capsys) -> None:
    record, token = create_key(cli_session, name="reporting")

    assert main(["list"]) == 0

    output = capsys.readouterr().out
    assert record.prefix in output
    assert "reporting" in output
    assert token not in output


def test_cli_revoke_disables_the_key(cli_session: Session, capsys) -> None:
    record, token = create_key(cli_session, name="reporting")

    assert main(["revoke", record.prefix]) == 0

    assert "revoked" in capsys.readouterr().out.lower()
    assert authenticate(cli_session, token) is None
    assert main(["revoke", "tf_missing"]) == 1


def test_cli_create_accepts_an_expiry(cli_session: Session, capsys) -> None:
    assert main(["create", "--name", "temporary", "--expires-in-days", "30"]) == 0

    capsys.readouterr()
    record = cli_session.query(ApiKey).filter_by(name="temporary").one()
    assert record.expires_at is not None
    assert record.expires_at > datetime.now(UTC) + timedelta(days=29)


def test_the_module_entrypoint_actually_runs() -> None:
    """`python -m threatfeed.keys --help` catches a missing `__main__` guard."""
    completed = subprocess.run(
        [sys.executable, "-m", "threatfeed.keys", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "create" in completed.stdout
