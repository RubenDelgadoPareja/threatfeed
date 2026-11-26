"""`python -m threatfeed.keys <create|list|revoke>`."""

import argparse
import logging
from datetime import UTC, datetime

from sqlalchemy import select

from threatfeed.db.session import get_session_factory
from threatfeed.keys.service import (
    ApiKeyAlreadyRevoked,
    ApiKeyNotFound,
    create_key,
    revoke_key,
)
from threatfeed.models import ApiKey

logger = logging.getLogger("threatfeed.keys")

TIME_FORMAT = "%Y-%m-%d %H:%M"


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m threatfeed.keys",
        description="Create, list and revoke API keys.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="create a key and print its secret once")
    create.add_argument("--name", required=True, help="who or what will use it")
    create.add_argument(
        "--expires-in-days",
        type=_positive_int,
        default=None,
        metavar="N",
        help="optional expiry, counted from now",
    )

    commands.add_parser("list", help="list prefixes and status, never the secrets")

    revoke = commands.add_parser("revoke", help="revoke a key by its prefix")
    revoke.add_argument("prefix")
    return parser


def _status(key: ApiKey, now: datetime) -> str:
    if key.revoked_at is not None:
        return "revoked"
    if key.expires_at is not None and key.expires_at <= now:
        return "expired"
    return "active"


def _stamp(value: datetime | None) -> str:
    return value.strftime(TIME_FORMAT) if value is not None else "never"


def _print_list(keys: list[ApiKey]) -> None:
    if not keys:
        print("No API keys.")
        return

    now = datetime.now(UTC)
    rows = [
        (
            key.prefix,
            key.name,
            _status(key, now),
            _stamp(key.created_at),
            _stamp(key.last_used_at),
            _stamp(key.expires_at),
        )
        for key in keys
    ]
    headers = ("PREFIX", "NAME", "STATUS", "CREATED", "LAST USED", "EXPIRES")
    widths = [max(len(str(cell)) for cell in column) for column in zip(headers, *rows, strict=True)]
    for row in (headers, *rows):
        print(
            "  ".join(
                str(cell).ljust(width) for cell, width in zip(row, widths, strict=True)
            ).rstrip()
        )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)-5.5s [%(name)s] %(message)s")

    try:
        with get_session_factory()() as session:
            if args.command == "create":
                record, token = create_key(
                    session, name=args.name, expires_in_days=args.expires_in_days
                )
                print(
                    f'Created API key "{record.name}" (prefix {record.prefix}).\n'
                    "Copy it now: it will not be shown again.\n"
                )
                print(token)
            elif args.command == "list":
                keys = session.scalars(select(ApiKey).order_by(ApiKey.created_at)).all()
                _print_list(list(keys))
            else:
                record = revoke_key(session, args.prefix)
                print(f'Revoked API key "{record.name}" (prefix {record.prefix}).')
    except (ApiKeyNotFound, ApiKeyAlreadyRevoked) as exc:
        logger.error("%s: %s", type(exc).__name__, exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
