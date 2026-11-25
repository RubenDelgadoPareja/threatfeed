"""`python -m threatfeed.ingest <feed> [--limit N]`."""

import argparse
import logging
import sys

from threatfeed.cache import invalidate_check_cache
from threatfeed.config import get_settings
from threatfeed.db.session import get_session_factory
from threatfeed.geoip import GeoIP
from threatfeed.ingest.errors import IngestError
from threatfeed.ingest.runner import FEEDS, run_feed


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m threatfeed.ingest",
        description="Ingest one public IoC feed into the indicator store.",
    )
    parser.add_argument("feed", choices=sorted(FEEDS))
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=None,
        metavar="N",
        help="stop after N data rows (smoke tests and local development)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)-5.5s [%(name)s] %(message)s")
    logger = logging.getLogger("threatfeed.ingest")

    geoip = None
    try:
        settings = get_settings()
        geoip = GeoIP.from_settings(settings)
        with get_session_factory()() as session:
            try:
                started = run_feed(session, args.feed, settings, geoip, limit=args.limit)
            finally:
                invalidate_check_cache()
        if not started:
            logger.warning("%s is already running; skipping this invocation", args.feed)
    except IngestError as exc:
        logger.error("%s", exc)
        return 1
    finally:
        if geoip is not None:
            geoip.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
