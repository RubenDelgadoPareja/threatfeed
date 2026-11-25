"""`python -m threatfeed.ingest <feed> [--limit N]`."""

import argparse
import logging
import sys

from threatfeed.config import get_settings
from threatfeed.db.session import get_session_factory
from threatfeed.ingest.errors import IngestError
from threatfeed.ingest.threatfox import ThreatFoxIngestor
from threatfeed.ingest.urlhaus import URLHausIngestor

FEEDS = {"threatfox": ThreatFoxIngestor, "urlhaus": URLHausIngestor}


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

    try:
        with get_session_factory()() as session:
            FEEDS[args.feed](session, get_settings()).run(limit=args.limit)
    except IngestError as exc:
        logger.error("%s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
