"""`python -m threatfeed.enrich [--limit N]`."""

import argparse
import logging
import sys

from threatfeed.config import get_settings
from threatfeed.db.session import get_session_factory
from threatfeed.enrich.service import backfill
from threatfeed.geoip import GeoIP
from threatfeed.ingest.errors import IngestError


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m threatfeed.enrich",
        description="Backfill GeoIP/ASN data for IP indicators already in the store.",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=None,
        metavar="N",
        help="stop after N IP indicators (smoke tests and local development)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)-5.5s [%(name)s] %(message)s")
    logger = logging.getLogger("threatfeed.enrich")

    geoip = None
    try:
        settings = get_settings()
        geoip = GeoIP.from_settings(settings)
        if geoip is None:
            raise IngestError("set GEOIP_COUNTRY_DB and/or GEOIP_ASN_DB before enriching")

        with get_session_factory()() as session:
            report = backfill(session, geoip, limit=args.limit)

        logger.info(
            "enriched %d of %d IPs (%d without geo data)",
            report.enriched,
            report.processed,
            report.missing,
        )
    except IngestError as exc:
        logger.error("%s", exc)
        return 1
    finally:
        if geoip is not None:
            geoip.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
