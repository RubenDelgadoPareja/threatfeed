"""SQLAlchemy models. Importing this package registers every table on `Base.metadata`."""

from threatfeed.models.api_key import ApiKey
from threatfeed.models.enums import IndicatorType, IngestStatus
from threatfeed.models.indicator import Indicator, IndicatorSource, IPEnrichment
from threatfeed.models.ingest_run import IngestRun

__all__ = [
    "ApiKey",
    "IPEnrichment",
    "Indicator",
    "IndicatorSource",
    "IndicatorType",
    "IngestRun",
    "IngestStatus",
]
