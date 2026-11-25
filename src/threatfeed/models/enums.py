"""Closed vocabularies shared by the models, the migrations and (later) the API schemas."""

from enum import StrEnum


class IndicatorType(StrEnum):
    """What kind of observable an indicator holds. Stored as a native PostgreSQL enum."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"


class IngestStatus(StrEnum):
    """Lifecycle of one ingestion run: `running` is written before the feed is touched."""

    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
