"""Errors that mean "this run must fail", as opposed to bugs that should raise loudly."""


class IngestError(Exception):
    """A feed could not be ingested safely. `ingest_runs` is marked `failed`."""


class RetryableIngestError(IngestError):
    """Transient network or storage failure; the scheduled task may retry it."""


class RateLimitedError(IngestError):
    """The provider asked us to back off. Do not retry until the quota resets."""

    def __init__(self, message: str, *, retry_after: str | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class InvalidRow(ValueError):
    """One feed row cannot be turned into an indicator; it is skipped and counted."""
