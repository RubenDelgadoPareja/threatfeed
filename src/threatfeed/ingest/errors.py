"""Errors that mean "this run must fail", as opposed to bugs that should raise loudly."""


class IngestError(Exception):
    """A feed could not be ingested safely. `ingest_runs` is marked `failed`."""


class InvalidRow(ValueError):
    """One feed row cannot be turned into an indicator; it is skipped and counted."""
