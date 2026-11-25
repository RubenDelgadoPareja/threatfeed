"""Errors that mean "this run must fail", as opposed to bugs that should raise loudly."""


class IngestError(Exception):
    """A feed could not be ingested safely. `ingest_runs` is marked `failed`."""
