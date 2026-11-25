"""CSV dialect shared by the feeds: comments, blank lines and commented headers."""

import csv
from collections.abc import Iterable, Iterator

from threatfeed.ingest.errors import IngestError


def iter_rows(stream: Iterable[str], required_columns: set[str]) -> Iterator[dict[str, str | None]]:
    """Yield data rows, validating the header once.

    URLhaus and ThreatFox both prefix the real header with `#`, and ThreatFox writes a space
    after every comma. `skipinitialspace` handles the latter without touching quoted values.
    """
    reader = csv.DictReader(_data_lines(stream, required_columns), skipinitialspace=True)
    if reader.fieldnames is None:
        raise IngestError("feed is empty")

    reader.fieldnames = [name.strip() for name in reader.fieldnames]
    missing = required_columns - set(reader.fieldnames)
    if missing:
        raise IngestError(f"feed is missing required columns: {sorted(missing)}")

    yield from reader


def _data_lines(stream: Iterable[str], required_columns: set[str]) -> Iterator[str]:
    header_found = False
    for line in stream:
        # A BOM would otherwise become part of the first header name.
        line = line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            if not header_found and _looks_like_header(candidate, required_columns):
                yield candidate
                header_found = True
            continue

        yield line
        header_found = True


def _looks_like_header(candidate: str, required_columns: set[str]) -> bool:
    fields = next(csv.reader([candidate]), [])
    return required_columns.issubset({field.strip() for field in fields})
