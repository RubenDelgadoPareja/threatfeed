"""Download helpers shared by the ingestors, including key redaction and ZIP resume."""

import logging
import os
import re
import time
import zipfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx2

from threatfeed.ingest.errors import IngestError, RateLimitedError, RetryableIngestError

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 60.0
DOWNLOAD_ATTEMPTS = 3
MARKUP_CONTENT_TYPES = ("application/json", "text/html")


def redact_url(url: str) -> str:
    """Hide the auth key before a URL reaches a log line or an error message."""
    return re.sub(r"(/exports/)[^/]+(/|$)", r"\1***\2", url)


@contextmanager
def download_lines(url: str) -> Iterator[Iterable[str]]:
    """Stream a plain CSV export line by line, never buffering it in memory."""
    try:
        with _quiet_http_logs(), _client() as client, client.stream("GET", url) as response:
            if response.status_code == 429:
                raise RateLimitedError(
                    "export download quota reached",
                    retry_after=response.headers.get("retry-after"),
                )
            if response.status_code != 200:
                raise IngestError(f"export returned HTTP {response.status_code}")
            _reject_markup(response)
            yield response.iter_lines()
    except httpx2.HTTPError as exc:
        # Network errors embed the request URL, key included; never chain the original.
        raise RetryableIngestError(f"request failed: {redact_url(str(exc))}") from None


@contextmanager
def download_zip(url: str, cache_path: Path) -> Iterator[Path]:
    """Use today's cached ZIP when possible; otherwise download it atomically.

    ThreatFox limits downloads to four times the file size per UTC day, counting partial
    transfers. A cache that is fresh for the current UTC day avoids burning that quota.
    """
    if is_fresh(cache_path):
        try:
            _validate_zip(cache_path)
            logger.info("using cached %s", cache_path)
            yield cache_path
            return
        except zipfile.BadZipFile:
            cache_path.unlink(missing_ok=True)

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    partial = cache_path.with_name(f"{cache_path.name}.part")
    partial.unlink(missing_ok=True)

    try:
        _fetch_zip(url, partial)
        os.replace(partial, cache_path)
        logger.info("cached %s", cache_path)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    yield cache_path


def is_fresh(path: Path, *, now: datetime | None = None) -> bool:
    """True when the file was downloaded on the current UTC day."""
    if not path.exists():
        return False
    current = now or datetime.now(UTC)
    modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    return modified.date() == current.date()


@contextmanager
def _quiet_http_logs() -> Iterator[None]:
    """httpx2 logs every request URL at INFO, and the abuse.ch URLs carry the auth key.

    Process-wide and not thread-safe, which matches the current model: one ingest run per
    process. A future in-process worker pool would need its own logging policy.
    """
    http_logger = logging.getLogger("httpx2")
    previous = http_logger.level
    http_logger.setLevel(max(previous, logging.WARNING))
    try:
        yield
    finally:
        http_logger.setLevel(previous)


def _client() -> httpx2.Client:
    return httpx2.Client(follow_redirects=True, timeout=httpx2.Timeout(TIMEOUT_SECONDS))


def _reject_markup(response: httpx2.Response) -> None:
    content_type = response.headers.get("content-type", "").lower()
    if content_type.startswith(MARKUP_CONTENT_TYPES):
        raise IngestError(f"export returned {content_type!r}, not a data file")


def _fetch_zip(url: str, path: Path) -> None:
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            _append_zip(url, path)
            _validate_zip(path)
            return
        except httpx2.HTTPError as exc:
            error = f"network error: {redact_url(str(exc))}"
        except zipfile.BadZipFile as exc:
            # Resume would append to corrupt bytes; start over.
            path.unlink(missing_ok=True)
            error = f"invalid ZIP: {exc}"

        if attempt == DOWNLOAD_ATTEMPTS:
            raise RetryableIngestError(
                f"could not download export after {DOWNLOAD_ATTEMPTS} attempts ({error})"
            )
        time.sleep(2 ** (attempt - 1))


def _append_zip(url: str, path: Path) -> None:
    offset = path.stat().st_size if path.exists() else 0
    headers = {"Range": f"bytes={offset}-"} if offset else None

    with (
        _quiet_http_logs(),
        _client() as client,
        client.stream("GET", url, headers=headers) as response,
    ):
        if offset and response.status_code == 416:
            return
        if response.status_code == 429:
            retry_after = response.headers.get("retry-after", "unknown")
            raise RateLimitedError(
                "export download quota reached "
                f"(retry after {retry_after}s; the full export is cached for the UTC day)",
                retry_after=response.headers.get("retry-after"),
            )
        if response.status_code not in (200, 206):
            raise IngestError(f"export returned HTTP {response.status_code}")
        _reject_markup(response)

        append = offset > 0 and response.status_code == 206
        with path.open("ab" if append else "wb") as file:
            for chunk in response.iter_bytes():
                file.write(chunk)


def _validate_zip(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        if not archive.namelist():
            raise zipfile.BadZipFile("empty archive")
        corrupt = archive.testzip()
        if corrupt is not None:
            raise zipfile.BadZipFile(f"corrupt member: {corrupt}")
