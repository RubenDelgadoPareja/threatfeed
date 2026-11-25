import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from threatfeed.ingest import http


def _write_zip(path: Path, member: str = "full.csv") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, "a\n")


def test_cache_is_fresh_only_within_the_same_utc_day(tmp_path: Path) -> None:
    path = tmp_path / "export.zip"
    _write_zip(path)

    noon = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
    timestamp = noon.timestamp()
    os.utime(path, (timestamp, timestamp))

    assert http.is_fresh(path, now=noon)
    assert not http.is_fresh(path, now=datetime(2026, 11, 26, 0, 1, tzinfo=UTC))


def test_missing_cache_is_not_fresh(tmp_path: Path) -> None:
    assert not http.is_fresh(tmp_path / "missing.zip")


def test_fresh_cache_is_used_without_downloading(tmp_path: Path, monkeypatch) -> None:
    cache = tmp_path / "export.zip"
    _write_zip(cache)

    def fail_download(*args: object) -> None:
        raise AssertionError("the cache should have been used")

    monkeypatch.setattr(http, "_fetch_zip", fail_download)

    with http.download_zip("https://example.invalid/export.zip", cache) as path:
        assert path == cache


def test_stale_cache_is_replaced(tmp_path: Path, monkeypatch) -> None:
    cache = tmp_path / "export.zip"
    _write_zip(cache)
    yesterday = datetime(2026, 11, 24, 12, 0, tzinfo=UTC).timestamp()
    os.utime(cache, (yesterday, yesterday))

    def download(url: str, path: Path) -> None:
        _write_zip(path, member="full.csv")

    monkeypatch.setattr(http, "_fetch_zip", download)

    with http.download_zip("https://example.invalid/export.zip", cache) as path:
        assert path == cache
        assert http.is_fresh(cache)
