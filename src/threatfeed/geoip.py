"""GeoIP / ASN lookups from a MaxMind-compatible MMDB pair (GeoLite2 or DB-IP Lite)."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import geoip2.database
from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError

from threatfeed.config import Settings
from threatfeed.ingest.errors import IngestError


class GeoIPError(IngestError):
    """A configured GeoIP database is missing or unreadable."""


@dataclass(frozen=True)
class GeoInfo:
    country_code: str | None = None
    country_name: str | None = None
    asn: int | None = None
    as_org: str | None = None


class GeoLookup(Protocol):
    """What the ingestors need; tests substitute a fake implementation."""

    def lookup(self, ip: str) -> GeoInfo | None: ...


class GeoIP:
    """Lazy readers for the country and ASN databases. Both are optional."""

    def __init__(self, country_db: Path | None, asn_db: Path | None) -> None:
        self._country = self._open(country_db)
        self._asn = self._open(asn_db)

    @classmethod
    def from_settings(cls, settings: Settings) -> "GeoIP | None":
        if settings.geoip_country_db is None and settings.geoip_asn_db is None:
            return None
        return cls(settings.geoip_country_db, settings.geoip_asn_db)

    @staticmethod
    def _open(path: Path | None) -> geoip2.database.Reader | None:
        if path is None:
            return None
        try:
            return geoip2.database.Reader(str(path))
        except (OSError, ValueError, InvalidDatabaseError) as exc:
            raise GeoIPError(f"cannot open GeoIP database {path}: {exc}") from exc

    def lookup(self, ip: str) -> GeoInfo | None:
        country_code: str | None = None
        country_name: str | None = None
        asn: int | None = None
        as_org: str | None = None

        if self._country is not None:
            try:
                record = self._country.country(ip)
            except (AddressNotFoundError, ValueError):
                record = None
            if record is not None and record.country is not None:
                country_code = record.country.iso_code
                country_name = record.country.name

        if self._asn is not None:
            try:
                asn_record = self._asn.asn(ip)
            except (AddressNotFoundError, ValueError):
                asn_record = None
            if asn_record is not None:
                asn = asn_record.autonomous_system_number
                as_org = asn_record.autonomous_system_organization

        if country_code is None and asn is None:
            return None
        return GeoInfo(
            country_code=country_code,
            country_name=country_name,
            asn=asn,
            as_org=as_org,
        )

    def close(self) -> None:
        for reader in (self._country, self._asn):
            if reader is not None:
                reader.close()
