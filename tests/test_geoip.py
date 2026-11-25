import pytest

from threatfeed.config import Settings
from threatfeed.geoip import GeoIP, GeoIPError


def test_geoip_is_disabled_without_paths() -> None:
    assert GeoIP.from_settings(Settings(_env_file=None)) is None


def test_missing_database_is_a_configuration_error(tmp_path) -> None:
    missing = tmp_path / "missing.mmdb"

    with pytest.raises(GeoIPError, match="cannot open"):
        GeoIP.from_settings(Settings(_env_file=None, geoip_country_db=missing))


def test_invalid_database_is_a_configuration_error(tmp_path) -> None:
    invalid = tmp_path / "invalid.mmdb"
    invalid.write_text("not a MaxMind database", encoding="utf-8")

    with pytest.raises(GeoIPError, match="cannot open"):
        GeoIP.from_settings(Settings(_env_file=None, geoip_asn_db=invalid))
