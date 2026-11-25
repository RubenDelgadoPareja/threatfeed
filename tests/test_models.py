"""Model-level guarantees that can be checked without a database."""

from sqlalchemy import UniqueConstraint

from threatfeed.db.base import Base
from threatfeed.models import (
    Indicator,
    IndicatorSource,
    IndicatorType,
    IngestRun,
    IngestStatus,
    IPEnrichment,
)


def test_metadata_registers_every_table() -> None:
    assert set(Base.metadata.tables) == {
        "indicators",
        "indicator_sources",
        "ingest_runs",
        "ip_enrichment",
    }


def test_constraints_follow_the_naming_convention() -> None:
    assert Indicator.__table__.primary_key.name == "pk_indicators"
    assert IngestRun.__table__.primary_key.name == "pk_ingest_runs"
    assert IndicatorSource.__table__.primary_key.name == "pk_indicator_sources"


def test_indicator_identity_is_unique() -> None:
    unique = {
        constraint.name
        for constraint in Indicator.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert unique == {"uq_indicators_type_value"}


def test_enum_columns_store_values_not_member_names() -> None:
    assert Indicator.__table__.c.type.type.enums == [
        "ip",
        "domain",
        "url",
        "hash_sha256",
        "hash_md5",
    ]
    assert IngestRun.__table__.c.status.type.enums == ["running", "succeeded", "failed"]


def test_indicator_type_enum_matches_the_model_vocabulary() -> None:
    assert [member.value for member in IndicatorType] == [
        "ip",
        "domain",
        "url",
        "hash_sha256",
        "hash_md5",
    ]
    assert [member.value for member in IngestStatus] == ["running", "succeeded", "failed"]


def test_ids_default_to_uuidv7_in_the_database() -> None:
    assert str(Indicator.__table__.c.id.server_default.arg) == "uuidv7()"
    assert str(IngestRun.__table__.c.id.server_default.arg) == "uuidv7()"


def test_deleting_an_indicator_cascades_to_its_sources() -> None:
    foreign_key = next(iter(IndicatorSource.__table__.c.indicator_id.foreign_keys))

    assert foreign_key.ondelete == "CASCADE"


def test_ip_enrichment_is_one_to_one_and_cascades() -> None:
    foreign_key = next(iter(IPEnrichment.__table__.c.indicator_id.foreign_keys))

    assert IPEnrichment.__table__.primary_key.name == "pk_ip_enrichment"
    assert foreign_key.ondelete == "CASCADE"
