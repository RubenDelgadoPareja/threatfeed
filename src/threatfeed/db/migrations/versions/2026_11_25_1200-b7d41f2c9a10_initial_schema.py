"""initial schema: indicators, indicator_sources, ingest_runs

Revision ID: b7d41f2c9a10
Revises:
Create Date: 2026-11-25 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7d41f2c9a10"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# create_type=False: the types are created explicitly before the tables and dropped after them,
# because Alembic's autogenerate does not emit DROP TYPE in a downgrade.
indicator_type = postgresql.ENUM(
    "ip",
    "domain",
    "url",
    "hash_sha256",
    "hash_md5",
    name="indicator_type",
    create_type=False,
)
ingest_status = postgresql.ENUM(
    "running",
    "succeeded",
    "failed",
    name="ingest_status",
    create_type=False,
)


def upgrade() -> None:
    """Create the indicator store and its audit trail."""
    bind = op.get_bind()
    indicator_type.create(bind, checkfirst=True)
    ingest_status.create(bind, checkfirst=True)

    op.create_table(
        "indicators",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("uuidv7()"),
            nullable=False,
        ),
        sa.Column("type", indicator_type, nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint("value <> ''", name="value_not_empty"),
        sa.PrimaryKeyConstraint("id", name="pk_indicators"),
        sa.UniqueConstraint("type", "value", name="uq_indicators_type_value"),
    )
    op.create_index("ix_indicators_type_last_seen_id", "indicators", ["type", "last_seen", "id"])

    op.create_table(
        "ingest_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("uuidv7()"),
            nullable=False,
        ),
        sa.Column("feed", sa.String(length=64), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", ingest_status, nullable=False),
        sa.Column("rows_read", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("rows_skipped", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("indicators_new", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("indicators_updated", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_ingest_runs"),
    )
    op.create_index("ix_ingest_runs_feed_started_at", "ingest_runs", ["feed", "started_at"])

    op.create_table(
        "indicator_sources",
        sa.Column("indicator_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("feed", sa.String(length=64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_indicator_sources_indicator_id_indicators",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("indicator_id", "feed", name="pk_indicator_sources"),
    )
    op.create_index("ix_indicator_sources_feed", "indicator_sources", ["feed"])


def downgrade() -> None:
    """Drop the tables first, then the types they depend on."""
    op.drop_index("ix_indicator_sources_feed", table_name="indicator_sources")
    op.drop_table("indicator_sources")
    op.drop_index("ix_ingest_runs_feed_started_at", table_name="ingest_runs")
    op.drop_table("ingest_runs")
    op.drop_index("ix_indicators_type_last_seen_id", table_name="indicators")
    op.drop_table("indicators")

    ingest_status.drop(op.get_bind(), checkfirst=True)
    indicator_type.drop(op.get_bind(), checkfirst=True)
