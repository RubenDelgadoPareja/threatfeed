"""add ip_enrichment

Revision ID: 4f2b8c1d7e90
Revises: b7d41f2c9a10
Create Date: 2026-11-25 21:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "4f2b8c1d7e90"
down_revision: str | Sequence[str] | None = "b7d41f2c9a10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the one-to-one enrichment table for IP indicators."""
    op.create_table(
        "ip_enrichment",
        sa.Column("indicator_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("country_name", sa.Text(), nullable=True),
        sa.Column("asn", sa.BigInteger(), nullable=True),
        sa.Column("as_org", sa.Text(), nullable=True),
        sa.Column(
            "enriched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_ip_enrichment_indicator_id_indicators",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("indicator_id", name="pk_ip_enrichment"),
    )


def downgrade() -> None:
    """Drop the enrichment table."""
    op.drop_table("ip_enrichment")
