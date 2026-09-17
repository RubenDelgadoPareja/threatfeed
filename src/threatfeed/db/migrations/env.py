"""Alembic environment: wires the app's settings and metadata into the migration runner.

The database URL is never stored in a config file; it comes from `threatfeed.config.Settings`
(environment / .env), exactly like the application itself.
"""

import logging

from alembic import context
from sqlalchemy import create_engine, pool

from threatfeed.config import get_settings
from threatfeed.db.base import Base

# Task 2 adds `import threatfeed.models` here, so every table registers on Base.metadata
# before autogenerate compares it against the live schema.

# No alembic.ini => no fileConfig(); a minimal setup keeps "Running upgrade ..." messages visible.
logging.basicConfig(level=logging.INFO, format="%(levelname)-5.5s [%(name)s] %(message)s")
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

# INTERVIEW: autogenerate diffs Base.metadata against the live database. It detects added or
# removed tables/columns but NOT renames (it sees a drop + an add): always review the file.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit the SQL to stdout instead of executing it (`alembic upgrade head --sql`)."""
    context.configure(
        url=get_settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and run the pending migrations inside a transaction."""
    # create_engine() directly instead of config.set_main_option("sqlalchemy.url", ...): the
    # ini path goes through ConfigParser interpolation, where every "%" of a URL-escaped
    # password would have to be doubled. NullPool: one short-lived connection is enough here.
    connectable = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
