"""Alembic environment: run by Database.migrate() with an open connection."""

from alembic import context

config = context.config
connection = config.attributes["connection"]
schema = config.attributes.get("schema")

context.configure(
    connection=connection,
    target_metadata=None,
    version_table_schema=schema,
    # SQLite cannot ALTER most things in place; batch mode rebuilds tables when needed.
    render_as_batch=connection.dialect.name == "sqlite",
)
with context.begin_transaction():
    context.run_migrations()
