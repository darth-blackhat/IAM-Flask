"""Shared by migration scripts: the target schema and the portable column types."""

from alembic import context

from app.schema import IdType, JsonType

__all__ = ["IdType", "JsonType", "schema"]


def schema() -> str | None:
    return context.config.attributes.get("schema")
