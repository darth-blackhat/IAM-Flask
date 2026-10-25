"""Dotted-path lookups into records, shared by export, audit and the consumer."""

from typing import Any


def extract(record: Any, path: str) -> list[str]:
    """Values at a dotted path, walking into lists: "organizations.name" -> ["Org A", ...]."""
    values = [record]
    for part in path.split("."):
        values = [item[part] for v in values for item in (v if isinstance(v, list) else [v])
                  if isinstance(item, dict) and part in item]
    flat = {str(x) for v in values for x in (v if isinstance(v, list) else [v])
            if x not in (None, "") and not isinstance(x, (dict, list))}
    return sorted(flat)
