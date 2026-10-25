import csv
import io
import json
from typing import Any


def to_csv(rows: list[dict[str, Any]]) -> str:
    """Rows with differing keys -> one CSV; nested values are written as JSON."""
    columns = list(dict.fromkeys(k for row in rows for k in row))
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v
                         for k, v in row.items()})
    return out.getvalue()
