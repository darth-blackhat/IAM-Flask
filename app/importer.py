"""Parse CSV / JSON user files into UserIn records.

CSV columns (header row required, names case-insensitive):
  id, first_name, last_name, email, phone, metadata_type_id,
  role_ids, group_ids, organization_ids, resource_ids   (lists separated by ';')
Any other column is passed to OpenIAM unchanged via `extra` (use EditUserModel names,
e.g. `login`, `employeeId`).

JSON: a list of UserIn objects, or {"users": [...]}.
"""

import csv
import io
import json
from typing import Any

from pydantic import ValidationError

from .schemas import EmailIn, PhoneIn, UserIn

LIST_COLUMNS = ("role_ids", "group_ids", "organization_ids", "resource_ids")
KNOWN_COLUMNS = {"id", "first_name", "last_name", "email", "phone", "metadata_type_id", *LIST_COLUMNS}


class ImportError_(ValueError):
    """The file could not be parsed; `row_errors` maps row number to the problem."""

    def __init__(self, message: str, row_errors: dict[int, str] | None = None):
        super().__init__(message)
        self.row_errors = row_errors or {}


def parse_users(data: bytes | str, filename: str) -> list[UserIn]:
    text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
    name = filename.lower()
    if name.endswith(".json"):
        return _parse_json(text)
    if name.endswith(".csv"):
        return _parse_csv(text)
    raise ImportError_("unsupported file type; use .csv or .json")


def _parse_json(text: str) -> list[UserIn]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise ImportError_(f"invalid JSON: {e}") from e
    rows = doc.get("users") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        raise ImportError_('JSON must be a list of users or {"users": [...]}')
    return _validate(rows, start=0)


def _parse_csv(text: str) -> list[UserIn]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ImportError_("CSV has no header row")
    rows: list[dict[str, Any]] = []
    for raw in reader:
        row = {(k or "").strip(): (v or "").strip() for k, v in raw.items()}
        lowered = {k.lower(): v for k, v in row.items()}
        rec: dict[str, Any] = {
            "id": lowered.get("id") or None,
            "first_name": lowered.get("first_name", ""),
            "last_name": lowered.get("last_name", ""),
            "metadata_type_id": lowered.get("metadata_type_id") or None,
            "emails": [EmailIn(email=lowered["email"])] if lowered.get("email") else [],
            "phones": [PhoneIn(number=lowered["phone"])] if lowered.get("phone") else [],
            "extra": {k: v for k, v in row.items() if k.lower() not in KNOWN_COLUMNS and v},
        }
        for col in LIST_COLUMNS:
            rec[col] = [x.strip() for x in lowered.get(col, "").split(";") if x.strip()]
        rows.append(rec)
    # CSV row numbers count the header as row 1.
    return _validate(rows, start=2)


def _validate(rows: list[Any], start: int) -> list[UserIn]:
    users: list[UserIn] = []
    errors: dict[int, str] = {}
    for i, row in enumerate(rows, start=start):
        try:
            user = UserIn.model_validate(row)
            if not user.first_name or not user.last_name:
                raise ValueError("first_name and last_name are required")
            users.append(user)
        except (ValidationError, ValueError, TypeError) as e:
            errors[i] = str(e)
    if errors:
        raise ImportError_(f"{len(errors)} invalid row(s)", errors)
    return users
