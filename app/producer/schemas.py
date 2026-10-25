from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..schemas import EmailIn, PhoneIn

ProducerEventType = Literal["hire", "update", "terminate", "leave", "return", "status"]


class ProducerPerson(BaseModel):
    first_name: str
    last_name: str
    emails: list[EmailIn] = []
    phones: list[PhoneIn] = []
    metadata_type_id: str | None = None
    # Other OpenIAM EditUserModel fields (title, login, ...), by their OpenIAM names.
    extra: dict[str, Any] = {}


class ProducerEvent(BaseModel):
    """One change from the producer (HR or another source system).

    hire/update create or update the person (they are the same "upsert").
    groups / roles / organizations are the full producer-assigned name lists; omit one to
    leave that kind alone.
    `statuses` (e.g. {"compliance": "non_compliant"}) can come with any event type.
    """

    type: ProducerEventType
    employee_id: str = Field(..., min_length=1)
    # the producer's own id for this message. Resending the same id is answered from the record.
    event_id: str | None = None
    person: ProducerPerson | None = None
    groups: list[str] | None = None
    roles: list[str] | None = None
    organizations: list[str] | None = None
    statuses: dict[str, str] = {}
    effective_date: date | datetime | None = None
    reason: str | None = None


class ProducerResult(BaseModel):
    employee_id: str
    type: ProducerEventType
    event_id: str | None = None
    ok: bool = True
    duplicate: bool = False
    user_id: str | None = None
    actions: list[str] = []
    warnings: list[str] = []
    error: str | None = None
    # AD instructions sent to the receiving site for what was actually applied.
    instructions: list[dict[str, Any]] = []
    # OpenIAM user fields this event wrote, and whether it changed the account state:
    # lets change detection tell source-of-truth changes from admin changes.
    fields_set: list[str] = []
    state_changed: bool = False
