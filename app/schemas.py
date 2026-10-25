from typing import Any, Literal

from pydantic import BaseModel, Field

from .config import Settings


class EmailIn(BaseModel):
    email: str
    type_id: str | None = None
    published: bool = False


class PhoneIn(BaseModel):
    number: str
    area_code: str | None = None
    country_code: str | None = None
    type_id: str | None = None
    for_sms: bool = False
    published: bool = False


class UserIn(BaseModel):
    """A user to push into OpenIAM. Converted to OpenIAM's EditUserModel by `to_openiam`.

    Fields beyond these (login, employeeId, title, ...) differ per deployment; put them
    in `extra` using the EditUserModel field names from your /webconsole/api-docs.
    """

    id: str | None = Field(None, description="Existing OpenIAM user id: update instead of create")
    first_name: str
    last_name: str
    metadata_type_id: str | None = None
    emails: list[EmailIn] = []
    phones: list[PhoneIn] = []
    notify_user_via_email: bool = False
    role_ids: list[str] = []
    group_ids: list[str] = []
    organization_ids: list[str] = []
    resource_ids: list[str] = []
    extra: dict[str, Any] = {}

    def to_openiam(self, settings: Settings) -> dict[str, Any]:
        model: dict[str, Any] = {
            **self.extra,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "notifyUserViaEmail": self.notify_user_via_email,
        }
        if self.id:
            model["id"] = self.id
        metadata_type_id = self.metadata_type_id or settings.default_user_metadata_type_id
        if metadata_type_id:
            model["metadataTypeId"] = metadata_type_id
        if self.emails:
            model["emailAddresses"] = [
                {"email": e.email, "typeId": e.type_id or settings.default_email_type_id,
                 "published": e.published}
                for e in self.emails
            ]
        if self.phones:
            model["phones"] = [
                {"phoneNbr": p.number, "areaCd": p.area_code, "countryCd": p.country_code,
                 "typeId": p.type_id or settings.default_phone_type_id,
                 "isForSMS": p.for_sms, "published": p.published}
                for p in self.phones
            ]
        return model

    def has_entitlements(self) -> bool:
        return bool(self.role_ids or self.group_ids or self.organization_ids or self.resource_ids)


class InjectResult(BaseModel):
    index: int | None = None
    ok: bool
    user_id: str | None = None
    created: bool | None = None
    dry_run: bool = False
    account_states: str | None = Field(None, description="OpenIAM successMessage (per-system state)")
    entitled: bool | None = None
    error: str | None = None
    error_codes: list[Any] = []


class BulkInjectResult(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[InjectResult]


class SearchIn(BaseModel):
    """OpenIAM user-search criteria, passed through as-is (e.g. {"lastName": "Smith"})."""

    criteria: dict[str, Any]
    from_: int = Field(0, alias="from", ge=0)
    size: int = Field(50, ge=1, le=1000)

    model_config = {"populate_by_name": True}


class ExportIn(BaseModel):
    criteria: dict[str, Any]
    page_size: int = Field(100, ge=1, le=1000)
    limit: int | None = Field(None, ge=1)


class EntitleIn(BaseModel):
    operation: Literal["ADD", "REPLACE", "DELETE"] = "ADD"
    role_ids: list[str] = []
    group_ids: list[str] = []
    organization_ids: list[str] = []
    resource_ids: list[str] = []


class ActionIn(BaseModel):
    reason: str | None = None
    description: str | None = None
    perform_date: str | None = Field(None, description="UTC, yyyy-MM-dd'T'HH:mm:ss.SSS'Z'; omit to run now")


class RawIn(BaseModel):
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"
    path: str = Field(..., examples=["/webconsole/rest/api/users/search"])
    params: dict[str, Any] | None = None
    body: Any = None
