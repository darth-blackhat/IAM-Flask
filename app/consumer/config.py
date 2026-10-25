from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from .ad_target import AdConfig

# Applied in this order so containers exist before the users placed in them.
ENTITY_ORDER = ("organization", "group", "role", "user")


class DirectoryEntity(BaseModel):
    """Groups / organizations / roles: matched by name in the remote OpenIAM."""

    search_path: str
    name_field: str = "name"
    id_field: str = "id"
    # Create missing ones (BasicAjaxResponse endpoint from the remote's /webconsole/api-docs).
    # Unset: a missing one is reported, not created.
    create_path: str | None = None
    create_body: dict[str, Any] = {"name": "{name}"}


class UserEntity(BaseModel):
    search_path: str = "/webconsole/rest/api/users/search"
    # Field present in both OpenIAMs that identifies the same person (ids differ per OpenIAM).
    match_field: str = "employeeId"
    # Source record field -> remote EditUserModel field. Unlisted fields are not copied.
    fields: dict[str, str] = {"firstName": "firstName", "lastName": "lastName",
                              "employeeId": "employeeId", "title": "title"}
    # Source field holding the primary email (sent as emailAddresses[0]).
    email_field: str | None = "email"
    # Dotted paths in the source record listing memberships by name, e.g. "groups.name".
    # Only memberships this consumer granted are ever removed.
    memberships: dict[Literal["group", "role", "organization"], str] = {}
    # A user missing from a newer zip of the same domain.
    on_missing: Literal["disable", "ignore"] = "disable"


def _default_directories() -> dict[str, DirectoryEntity]:
    return {
        "group": DirectoryEntity(search_path="/webconsole/rest/api/groups/search"),
        "role": DirectoryEntity(search_path="/webconsole/rest/api/roles/search"),
        "organization": DirectoryEntity(search_path="/webconsole/rest/api/organizations/search"),
    }


class ConsumerConfig(BaseModel):
    # Folder the producer side writes zips to (scanned recursively), e.g. \\share\iam-exports.
    inbox: str
    # Processed zips are moved here (per domain); null leaves them in the inbox.
    archive: str | None = "data/consumer/archive"
    failed: str | None = "data/consumer/failed"
    interval_seconds: int = Field(60, ge=5)
    # React to new zips at once (watchdog). The timed scan above stays as a fallback.
    watch_inbox: bool = True
    # Network shares (SMB / NFS) do not report other machines' writes: poll instead.
    watch_polling: bool = False
    # A file is taken only once it has not changed for this long (copies in progress).
    settle_seconds: float = Field(3.0, ge=0)
    # Ed25519 public keys (.pub files from `iam keys signing`) whose signatures are trusted.
    trusted_signing_keys: list[str] = []
    # Reject zips without a valid signature from a trusted key.
    require_signature: bool = False
    # age identity (from `iam keys age`) to open .zip.age files.
    age_identity_file: str | None = None
    # Reject zips that were not encrypted.
    require_encryption: bool = False
    # Accept only these domains (empty: all).
    domains: list[str] = []
    user: UserEntity = UserEntity()
    # Only used with CONSUMER_TARGET=ad (a site without OpenIAM).
    ad: AdConfig | None = None
    # OpenIAM target: carry out the zip's AD instructions that records cannot express
    # (enable / disable, add / remove member, delete -> disable).
    apply_instructions: bool = True
    # AD key attribute in an instruction -> OpenIAM user field.
    instruction_user_keys: dict[str, str] = {"employeeID": "employeeId"}
    directories: dict[Literal["group", "role", "organization"], DirectoryEntity] = Field(
        default_factory=_default_directories)

    @model_validator(mode="after")
    def _fill_directories(self) -> "ConsumerConfig":
        # Configuring only `group` must not drop the defaults for role / organization.
        self.directories = {**_default_directories(), **self.directories}
        return self

    @model_validator(mode="after")
    def _check_security(self) -> "ConsumerConfig":
        if self.require_signature and not self.trusted_signing_keys:
            raise ValueError("require_signature needs trusted_signing_keys")
        if self.require_encryption and not self.age_identity_file:
            raise ValueError("require_encryption needs age_identity_file")
        return self


def load_consumer_config(path: str) -> ConsumerConfig:
    with open(path, encoding="utf-8") as f:
        return ConsumerConfig.model_validate(yaml.safe_load(f) or {})
