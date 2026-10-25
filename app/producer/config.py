from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from ..openiam.client import USER_ACTIONS

# What the producer can place a person into. Each maps to an /prov/entitle id list.
Kind = Literal["group", "role", "organization"]
KINDS: tuple[Kind, ...] = ("group", "role", "organization")


class Assignments(BaseModel):
    """Names of groups / roles / organizations, as the producer knows them."""

    groups: list[str] = []
    roles: list[str] = []
    organizations: list[str] = []

    def by_kind(self) -> dict[Kind, list[str]]:
        return {"group": self.groups, "role": self.roles, "organization": self.organizations}


class StatusRule(Assignments):
    """What one value of a producer status (compliance, training, ...) means in OpenIAM.

    hold: while true the account is disabled. Several holds can be active at once;
          the account is enabled again only when none remain.
    groups / roles / organizations: what the person has while in this status
          (replaced when the status changes).
    """

    hold: bool = False


class DirectoryConfig(BaseModel):
    """How to find (and optionally create) one kind of object by name."""

    search_path: str
    name_field: str = "name"
    id_field: str = "id"
    # Producer name -> OpenIAM name, e.g. {"Finance": "GRP-Finance-RW"}. Unlisted names are used as-is.
    aliases: dict[str, str] = {}
    # Extra search criteria sent with every lookup.
    search_extra: dict[str, Any] = {}
    # Field values a match must have, e.g. {"managedSysId": "<AD managed system id>"} so
    # only groups linked to AD are used. Check the field name in a real search result.
    require: dict[str, Any] = {}
    # Endpoint that creates one (BasicAjaxResponse). Not in OpenIAM's published docs:
    # take it from your /webconsole/api-docs. Unset means unknown names are an error.
    create_path: str | None = None
    # Body sent to create_path; "{name}" is replaced with the name.
    create_body: dict[str, Any] = {"name": "{name}"}


def _default_directories() -> dict[Kind, DirectoryConfig]:
    return {
        "group": DirectoryConfig(search_path="/webconsole/rest/api/groups/search"),
        "role": DirectoryConfig(search_path="/webconsole/rest/api/roles/search"),
        "organization": DirectoryConfig(search_path="/webconsole/rest/api/organizations/search"),
    }


class LifecycleActions(BaseModel):
    terminate: str = "terminate"
    leave: str = "leave-of-absence"
    # Coming back from leave with no holds active.
    return_: str = Field("enable", alias="return")

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _known(self) -> "LifecycleActions":
        for action in (self.terminate, self.leave, self.return_):
            if action not in USER_ACTIONS:
                raise ValueError(f"unknown OpenIAM action {action!r}; one of {sorted(USER_ACTIONS)}")
        return self


class ProducerConfig(BaseModel):
    # OpenIAM user field holding the producer's employee id. Set on every user this backend creates,
    # and used to find users that already existed in OpenIAM.
    employee_id_field: str = "employeeId"
    user_search_path: str = "/webconsole/rest/api/users/search"
    directories: dict[Kind, DirectoryConfig] = Field(default_factory=_default_directories)
    lifecycle_actions: LifecycleActions = LifecycleActions()
    # On termination, remove every group / role / organization this backend granted.
    terminate_removes_access: bool = True
    # status name -> status value -> rule. Unknown values are reported as warnings.
    status_rules: dict[str, dict[str, StatusRule]] = {}

    @model_validator(mode="after")
    def _fill_directories(self) -> "ProducerConfig":
        # Configuring only `role` must not drop the defaults for group / organization.
        self.directories = {**_default_directories(), **self.directories}
        return self

    def rule(self, status: str, value: str) -> StatusRule | None:
        return self.status_rules.get(status, {}).get(value)


def load_producer_config(path: str) -> ProducerConfig:
    with open(path, encoding="utf-8") as f:
        return ProducerConfig.model_validate(yaml.safe_load(f) or {})
