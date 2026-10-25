from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from ..ad import AdMapping


class EntityConfig(BaseModel):
    """How to pull one entity type (user, group, ...) out of OpenIAM.

    OpenIAM has no "list all", so `queries` is a list of search criteria whose
    combined results must cover every record. Records are merged by `id_field`.
    """

    path: str
    queries: list[dict[str, Any]] = Field(..., min_length=1)
    id_field: str = "id"
    page_size: int = Field(100, ge=1, le=1000)
    # Fields that change without a real data change (last login, counters, ...).
    ignore_fields: list[str] = []
    # Keep only these fields (after ignore_fields). Empty keeps everything.
    include_fields: list[str] = []


class WebhookTarget(BaseModel):
    type: Literal["webhook"] = "webhook"
    url: str
    # Name of the env var holding the HMAC secret; the secret itself never goes in this file.
    secret_env: str | None = "SYNC_WEBHOOK_SECRET"
    headers: dict[str, str] = {}
    timeout_seconds: float = 30.0
    verify_tls: bool = True


class FileTarget(BaseModel):
    """Append events to a JSON-lines file (for testing, or a shared folder the other site reads)."""

    type: Literal["file"] = "file"
    path: str


class NoTarget(BaseModel):
    """Only record events; the other site pulls them from GET /sync/events."""

    type: Literal["none"] = "none"


class DomainSplit(BaseModel):
    """How records are assigned to domains; each domain gets its own zip.

    by_field: entity -> field naming the record's domain. Dotted paths reach into nested
              data and lists ("organizations.name"); a record with several values goes
              into each of those domains. New values become new domains automatically.
    shared:   entities copied into every domain's zip (e.g. global roles).
    With neither set, everything goes into one domain named "all".
    """

    by_field: dict[str, str] = {}
    shared: list[str] = []
    # Domain for records whose field is empty; null leaves them out of every zip.
    unassigned: str | None = "_unassigned"
    # Export only these domains (empty: all).
    only: list[str] = []


class AuditFields(BaseModel):
    """Field names in an audit search result (dotted paths allowed for target_id)."""

    id: str = "id"
    time: str = "timestamp"
    actor: str = "principal"        # login of whoever made the change
    actor_id: str = "userId"
    action: str = "action"
    result: str = "result"
    target_id: str = "targets.targetId"   # id(s) of the changed object(s)


class AuditConfig(BaseModel):
    """OpenIAM audit log search. Verify every value against your /webconsole/api-docs."""

    search_path: str = "/webconsole/rest/api/auditlog/search"
    criteria: dict[str, Any] = {}
    # Criterion that limits results to entries after the previous sync run.
    # ("from"/"size" are taken: they page every search.)
    since_criterion: str = "fromDate"
    since_format: Literal["epoch_ms", "epoch_s", "iso"] = "epoch_ms"
    page_size: int = Field(200, ge=1, le=1000)
    max_records: int = Field(5000, ge=1)
    fields: AuditFields = AuditFields()

    @model_validator(mode="after")
    def _no_paging_clash(self) -> "AuditConfig":
        if self.since_criterion in ("from", "size") or {"from", "size"} & set(self.criteria):
            raise ValueError("audit: 'from' and 'size' are the paging fields of every search; "
                             "use another name for the time criterion")
        return self


class ZipTarget(BaseModel):
    """Instructions are delivered inside the per-domain zips (ad_instructions.jsonl)."""

    type: Literal["zip"] = "zip"


class ExportConfig(BaseModel):
    # Destination folder (local path or network share, e.g. \\fileserver\iam-exports).
    folder: str
    formats: list[Literal["jsonl", "csv", "json"]] = Field(["jsonl", "csv"], min_length=1)
    # Zips kept per domain; older ones are deleted. null keeps all.
    keep: int | None = Field(30, ge=1)
    subfolder_per_domain: bool = True
    # Export after each sync run, for domains whose data changed (or are new).
    after_sync: bool = False
    domains: DomainSplit = DomainSplit()
    # Data minimization: per entity, the only fields that may leave this site (data files
    # and the record payload of AD instructions). Ids and the domain field are always kept.
    # Unlisted entity: every field.
    fields: dict[str, list[str]] = {}
    # Ed25519 private key (iam keys signing): every manifest is signed with it.
    signing_key_file: str | None = None
    # age recipients ("age1...") or files containing them (iam keys age): zips are encrypted
    # to all of them and written as .zip.age.
    encrypt_to: list[str] = []


class SyncConfig(BaseModel):
    interval_seconds: int = Field(300, ge=10)
    # Refuse a run where more than this share of an entity type vanished at once:
    # it is far more likely a broken query or permission change than real deletions.
    max_delete_ratio: float = Field(0.2, ge=0, le=1)
    # Deleting fewer records than this is never treated as suspicious.
    mass_delete_min: int = Field(5, ge=1)
    batch_size: int = Field(100, ge=1, le=5000)
    max_attempts: int = Field(20, ge=1)
    entities: dict[str, EntityConfig]
    target: WebhookTarget | FileTarget | NoTarget | ZipTarget = Field(default_factory=NoTarget,
                                                                      discriminator="type")
    # Who changed what directly in OpenIAM (optional, best effort).
    audit: AuditConfig | None = None
    export: ExportConfig | None = None
    # How changes are expressed as AD instructions for the receiving site.
    ad: AdMapping = AdMapping()

    @model_validator(mode="after")
    def _check(self) -> "SyncConfig":
        if not self.entities:
            raise ValueError("at least one entity is required")
        if isinstance(self.target, ZipTarget) and not (self.export and self.export.after_sync):
            raise ValueError("target type zip needs an export section with after_sync: true")
        if self.export:
            d = self.export.domains
            named = set(d.by_field) | set(d.shared)
            if unknown := named - set(self.entities):
                raise ValueError(f"export.domains names unknown entities: {sorted(unknown)}")
            if both := set(d.by_field) & set(d.shared):
                raise ValueError(f"export.domains: {sorted(both)} both split and shared")
            if d.by_field and (missing := set(self.entities) - named):
                raise ValueError("export.domains: say how to split or share "
                                 f"{sorted(missing)} (by_field or shared)")
        return self


def load_config(path: str | Path) -> SyncConfig:
    with open(path, encoding="utf-8") as f:
        return SyncConfig.model_validate(yaml.safe_load(f) or {})
