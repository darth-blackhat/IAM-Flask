"""Shared by the AD target tests and fixtures."""

from app.consumer.ad_target import AdConfig

BASE = "DC=corp,DC=example"
USERS = f"OU=Users,OU=IAM,{BASE}"
GROUPS = f"OU=Groups,OU=IAM,{BASE}"


def ad_cfg(**kw):
    return AdConfig.model_validate({"servers": ["ldaps://dc1.corp.example"], "bind_dn": f"CN=svc,{BASE}",
                                    "base_dn": BASE, "users_ou": USERS, "groups_ou": GROUPS,
                                    "ous_base": f"OU=IAM,{BASE}", "upn_suffix": "corp.example",
                                    "mode": "auto", **kw})
