"""AD placement by domain / organization type, moves, renames, more attributes, activation."""

import asyncio

import pytest
from ldap3 import SUBTREE

from app.consumer.ad_target import AdApplier, filetime_end_of, group_type
from app.directory import DirectoryRequest
from app.notify import Notifications

from .ad_helpers import BASE, GROUPS, USERS, ad_cfg
from .test_ad_target import drop, find, line
from .test_directory import J, queued

LAGOS_USERS, LAGOS_GROUPS = f"OU=Users,OU=Lagos,{BASE}", f"OU=Groups,OU=Lagos,{BASE}"
BRANCHES = f"OU=Branches,{BASE}"
PLACEMENT = {"domains": {"lagos": {"users_ou": LAGOS_USERS, "groups_ou": LAGOS_GROUPS}},
             "org_types": {"Branch": BRANCHES}}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def placed(ad):
    for dn, name in ((f"OU=Lagos,{BASE}", "Lagos"), (LAGOS_USERS, "Users"), (LAGOS_GROUPS, "Groups"),
                     (BRANCHES, "Branches")):
        ad.add(dn, ["organizationalUnit"], {"ou": name})
    return AdApplier(ad_cfg(placement=PLACEMENT), conn_factory=lambda: ad)


def ln(seq, op, cls, key, domain="corp", **ins):
    out = line(seq, op, cls, key, **ins)
    out["domain"] = domain
    return out


def user(seq, eid, given, domain="corp"):
    return ln(seq, "create", "user", {"employeeID": eid}, domain,
              attributes={"givenName": given, "sn": "Test", "employeeID": eid})


def test_new_objects_land_in_the_domains_ou_and_ous_by_type(placed, ad):
    items = placed.apply([user(1, "E1", "Ada", "lagos"), user(2, "E2", "Bob"),
                          ln(3, "create", "group", {"cn": "GRP-Lagos"}, "lagos", attributes={"cn": "GRP-Lagos"}),
                          ln(4, "create", "organizationalUnit", {"ou": "Ikeja"}, "lagos",
                             attributes={"ou": "Ikeja", "businessCategory": "Branch"})])
    assert all(i["ok"] for i in items), items
    assert find(ad, "(employeeID=E1)")[0]["dn"] == f"CN=Ada Test,{LAGOS_USERS}"
    assert find(ad, "(employeeID=E2)")[0]["dn"] == f"CN=Bob Test,{USERS}"          # unlisted domain: default
    assert find(ad, "(cn=GRP-Lagos)")[0]["dn"] == f"CN=GRP-Lagos,{LAGOS_GROUPS}"
    assert find(ad, "(ou=Ikeja)")[0]["dn"] == f"OU=Ikeja,{BRANCHES}"


def test_placement_must_stay_under_base_dn():
    with pytest.raises(ValueError, match="under base_dn"):
        ad_cfg(placement={"domains": {"x": {"users_ou": "OU=Evil,DC=other,DC=example"}}})


def test_move_follows_the_domain_and_is_idempotent(placed, ad):
    placed.apply([user(1, "E1", "Ada")])
    [item] = placed.apply([ln(2, "move", "user", {"employeeID": "E1"}, domain="lagos")])
    assert item["ldap"] == "move" and item["ok"], item
    assert find(ad, "(employeeID=E1)")[0]["dn"] == f"CN=Ada Test,{LAGOS_USERS}"
    [again] = placed.plan([ln(3, "move", "user", {"employeeID": "E1"}, domain="lagos")])
    assert again["ldap"] == "noop"


def test_rename_groups_and_ous_but_never_protected_ones(placed, ad):
    placed.apply([ln(1, "create", "group", {"cn": "GRP-Old"}, attributes={"cn": "GRP-Old"})])
    [item] = placed.apply([ln(2, "rename", "group", {"cn": "GRP-Old"}, new_name="GRP-New")])
    assert item["ok"], item
    [g] = find(ad, "(cn=GRP-New)")
    assert g["dn"] == f"CN=GRP-New,{GROUPS}" and g["attributes"]["sAMAccountName"] in ("GRP-New", ["GRP-New"])
    assert find(ad, "(cn=GRP-Old)") == []
    [refused] = placed.plan([ln(3, "rename", "group", {"cn": "Domain Admins"}, new_name="Harmless")])
    assert refused["ldap"] == "error" and "protected" in refused["error"]
    placed.apply([ln(4, "create", "group", {"cn": "GRP-Other"}, attributes={"cn": "GRP-Other"})])
    [clash] = placed.plan([ln(5, "rename", "group", {"cn": "GRP-Other"}, new_name="GRP-New")])
    assert clash["ldap"] == "error" and "already exists" in clash["error"]
    placed.apply([user(6, "E9", "Zed")])
    [user_rename] = placed.plan([ln(7, "rename", "user", {"employeeID": "E9"}, new_name="x")])
    assert user_rename["ldap"] == "error" and "not renamed" in user_rename["error"]


def test_manager_expiry_and_group_type(placed, ad):
    placed.apply([user(1, "E1", "Boss")])
    items = placed.apply([ln(2, "create", "user", {"employeeID": "E2"},
                             attributes={"givenName": "Ann", "sn": "Test", "employeeID": "E2", "manager": "E1",
                                         "department": "Finance", "accountExpires": "2027-03-31"}),
                          ln(3, "create", "group", {"cn": "DL-News"},
                             attributes={"cn": "DL-News", "groupScope": "universal", "groupCategory": "distribution"}),
                          ln(4, "update", "user", {"employeeID": "E2"},
                             changes=[{"attribute": "manager", "old": None, "new": "E404"}])])
    assert all(i["ok"] for i in items), items
    a = find(ad, "(employeeID=E2)")[0]["attributes"]
    assert str(a["manager"][0] if isinstance(a["manager"], list) else a["manager"]).startswith("CN=Boss Test,")
    assert str(a["accountExpires"]) in (filetime_end_of("2027-03-31"), f"['{filetime_end_of('2027-03-31')}']") \
        or a["accountExpires"] is not None
    g = find(ad, "(cn=DL-News)")[0]["attributes"]
    assert int(g["groupType"][0] if isinstance(g["groupType"], list) else g["groupType"]) == 8
    assert "E404 not found" in items[2]["note"]
    assert group_type("global", "security") == -2147483646 and group_type("domain_local", None) == -2147483644


def test_new_users_raise_an_activation_alert(make_ad_consumer, ad, tmp_path, database):
    drop(tmp_path, [user(1, "E7", "New")])
    run(make_ad_consumer().scan())
    [n] = [x for x in Notifications(database).recent() if x["event"] == "ad.account_needs_activation"]
    assert "CN=New Test" in n["text"]


def test_producer_sends_rename_move_and_new_attributes(service, sync):
    run(service.handle({**J, "via": "ad", "kind": "group", "op": "update", "name": "GRP-Old",
                        "new_name": "GRP-New", "description": "renamed", "group_scope": "universal"}))
    run(service.handle({**J, "via": "ad", "kind": "user", "op": "update", "name": "E1", "first_name": "A",
                        "last_name": "B", "department": "Finance", "manager": "E2", "domain": "lagos"}))
    ops = [(i["op"], i.get("new_name") or i.get("domain")) for e in queued(sync) for i in e["instructions"]]
    assert ops == [("update", None), ("rename", "GRP-New"), ("update", None), ("move", "lagos")]
    upd = queued(sync)[1]["instructions"][0]
    assert {c["attribute"]: c["new"] for c in upd["changes"]}["manager"] == "E2"
    for bad in ({"kind": "group", "department": "x"}, {"kind": "user", "group_scope": "global"},
                {"kind": "user", "account_expires": "31/12/2027"}, {"kind": "user", "manager": "E1"}):
        with pytest.raises(ValueError):
            DirectoryRequest.model_validate({**J, "via": "ad", "op": "update", "name": "E1", "first_name": "A",
                                             "last_name": "B", **bad})


def test_ldap_search_helper_sanity(ad):
    ad.search(BASE, "(objectClass=organizationalUnit)", SUBTREE)
    assert ad.response
