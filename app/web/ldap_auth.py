"""Sign-in against Active Directory (LDAP), read-only.

WEB_AUTH_MODE:
  local   web users with their own passwords (the original behaviour)
  ldap    AD only: the password is checked by binding as the user; AD groups give the role
  both    AD first; local accounts still work (break-glass when AD is down)

How a sign-in works (nothing is ever written to AD; connections are read_only):
  1. bind with the service account (WEB_LDAP_BIND_DN) and find the user by sAMAccountName
  2. bind as that user with the given password (an empty password is refused: AD would
     treat it as an anonymous bind and "succeed")
  3. collect the user's groups, nested ones too, and map them to a role:
     WEB_LDAP_GROUP_ADMIN / _OPERATOR / _AUDITOR / _VIEWER (group DNs, several separated by ";")
     The highest role wins; no mapped group = no access.
Only LDAPS, or LDAP with StartTLS, with the server certificate verified (WEB_LDAP_CA_FILE).
"""

import re
import ssl
from collections.abc import Callable
from typing import Any

from ldap3 import SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from ..config import Settings
from .auth import RANK

USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_NESTING = 8
ROLE_SETTINGS = ("admin", "operator", "auditor", "viewer")


class LdapUnavailable(Exception):
    """AD could not be reached (as opposed to a wrong password)."""


Connect = Callable[[str, str], Connection]


class LdapAuth:
    def __init__(self, settings: Settings, connect: Connect | None = None):
        self.s = settings
        self.base = settings.web_ldap_base_dn
        self.groups = {role: [g.strip().lower() for g in getattr(settings, f"web_ldap_group_{role}").split(";")
                              if g.strip()] for role in ROLE_SETTINGS}
        if not self.base or not settings.web_ldap_bind_dn:
            raise ValueError("WEB_LDAP_BASE_DN and WEB_LDAP_BIND_DN are required for LDAP sign-in")
        if not any(self.groups.values()):
            raise ValueError("map at least one AD group to a role (WEB_LDAP_GROUP_ADMIN, ...)")
        self._connect = connect or self._real_connect

    # ---- connections -------------------------------------------------------

    def _real_connect(self, user: str, password: str) -> Connection:
        urls = [u.strip() for u in self.s.web_ldap_urls.split(",") if u.strip()]
        if not urls:
            raise LdapUnavailable("WEB_LDAP_URLS is empty")
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.s.web_ldap_ca_file or None,
                  version=ssl.PROTOCOL_TLS_CLIENT)
        servers = []
        for url in urls:
            if url.startswith("ldap://") and not self.s.web_ldap_starttls:
                raise LdapUnavailable(f"{url}: plain LDAP refused (use ldaps:// or WEB_LDAP_STARTTLS=true)")
            servers.append(Server(url, use_ssl=url.startswith("ldaps://"), tls=tls,
                                  connect_timeout=self.s.web_ldap_timeout))
        conn = Connection(ServerPool(servers, "FIRST", active=1, exhaust=True), user=user, password=password,
                          read_only=True, receive_timeout=self.s.web_ldap_timeout, raise_exceptions=False)
        try:
            if self.s.web_ldap_starttls:
                conn.open()
                conn.start_tls()
            conn.bind()
        except LDAPException as e:
            raise LdapUnavailable(f"AD unreachable: {type(e).__name__}") from None
        return conn

    # ---- sign-in -------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> tuple[dict[str, Any] | None, str]:
        """({"username", "role", "dn", "display"}, "") or (None, reason for the audit trail).
        Raises LdapUnavailable when AD cannot be reached."""
        if not USERNAME.match(username or ""):
            return None, "not a valid AD account name"
        if not password:
            return None, "empty password"          # never let an empty password become an anonymous bind
        svc = self._connect(self.s.web_ldap_bind_dn, self.s.web_ldap_bind_password.get_secret_value())
        if not svc.bound:
            raise LdapUnavailable("the LDAP service account cannot bind (check WEB_LDAP_BIND_DN / password)")
        try:
            flt = self.s.web_ldap_user_filter.replace("{username}", escape_filter_chars(username))
            svc.search(self.base, flt, SUBTREE, attributes=["sAMAccountName", "displayName"], size_limit=2)
            hits = [e for e in svc.response or [] if e.get("type") == "searchResEntry"]
            if len(hits) != 1:
                return None, "unknown AD account" if not hits else "ambiguous AD account"
            dn = hits[0]["dn"]
            attrs = hits[0].get("attributes") or {}
            user = self._connect(dn, password)
            ok = user.bound
            try:
                user.unbind()
            except Exception:
                pass
            if not ok:
                return None, "wrong password (or the AD account is disabled / locked)"
            groups = self._groups(svc, dn)
        finally:
            try:
                svc.unbind()
            except Exception:
                pass
        role = None
        for r, wanted in self.groups.items():
            if wanted and groups & set(wanted) and (role is None or RANK[r] > RANK[role]):
                role = r
        if role is None:
            return None, "not in any AD group that gives access"
        name = _first(attrs.get("sAMAccountName")) or username
        return {"username": str(name).lower(), "role": role, "dn": dn,
                "display": _first(attrs.get("displayName"))}, ""

    def _groups(self, conn: Connection, dn: str) -> set[str]:
        """DNs (lower case) of every group the account is in, nested groups included."""
        seen: set[str] = set()
        frontier = [dn]
        for _ in range(MAX_NESTING):
            found = []
            for member in frontier:
                conn.search(self.base, f"(&(objectClass=group)(member={escape_filter_chars(member)}))",
                            SUBTREE, attributes=[])
                for e in conn.response or []:
                    if e.get("type") == "searchResEntry" and e["dn"].lower() not in seen:
                        seen.add(e["dn"].lower())
                        found.append(e["dn"])
            if not found:
                break
            frontier = found
        return seen


def _first(v: Any) -> Any:
    return v[0] if isinstance(v, list) and v else (v or None)


__all__ = ["LdapAuth", "LdapUnavailable"]
