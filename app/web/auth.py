"""Web users: scrypt password hashes, roles, lockout after repeated failures."""

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any

from sqlalchemy import insert, select, update

from ..db import Database

ROLES = ("viewer", "operator", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
MIN_PASSWORD = 12
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt${n}${r}${p}${s}${d}".format(
        **_SCRYPT, s=base64.b64encode(salt).decode(), d=base64.b64encode(digest).decode())


def check_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), dklen=32,
                             n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(got, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


# Checked for unknown usernames so the response time does not reveal which names exist.
_DUMMY = hash_password(secrets.token_urlsafe(16))


def password_problem(username: str, password: str) -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"password must be at least {MIN_PASSWORD} characters"
    if password.lower() == username.lower():
        return "password must differ from the username"
    return None


class WebUserStore:
    def __init__(self, db: Database, max_failures: int = 5, lock_minutes: int = 15):
        self.db, self.t = db, db.tables.web_users
        self.max_failures, self.lock_seconds = max_failures, lock_minutes * 60

    def get(self, username: str) -> dict[str, Any] | None:
        with self.db.begin() as conn:
            r = conn.execute(select(self.t).where(self.t.c.username == username)).first()
            return dict(r._mapping) if r else None

    def list(self) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            return [{k: v for k, v in r._mapping.items() if k != "password_hash"}
                    for r in conn.execute(select(self.t).order_by(self.t.c.username))]

    def count(self) -> int:
        return len(self.list())

    def create(self, username: str, password: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if not username or len(username) > 100 or not username.replace(".", "").replace("-", "").replace("_", "").isalnum():
            raise ValueError("username: letters, digits, . - _ only")
        if problem := password_problem(username, password):
            raise ValueError(problem)
        now = time.time()
        with self.db.begin() as conn:
            conn.execute(insert(self.t).values(username=username, password_hash=hash_password(password),
                                               role=role, disabled=False, failed_logins=0,
                                               session_epoch=0, created_at=now,
                                               password_changed_at=now))

    def _set(self, username: str, **values: Any) -> bool:
        with self.db.begin() as conn:
            return conn.execute(update(self.t).where(self.t.c.username == username)
                                .values(**values)).rowcount > 0

    def set_password(self, username: str, password: str) -> None:
        if problem := password_problem(username, password):
            raise ValueError(problem)
        user = self.get(username)
        if not user:
            raise ValueError("no such user")
        # New password: every existing session of this user ends.
        self._set(username, password_hash=hash_password(password), password_changed_at=time.time(),
                  session_epoch=user["session_epoch"] + 1, failed_logins=0, locked_until=None)

    def set_role(self, username: str, role: str) -> bool:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        user = self.get(username)
        return bool(user) and self._set(username, role=role, session_epoch=user["session_epoch"] + 1)

    def set_disabled(self, username: str, disabled: bool) -> bool:
        user = self.get(username)
        return bool(user) and self._set(username, disabled=disabled,
                                        session_epoch=user["session_epoch"] + 1)

    def unlock(self, username: str) -> bool:
        return self._set(username, failed_logins=0, locked_until=None)

    def logout_everywhere(self, username: str) -> bool:
        user = self.get(username)
        return bool(user) and self._set(username, session_epoch=user["session_epoch"] + 1)

    def authenticate(self, username: str, password: str) -> tuple[dict | None, str]:
        """(user, "") or (None, reason). Reasons are for the audit trail, not the screen."""
        user = self.get(username)
        if user is None:
            check_password(password, _DUMMY)
            return None, "unknown user"
        if user["locked_until"] and user["locked_until"] > time.time():
            return None, "locked"
        if not check_password(password, user["password_hash"]):
            failures = user["failed_logins"] + 1
            locked = time.time() + self.lock_seconds if failures >= self.max_failures else None
            self._set(username, failed_logins=0 if locked else failures, locked_until=locked)
            return None, "locked after repeated failures" if locked else "wrong password"
        if user["disabled"]:
            return None, "disabled"
        self._set(username, failed_logins=0, locked_until=None, last_login_at=time.time())
        return user, ""
