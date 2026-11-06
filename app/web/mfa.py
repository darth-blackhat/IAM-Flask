"""Second factor for the web UIs: TOTP (RFC 6238; any authenticator app) and one-time
recovery codes.

- The TOTP secret is stored encrypted (AES-GCM, key derived from WEB_SECRET_KEY with HKDF),
  so a copy of the database alone does not reveal it.
- A code is accepted once: the time step it used is remembered and older steps are refused.
- Recovery codes are random, shown once, and stored only as SHA-256 hashes.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STEP, DIGITS, WINDOW = 30, 6, 1          # 30 s codes, 6 digits, accept one step either side
RECOVERY_CODES = 10


class MfaError(ValueError):
    pass


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_key: str) -> bytes:
    if not secret_key:
        raise MfaError("WEB_SECRET_KEY must be set to use MFA (it protects the stored secrets)")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"backend-iam/mfa/v1",
                info=b"totp-secret").derive(secret_key.encode())


def seal(secret: str, secret_key: str) -> str:
    nonce = secrets.token_bytes(12)
    return "v1:" + base64.b64encode(nonce + AESGCM(_key(secret_key)).encrypt(nonce, secret.encode(), b"totp")).decode()


def unseal(sealed: str, secret_key: str) -> str:
    try:
        raw = base64.b64decode(sealed.removeprefix("v1:"))
        return AESGCM(_key(secret_key)).decrypt(raw[:12], raw[12:], b"totp").decode()
    except MfaError:
        raise
    except Exception:
        raise MfaError("the MFA secret cannot be read (WEB_SECRET_KEY changed?); an admin must reset MFA")


def code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, last_counter: int | None, now: float | None = None) -> int | None:
    """The time step `code` belongs to, or None. Steps at or before last_counter are refused."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for counter in range(current - WINDOW, current + WINDOW + 1):
        if last_counter is not None and counter <= last_counter:
            continue
        if hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def otpauth_uri(secret: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """(codes to show once, hashes to store)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"           # no look-alikes
    codes = ["-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2))
             for _ in range(RECOVERY_CODES)]
    return codes, [hash_recovery(c) for c in codes]


def hash_recovery(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace(" ", "").encode()).hexdigest()
