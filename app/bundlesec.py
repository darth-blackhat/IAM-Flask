"""Signing and encryption of the per-domain zips.

Signature: Ed25519 over manifest.json, stored as manifest.sig (base64) in the zip. The
manifest lists the sha256 of every other file, so one signature covers the whole zip.
Encryption: the finished zip is encrypted with age (X25519) to one or more recipients:
openiam-DOMAIN-UTC.zip.age, readable with `age -d -i key.txt` as well as by the consumer.
Everything here works offline; keys are files made by `iam keys`.
"""

import base64
import hashlib
from pathlib import Path

import pyrage
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_FILE = "manifest.sig"


class BundleSecurityError(Exception):
    pass


# ---- keys ---------------------------------------------------------------------

def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:  # Windows: rely on the folder's ACLs
        pass


def generate_signing_key(prefix: Path) -> tuple[Path, Path]:
    """<prefix>.key (private, keep on the producer site) and <prefix>.pub (give to consumers)."""
    key = Ed25519PrivateKey.generate()
    priv, pub = prefix.with_suffix(".key"), prefix.with_suffix(".pub")
    _write_secret(priv, key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def generate_age_identity(path: Path) -> str:
    """Write an age identity (consumer site keeps it); return its recipient (give to producer)."""
    ident = pyrage.x25519.Identity.generate()
    recipient = str(ident.to_public())
    _write_secret(path, f"# public key: {recipient}\n{ident}\n".encode())
    return recipient


def load_signing_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleSecurityError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise BundleSecurityError(f"{path} is not an Ed25519 public key")
    return key


def key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_recipients(values: list[str]) -> list:
    """age recipients given inline ("age1...") or as files containing them."""
    out = []
    for v in values:
        text = v if v.startswith("age1") else Path(v).read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("age1"):
                out.append(pyrage.x25519.Recipient.from_str(line))
    if values and not out:
        raise BundleSecurityError("no age recipients found in export.encrypt_to")
    return out


def load_identities(path: str) -> list:
    idents = [pyrage.x25519.Identity.from_str(line.strip())
              for line in Path(path).read_text(encoding="utf-8").splitlines()
              if line.strip().startswith("AGE-SECRET-KEY-")]
    if not idents:
        raise BundleSecurityError(f"no age identity in {path}")
    return idents


# ---- sign / verify ------------------------------------------------------------

def sign(manifest_bytes: bytes, key: Ed25519PrivateKey) -> bytes:
    return base64.b64encode(key.sign(manifest_bytes))


def verify(manifest_bytes: bytes, signature_b64: bytes | None,
           trusted: dict[str, Ed25519PublicKey]) -> str:
    """Return the key id that signed the manifest, or raise."""
    if not signature_b64:
        raise BundleSecurityError("zip is not signed (no manifest.sig)")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError as e:
        raise BundleSecurityError("manifest.sig is not valid base64") from e
    for kid, public in trusted.items():
        try:
            public.verify(signature, manifest_bytes)
            return kid
        except InvalidSignature:
            continue
    raise BundleSecurityError("signature does not match any trusted signing key")


# ---- encrypt / decrypt --------------------------------------------------------

def encrypt(data: bytes, recipients: list) -> bytes:
    return pyrage.encrypt(data, recipients)


def decrypt(data: bytes, identities: list) -> bytes:
    try:
        return pyrage.decrypt(data, identities)
    except pyrage.DecryptError as e:
        raise BundleSecurityError(f"cannot decrypt: {e}") from e
