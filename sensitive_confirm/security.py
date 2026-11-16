"""Password hashing, MAC helpers and the locally provisioned confirm key."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import string
import time
from pathlib import Path

PBKDF2_ROUNDS = 120_000
KEY_BYTES = 32


def b64e(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    import base64
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 PBKDF2_ROUNDS)
    return b64e(salt), b64e(digest)


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = b64d(salt_b64)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 PBKDF2_ROUNDS)
    return hmac.compare_digest(b64e(digest), hash_b64)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mac(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def mac_bytes(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class ConfirmKey:
    """The server-side confirm secret, provisioned by ``init``.

    It is deliberately *not* readable through any HTTP endpoint.  Requests may
    supply a confirmation code derived from it (the human proves possession),
    but the key itself is never taken from a request and never used as truth.
    """

    def __init__(self, key: bytes, path: Path):
        self._key = key
        self.path = path

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "ConfirmKey":
        p = Path(path)
        raw = json.loads(p.read_text(encoding="utf-8"))
        key = b64d(raw["confirm_key"])
        if len(key) < 32:
            raise ValueError("confirm key is too short")
        return cls(key, p)

    @classmethod
    def save(cls, path: str | os.PathLike[str]) -> "ConfirmKey":
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(KEY_BYTES)
        p.write_text(json.dumps({
            "format": "sensitive-confirm-key/v1",
            "created_at": int(time.time()),
            "confirm_key": b64e(key),
        }, indent=2), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return cls(key, p)

    @property
    def raw(self) -> bytes:
        """Only used by the admin endpoint comparison and the init command.
        Never serialised into an HTTP response."""
        return self._key

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()[:16]

    def confirmation_code(self, tenant_id: str, user_id: str, challenge: str,
                          expires_at: int, purpose: str,
                          row_id: str, fields: list[tuple[str, str]]) -> str:
        """Deterministic 8-digit code the user reads off the prepare response
        and types back.  It is a MAC over every field of the intent, so a code
        copied from another intent / challenge / field cannot verify."""
        msg = "|".join([
            "confirm-code/v1", purpose, tenant_id, user_id, challenge,
            str(expires_at), row_id,
        ] + [f"{k}={v}" for k, v in fields]).encode("utf-8")
        digest = mac_bytes(self._key, msg)
        num = int.from_bytes(digest[:8], "big") % 100_000_000
        return f"{num:08d}"

    def code_matches(self, expected: str, supplied: str) -> bool:
        return hmac.compare_digest(expected.encode(), supplied.encode())


_ALPHABET = string.ascii_letters + string.digits


def random_code(length: int = 8) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))
