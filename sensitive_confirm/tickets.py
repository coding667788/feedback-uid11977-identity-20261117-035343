"""Ticket payload signing and verification.

The ticket token is ``v1.<b64url(payload)>.<hex mac>``.  The MAC covers the
payload byte-for-byte; the payload in turn duplicates the intent / session /
user identifiers.  Even though every field is also re-bound in the database,
signing lets the server reject a tampered ticket before it looks anything up.
"""

from __future__ import annotations

import base64
import json

from . import security


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


TICKET_VERSION = "v1"


def sign_ticket(key: bytes, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    tag = security.mac_bytes(key, b"sensitive-confirm-ticket/v1|" + body).hex()
    return f"{TICKET_VERSION}.{_b64e(body)}.{tag}"


def parse_ticket(key: bytes, token: str) -> dict | None:
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    version, body_b64, tag = token.split(".")
    if version != TICKET_VERSION:
        return None
    try:
        body = _b64d(body_b64)
    except Exception:
        return None
    expected = security.mac_bytes(key, b"sensitive-confirm-ticket/v1|" + body).hex()
    if not security.constant_time_eq(expected, tag):
        return None
    try:
        payload = json.loads(body)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload
