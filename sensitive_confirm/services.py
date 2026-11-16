"""Core service logic.

All choreography lives below the HTTP layer so that the HTTP handlers are thin
and the security invariants can be tested directly.

Invariants implemented here
---------------------------
1. A normal login session can read / prepare but never write a config.
2. ``prepare`` snapshots an *immutable* intent (tenant, user, session, config,
   expected version, new value) and a challenge derived from it.
3. ``verify`` requires the locally provisioned confirm key (its code) and
   creates at most one approval per challenge, issuing a 30 s one-time ticket
   bound to the intent *and* the originating login session.
4. ``execute`` successfully runs exactly one transaction that atomically:
     - re-validates the caller's identity, session and account state,
     - claims the ticket (issued -> used),
     - inserts the execution record (PRIMARY KEY on intent_id -> no double
       execution),
     - applies the config CAS ``version = expected_version``.
   A retry with the same ticket after a committed execution returns the stored
   result, again only after re-checking identity / session / disabled state.
5. Revocation, rotation and disable wins over an execution that has already
   been *verified* but not committed: the execution transaction re-reads those
   rows after it has acquired the write lock, so it aborts rather than writing.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass

from . import db, security, tickets
from .crashpoints import CrashPoint

SESSION_TTL_MS = 12 * 60 * 60 * 1000
INTENT_TTL_MS = 5 * 60 * 1000
TICKET_TTL_MS = 30_000
MAX_VERIFY_ATTEMPTS = 10
VERIFY_LOCK_MS = 60_000


def code_echo_enabled() -> bool:
    return os.environ.get("SC_CODE_ECHO", "0") == "1"


def ticket_ttl_ms() -> int:
    """30 s by default.  Overridable for the expiry-boundary tests only; the
    service never reads this from a request."""
    try:
        return max(1, int(os.environ.get("SC_TICKET_TTL_MS", TICKET_TTL_MS)))
    except ValueError:
        return TICKET_TTL_MS


def intent_ttl_ms() -> int:
    try:
        return max(1, int(os.environ.get("SC_INTENT_TTL_MS", INTENT_TTL_MS)))
    except ValueError:
        return INTENT_TTL_MS


_SECRET_FIELD_NAMES = {"confirm_key", "confirm_key_hex", "confirmation_key",
                       "server_key", "admin_key", "secret"}


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra

    def body(self) -> dict:
        out = {"ok": False, "error": self.code, "message": self.message}
        out.update(self.extra)
        return out


@dataclass
class Ctx:
    db_path: str
    confirm_key: security.ConfirmKey
    crashes: dict[str, CrashPoint]

    @classmethod
    def load(cls, db_path: str, key_path: str, crashes=None) -> "Ctx":
        return cls(db_path=db_path, confirm_key=security.ConfirmKey.load(key_path),
                   crashes=crashes or {})

    # -- helpers ---------------------------------------------------------
    def conn(self) -> sqlite3.Connection:
        return db.connect(self.db_path)

    def crash(self, name: str) -> None:
        point = self.crashes.get(name)
        if point is not None:
            point.hit()


def _now() -> int:
    return db.now_ms()


# ---------------------------------------------------------------------------
# Identity / session
# ---------------------------------------------------------------------------

def _load_session(conn: sqlite3.Connection, token: str | None,
                  now: int) -> sqlite3.Row:
    if not token:
        raise ServiceError(401, "unauthenticated", "missing session token")
    h = security.sha256_hex(token)
    row = conn.execute(
        "SELECT s.*, u.disabled FROM sessions s JOIN users u"
        " ON u.user_id = s.user_id WHERE s.token_hash = ?", (h,)).fetchone()
    if row is None:
        raise ServiceError(401, "unauthenticated", "unknown session token")
    if row["revoked_at"] is not None:
        raise ServiceError(401, "session_revoked", "session was revoked")
    if row["rotated_at"] is not None:
        raise ServiceError(401, "session_rotated", "session was rotated")
    if row["expires_at"] <= now:
        raise ServiceError(401, "session_expired", "session expired")
    if row["disabled"]:
        raise ServiceError(403, "account_disabled", "account is disabled")
    return row


def login(ctx: Ctx, tenant_id: str, login_name: str, password: str) -> dict:
    now = _now()
    conn = ctx.conn()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE tenant_id = ? AND login_name = ?",
            (tenant_id, login_name)).fetchone()
        if user is None or not security.verify_password(
                password, user["password_salt"], user["password_hash"]):
            raise ServiceError(401, "invalid_credentials", "bad tenant/user/password")
        if user["disabled"]:
            raise ServiceError(403, "account_disabled", "account is disabled")
        token = security.random_token()
        session_id = "ses_" + security.random_token(12)
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO sessions(session_id, token_hash, tenant_id, user_id,"
                " created_at, last_seen_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (session_id, security.sha256_hex(token), tenant_id,
                 user["user_id"], now, now, now + SESSION_TTL_MS))
            db.audit(conn, "login", tenant_id=tenant_id, user_id=user["user_id"],
                     session_id=session_id)
            conn.execute("COMMIT")
        except Exception:
            db.tx_rollback(conn)
            raise
        return {"ok": True, "session_token": token, "session_id": session_id,
                "tenant_id": tenant_id, "user_id": user["user_id"],
                "expires_at": now + SESSION_TTL_MS}
    finally:
        conn.close()


def whoami(ctx: Ctx, token: str | None) -> dict:
    now = _now()
    conn = ctx.conn()
    try:
        row = _load_session(conn, token, now)
        return {"ok": True, "session_id": row["session_id"],
                "tenant_id": row["tenant_id"], "user_id": row["user_id"],
                "expires_at": row["expires_at"],
                "rotated_at": row["rotated_at"]}
    finally:
        conn.close()


def logout(ctx: Ctx, token: str | None) -> dict:
    now = _now()
    conn = ctx.conn()
    try:
        row = _load_session(conn, token, now)
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE sessions SET revoked_at = ?, revoke_reason = 'logout'"
                " WHERE session_id = ? AND revoked_at IS NULL",
                (now, row["session_id"]))
            # Fail-closed: everything issued from this session dies with it, in
            # the same transaction as the revocation.
            cur = conn.execute(
                "UPDATE tickets SET state = 'used', used_at = ?"
                " WHERE session_id = ? AND state = 'issued'",
                (now, row["session_id"]))
            db.audit(conn, "logout", tenant_id=row["tenant_id"],
                     user_id=row["user_id"], session_id=row["session_id"],
                     detail=json.dumps({"tickets_invalidated": cur.rowcount}))
            conn.execute("COMMIT")
        except BaseException:
            db.tx_rollback(conn)
            raise
        ctx.crash("after_session_revoke")
        return {"ok": True, "revoked_session_id": row["session_id"]}
    finally:
        conn.close()


def rotate_session(ctx: Ctx, token: str | None) -> dict:
    """Browser-session rotation: the old session and every ticket tied to it
    become unusable immediately; a fresh session token is returned."""
    now = _now()
    conn = ctx.conn()
    try:
        row = _load_session(conn, token, now)
        new_token = security.random_token()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE sessions SET rotated_at = ?, revoke_reason = 'rotated'"
                " WHERE session_id = ? AND rotated_at IS NULL",
                (now, row["session_id"]))
            new_sid = "ses_" + security.random_token(12)
            conn.execute(
                "INSERT INTO sessions(session_id, token_hash, tenant_id, user_id,"
                " created_at, last_seen_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (new_sid, security.sha256_hex(new_token), row["tenant_id"],
                 row["user_id"], now, now, row["expires_at"]))
            conn.execute(
                "UPDATE tickets SET state = 'used', used_at = ?"
                " WHERE session_id = ? AND state = 'issued'",
                (now, row["session_id"]))
            db.audit(conn, "session_rotate", tenant_id=row["tenant_id"],
                     user_id=row["user_id"], session_id=row["session_id"],
                     detail=json.dumps({"new_session_id": new_sid}))
            conn.execute("COMMIT")
        except Exception:
            db.tx_rollback(conn)
            raise
        return {"ok": True, "session_token": new_token, "session_id": new_sid,
                "rotated_from": row["session_id"]}
    finally:
        conn.close()


def admin_set_disabled(ctx: Ctx, tenant_id: str, login_name: str,
                       disabled: bool) -> dict:
    now = _now()
    conn = ctx.conn()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE tenant_id = ? AND login_name = ?",
            (tenant_id, login_name)).fetchone()
        if user is None:
            raise ServiceError(404, "not_found", "user not found")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("UPDATE users SET disabled = ? WHERE user_id = ?",
                         (1 if disabled else 0, user["user_id"]))
            reason = "account_disabled" if disabled else "account_enabled"
            revoked = 0
            if disabled:
                cur = conn.execute(
                    "UPDATE sessions SET revoked_at = ?, revoke_reason = ?"
                    " WHERE user_id = ? AND revoked_at IS NULL",
                    (now, reason, user["user_id"]))
                revoked = cur.rowcount
                # Fail closed: every outstanding ticket of the user is consumed
                # in the same transaction that disables the account.
                conn.execute(
                    "UPDATE tickets SET state = 'used', used_at = ?"
                    " WHERE user_id = ? AND state = 'issued'",
                    (now, user["user_id"]))
            db.audit(conn, reason, tenant_id=tenant_id,
                     user_id=user["user_id"],
                     detail=json.dumps({"sessions_revoked": revoked}))
            conn.execute("COMMIT")
        except Exception:
            db.tx_rollback(conn)
            raise
        ctx.crash("after_session_revoke")
        return {"ok": True, "user_id": user["user_id"], "disabled": bool(disabled),
                "sessions_revoked": revoked}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def list_configs(ctx: Ctx, token: str | None) -> dict:
    now = _now()
    conn = ctx.conn()
    try:
        session = _load_session(conn, token, now)
        rows = conn.execute(
            "SELECT config_id, version, value, updated_by, updated_at"
            " FROM configs WHERE tenant_id = ? ORDER BY config_id",
            (session["tenant_id"],)).fetchall()
        return {"ok": True, "tenant_id": session["tenant_id"],
                "configs": [dict(r) for r in rows]}
    finally:
        conn.close()


def get_config(ctx: Ctx, token: str | None, config_id: str) -> dict:
    now = _now()
    conn = ctx.conn()
    try:
        session = _load_session(conn, token, now)
        row = conn.execute(
            "SELECT config_id, version, value, updated_by, updated_at"
            " FROM configs WHERE tenant_id = ? AND config_id = ?",
            (session["tenant_id"], config_id)).fetchone()
        if row is None:
            raise ServiceError(404, "config_not_found", "unknown config_id")
        return {"ok": True, "tenant_id": session["tenant_id"], **dict(row)}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# prepare
# ---------------------------------------------------------------------------

def _intent_summary(tenant_id: str, user_id: str, session_id: str,
                    config_id: str, expected_version: int, new_value: str,
                    challenge: str, expires_at: int) -> str:
    return json.dumps({
        "action": "update_service_config",
        "tenant_id": tenant_id,
        "user_id": user_id,
        "session_id": session_id,
        "config_id": config_id,
        "expected_version": expected_version,
        "new_value": new_value,
        "challenge": challenge,
        "intent_expires_at": expires_at,
    }, sort_keys=True)


def prepare(ctx: Ctx, token: str | None, body: dict) -> dict:
    now = _now()
    config_id = body.get("config_id")
    expected_version = body.get("expected_version")
    new_value = body.get("new_value")

    if not isinstance(config_id, str) or not config_id:
        raise ServiceError(400, "invalid_request", "config_id must be a non-empty string")
    if not isinstance(expected_version, int) or isinstance(expected_version, bool):
        raise ServiceError(400, "invalid_request", "expected_version must be an integer")
    if not isinstance(new_value, str):
        raise ServiceError(400, "invalid_request", "new_value must be a string")
    if len(new_value) > 4096:
        raise ServiceError(400, "invalid_request", "new_value is too long")
    # A caller may not propose tenant/user/session themselves.
    for forbidden in ("tenant_id", "user_id", "session_id"):
        if forbidden in body:
            raise ServiceError(
                400, "request_cannot_choose_identity",
                f"{forbidden} comes from the session, not from the request")

    challenge = "chl_" + security.random_token(18)
    intent_id = "int_" + security.random_token(12)
    intent_expires_at = now + intent_ttl_ms()

    conn = ctx.conn()
    try:
        session = _load_session(conn, token, now)
        tenant_id, user_id, session_id = (
            session["tenant_id"], session["user_id"], session["session_id"])
        # Serialise prepares so "latest version" is well defined under load.
        conn.execute("BEGIN IMMEDIATE")
        try:
            cfg = conn.execute(
                "SELECT version, value FROM configs WHERE tenant_id = ? AND"
                " config_id = ?", (tenant_id, config_id)).fetchone()
            if cfg is None:
                raise ServiceError(404, "config_not_found", "unknown config_id")
            if cfg["version"] != expected_version:
                # Refuse to build a challenge the caller already knows is
                # stale: the user would be confirming content that no longer
                # describes the resource, and the execution could only fail.
                raise ServiceError(
                    409, "stale_expected_version",
                    "expected_version does not match the current resource"
                    " version; nothing was prepared",
                    expected_version=expected_version,
                    current_version=cfg["version"],
                    current_value=cfg["value"])
            summary = _intent_summary(tenant_id, user_id, session_id, config_id,
                                      expected_version, new_value, challenge,
                                      intent_expires_at)
            conn.execute(
                "INSERT INTO intents(intent_id, challenge_hash, tenant_id,"
                " user_id, session_id, config_id, expected_version, new_value,"
                " summary_json, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (intent_id, security.sha256_hex(challenge), tenant_id, user_id,
                 session_id, config_id, expected_version, new_value, summary,
                 now, intent_expires_at))
            db.audit(conn, "prepare", tenant_id=tenant_id, user_id=user_id,
                     session_id=session_id, intent_id=intent_id,
                     detail=summary)
            conn.execute("COMMIT")
        except BaseException:
            db.tx_rollback(conn)
            raise

        code = ctx.confirm_key.confirmation_code(
            tenant_id, user_id, challenge, intent_expires_at, "update_config",
            intent_id, [("config_id", config_id),
                        ("expected_version", str(expected_version)),
                        ("new_value", new_value)])

        resp = {
            "ok": True,
            "intent_id": intent_id,
            "challenge": challenge,
            "challenge_expires_at": intent_expires_at,
            "pending_action": {
                "action": "update_service_config",
                "tenant_id": tenant_id,
                "user_id": user_id,
                "session_id": session_id,
                "config_id": config_id,
                "current_version": cfg["version"],
                "current_value": cfg["value"],
                "expected_version": expected_version,
                "new_value": new_value,
                "version_confirmed_current": True,
            },
            "note": ("Confirm the exact fields above. The one-time confirmation"
                     " code binds this challenge, session and every field; it"
                     " expires with the challenge and yields a 30 s ticket."),
        }
        if code_echo_enabled():
            # Explicitly opt-in and only for local demos: in a real deployment
            # the code is delivered out of band (SMS/TOTP are out of scope).
            resp["confirmation_code"] = code
            resp["confirmation_code_note"] = (
                "SC_CODE_ECHO=1 is a local-demo shortcut. With it off, no HTTP"
                " endpoint ever reveals the code -- it can only be derived from"
                " the provisioned confirm key.")
        return resp
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def verify(ctx: Ctx, token: str | None, body: dict) -> dict:
    now = _now()
    challenge = body.get("challenge")
    supplied_code = body.get("confirmation_code")
    if not isinstance(challenge, str) or not challenge:
        raise ServiceError(400, "invalid_request", "challenge is required")
    if not isinstance(supplied_code, str) or not supplied_code:
        raise ServiceError(400, "invalid_request", "confirmation_code is required")
    injected = sorted(k for k in body if k in _SECRET_FIELD_NAMES)
    if injected:
        # The confirm key is server-side truth provisioned by `init`; it is
        # never taken from a request, so a request trying to supply one is
        # rejected outright instead of silently ignored.
        raise ServiceError(400, "request_cannot_supply_key",
                           "server-side confirmation key cannot come from a"
                           " request", rejected_fields=injected)

    conn = ctx.conn()
    try:
        session = _load_session(conn, token, now)
        ch_hash = security.sha256_hex(challenge)

        # Rate limit before touching the code: an 8 digit code is only safe if
        # guessing is expensive.  attempts/locked_until are advisory only.
        attempt = conn.execute(
            "SELECT * FROM verify_attempts WHERE challenge_hash = ?",
            (ch_hash,)).fetchone()
        if attempt and attempt["locked_until"] and attempt["locked_until"] > now:
            raise ServiceError(429, "too_many_attempts",
                               "too many failed confirmations for this challenge",
                               retry_after_ms=attempt["locked_until"] - now)

        conn.execute("BEGIN IMMEDIATE")
        try:
            intent = conn.execute(
                "SELECT * FROM intents WHERE challenge_hash = ?",
                (ch_hash,)).fetchone()
            if intent is None:
                raise ServiceError(404, "unknown_challenge", "unknown challenge")
            _assert_intent_owner(intent, session)
            if intent["expires_at"] <= now:
                raise ServiceError(410, "challenge_expired", "challenge expired")

            expected_code = ctx.confirm_key.confirmation_code(
                intent["tenant_id"], intent["user_id"], challenge,
                intent["expires_at"], "update_config", intent["intent_id"],
                [("config_id", intent["config_id"]),
                 ("expected_version", str(intent["expected_version"])),
                 ("new_value", intent["new_value"])])
            if not ctx.confirm_key.code_matches(expected_code, supplied_code):
                _record_failed_attempt(conn, ch_hash, now, attempt)
                db.audit(conn, "verify_rejected", tenant_id=intent["tenant_id"],
                         user_id=intent["user_id"], session_id=intent["session_id"],
                         intent_id=intent["intent_id"],
                         detail="confirmation code mismatch")
                conn.execute("COMMIT")
                raise ServiceError(403, "confirmation_rejected",
                                   "confirmation code is not valid for this action")

            existing = conn.execute(
                "SELECT * FROM approvals WHERE intent_id = ?",
                (intent["intent_id"],)).fetchone()
            if existing is not None:
                raise ServiceError(409, "already_confirmed",
                                   "this challenge has already been confirmed")

            # The ticket inherits the *intent's* session, which must still be
            # the calling session.  This is what stops a ticket (or approval)
            # from being moved to another browser session later.
            approval_id = "apr_" + security.random_token(12)
            ticket_id = "tkt_" + security.random_token(12)
            ticket_expires_at = now + ticket_ttl_ms()
            conn.execute(
                "INSERT INTO approvals(approval_id, intent_id, tenant_id,"
                " user_id, session_id, confirmed_at) VALUES (?,?,?,?,?,?)",
                (approval_id, intent["intent_id"], intent["tenant_id"],
                 intent["user_id"], intent["session_id"], now))
            payload = {
                "v": 1,
                "ticket_id": ticket_id,
                "intent_id": intent["intent_id"],
                "challenge": challenge,
                "tenant_id": intent["tenant_id"],
                "user_id": intent["user_id"],
                "session_id": intent["session_id"],
                "config_id": intent["config_id"],
                "expected_version": intent["expected_version"],
                "new_value_sha256": security.sha256_hex(intent["new_value"]),
                "issued_at": now,
                "expires_at": ticket_expires_at,
                "nonce": security.random_token(8),
            }
            token_str = tickets.sign_ticket(ctx.confirm_key.raw, payload)
            conn.execute(
                "INSERT INTO tickets(ticket_id, payload, intent_id, approval_id,"
                " tenant_id, user_id, session_id, state, issued_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,'issued',?,?)",
                (ticket_id, token_str, intent["intent_id"], approval_id,
                 intent["tenant_id"], intent["user_id"], intent["session_id"],
                 now, ticket_expires_at))
            conn.execute("DELETE FROM verify_attempts WHERE challenge_hash = ?",
                         (ch_hash,))
            db.audit(conn, "verify_approved", tenant_id=intent["tenant_id"],
                     user_id=intent["user_id"], session_id=intent["session_id"],
                     intent_id=intent["intent_id"], ticket_id=ticket_id)
            conn.execute("COMMIT")
        except BaseException:
            db.tx_rollback(conn)
            raise

        return {
            "ok": True,
            "approval_id": approval_id,
            "ticket": token_str,
            "ticket_id": ticket_id,
            "ticket_expires_at": ticket_expires_at,
            "expires_in_ms": ticket_expires_at - now,
            "intent_id": intent["intent_id"],
            "confirmed_action": json.loads(intent["summary_json"]),
        }
    finally:
        conn.close()


def _assert_intent_owner(intent: sqlite3.Row, session: sqlite3.Row) -> None:
    if (intent["tenant_id"] != session["tenant_id"]
            or intent["user_id"] != session["user_id"]
            or intent["session_id"] != session["session_id"]):
        raise ServiceError(403, "wrong_session",
                           "challenge does not belong to this session")


def _record_failed_attempt(conn, ch_hash: str, now: int, prior) -> None:
    attempts = (prior["attempts"] if prior else 0) + 1
    locked = now + VERIFY_LOCK_MS if attempts >= MAX_VERIFY_ATTEMPTS else None
    conn.execute(
        "INSERT INTO verify_attempts(challenge_hash, attempts, locked_until)"
        " VALUES (?,?,?) ON CONFLICT(challenge_hash) DO UPDATE SET"
        " attempts = excluded.attempts, locked_until = excluded.locked_until",
        (ch_hash, attempts, locked))


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------

def _claim_write_lock(conn: sqlite3.Connection, ticket_id: str) -> None:
    """First statement of the execution transaction: take the write lock.

    In WAL mode a write acquires SQLite's RESERVED lock.  A logout / disable
    that commits *before* this point is visible to every read we make afterwards
    (a deferred transaction takes its snapshot at its first read, which is after
    the lock is held).  A logout / disable that arrives *after* this point queues
    behind us and cannot land between "ticket used" and COMMIT.  Those two
    orderings are exactly what the race tests exercise.

    The no-op UPDATE is intentional: it has to be a write to take the lock, and
    writing the same value to an unclaimed ticket changes nothing.  The earlier
    "is this ticket even ours" checks run as *reads* and are re-done below.
    """
    conn.execute(
        "UPDATE tickets SET state = state WHERE ticket_id = ?", (ticket_id,))


def _load_owned_session(conn: sqlite3.Connection, session_id: str,
                        tenant_id: str, user_id: str, now: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT s.*, u.disabled FROM sessions s JOIN users u"
        " ON u.user_id = s.user_id WHERE s.session_id = ?",
        (session_id,)).fetchone()
    if row is None:
        raise ServiceError(401, "unauthenticated", "originating session is gone")
    if row["tenant_id"] != tenant_id or row["user_id"] != user_id:
        raise ServiceError(403, "ticket_identity_mismatch",
                           "ticket identity does not match session")
    if row["disabled"]:
        raise ServiceError(403, "account_disabled", "account is disabled")
    if row["revoked_at"] is not None:
        raise ServiceError(401, "session_revoked",
                           f"session revoked ({row['revoke_reason']})")
    if row["rotated_at"] is not None:
        raise ServiceError(401, "session_rotated", "session was rotated")
    if row["expires_at"] <= now:
        raise ServiceError(401, "session_expired", "session expired")
    return row


def execute(ctx: Ctx, token: str | None, body: dict) -> dict:
    now = _now()
    ticket_token = body.get("ticket")
    if not isinstance(ticket_token, str) or not ticket_token:
        raise ServiceError(400, "invalid_request", "ticket is required")
    # Explicitly refuse to let the request re-specify what is being changed.
    override = sorted(k for k in ("config_id", "expected_version", "new_value",
                                  "version", "value", "tenant_id", "user_id",
                                  "session_id") if k in body)
    if override:
        raise ServiceError(
            400, "request_cannot_override_intent",
            "execute only accepts the ticket; confirmed fields come from the"
            " saved intent", rejected_fields=override)

    payload = tickets.parse_ticket(ctx.confirm_key.raw, ticket_token)
    if payload is None:
        raise ServiceError(401, "invalid_ticket", "ticket signature is invalid")
    ticket_id = payload.get("ticket_id")
    intent_id = payload.get("intent_id")
    if not isinstance(ticket_id, str) or not isinstance(intent_id, str):
        raise ServiceError(401, "invalid_ticket", "ticket is malformed")

    conn = ctx.conn()
    try:
        caller = _load_session(conn, token, now)
        ctx.crash("before_begin")
        conn.execute("BEGIN")
        try:
            _claim_write_lock(conn, ticket_id)
            ctx.crash("before_claim")

            # Re-read everything *inside* the transaction and *after* the lock.
            session = _load_owned_session(
                conn, payload.get("session_id"), payload.get("tenant_id"),
                payload.get("user_id"), now)
            ticket = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()
            if ticket is None:
                raise ServiceError(401, "invalid_ticket", "unknown ticket")
            if not security.constant_time_eq(ticket["payload"], ticket_token):
                raise ServiceError(401, "invalid_ticket", "ticket payload mismatch")
            if (ticket["intent_id"] != intent_id
                    or ticket["tenant_id"] != caller["tenant_id"]
                    or ticket["user_id"] != caller["user_id"]
                    or ticket["session_id"] != caller["session_id"]
                    or ticket["session_id"] != session["session_id"]
                    or ticket["tenant_id"] != session["tenant_id"]
                    or ticket["user_id"] != session["user_id"]):
                # Covers "ticket moved to another login session" and
                # "ticket moved across tenants / users".
                raise ServiceError(403, "ticket_bound_to_other_session",
                                   "ticket is bound to a different login session")

            prior = conn.execute(
                "SELECT * FROM executions WHERE intent_id = ? OR ticket_id = ?",
                (intent_id, ticket_id)).fetchone()

            if ticket["state"] == "used":
                if prior is None:
                    # Ticket was consumed by logout/disable cleanup: the action
                    # never ran, and a consumed ticket never runs.
                    raise ServiceError(401, "ticket_invalidated",
                                       "ticket was invalidated before execution")
                # Idempotent replay.  Identity / session / disabled checks above
                # have already run against current state.
                conn.execute("COMMIT")
                return _replay_response(prior, ticket)
            if prior is not None:
                raise ServiceError(409, "already_executed",
                                   "intent already has an execution record")
            if ticket["expires_at"] <= now:
                raise ServiceError(410, "ticket_expired", "ticket expired")

            approval = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (ticket["approval_id"],)).fetchone()
            intent = conn.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
            if approval is None or intent is None:
                raise ServiceError(409, "inconsistent_state",
                                   "approval or intent missing")
            if (intent["tenant_id"] != caller["tenant_id"]
                    or intent["user_id"] != caller["user_id"]
                    or intent["session_id"] != caller["session_id"]
                    or intent["intent_id"] != ticket["intent_id"]):
                raise ServiceError(403, "ticket_bound_to_other_session",
                                   "intent is bound to a different session")
            # Belt and braces: the signed payload's digest of the new value must
            # match the stored intent.  A mismatch means the ticket was minted
            # by something other than this verify path.
            if payload.get("new_value_sha256") != security.sha256_hex(
                    intent["new_value"]):
                raise ServiceError(409, "ticket_intent_mismatch",
                                   "ticket does not describe this intent")

            # --- the committing transaction -----------------------------
            cur = conn.execute(
                "UPDATE tickets SET state = 'used', used_at = ?"
                " WHERE ticket_id = ? AND state = 'issued'", (now, ticket_id))
            if cur.rowcount != 1:
                raise ServiceError(409, "ticket_already_consumed",
                                   "ticket was consumed concurrently")
            ctx.crash("ticket_marked_used")

            cfg = conn.execute(
                "SELECT version, value FROM configs WHERE tenant_id = ?"
                " AND config_id = ?", (intent["tenant_id"], intent["config_id"])
            ).fetchone()
            if cfg is None:
                raise ServiceError(404, "config_not_found",
                                   "config disappeared after prepare")
            if cfg["version"] != intent["expected_version"]:
                raise ServiceError(
                    409, "version_conflict",
                    "resource version changed after prepare; nothing was applied",
                    expected_version=intent["expected_version"],
                    current_version=cfg["version"],
                    current_value=cfg["value"])

            new_version = cfg["version"] + 1
            upd = conn.execute(
                "UPDATE configs SET version = ?, value = ?, updated_by = ?,"
                " updated_at = ? WHERE tenant_id = ? AND config_id = ?"
                " AND version = ?",
                (new_version, intent["new_value"], intent["user_id"], now,
                 intent["tenant_id"], intent["config_id"],
                 intent["expected_version"]))
            if upd.rowcount != 1:
                # Unreachable while the row is locked, but if it ever happens
                # the transaction is rolled back rather than half-applied.
                raise ServiceError(409, "version_conflict",
                                   "CAS update lost; nothing was applied")
            ctx.crash("config_updated")

            result = {
                "action": "update_service_config",
                "tenant_id": intent["tenant_id"],
                "config_id": intent["config_id"],
                "previous_version": cfg["version"],
                "previous_value": cfg["value"],
                "version": new_version,
                "value": intent["new_value"],
                "intent_id": intent["intent_id"],
                "challenge": payload.get("challenge"),
                "ticket_id": ticket_id,
                "approval_id": approval["approval_id"],
                "executed_at": now,
            }
            result_json = json.dumps(result, sort_keys=True)
            conn.execute(
                "INSERT INTO executions(intent_id, ticket_id, outcome,"
                " result_json, executed_at) VALUES (?,?,'applied',?,?)",
                (intent_id, ticket_id, result_json, now))
            db.audit(conn, "execute_applied", tenant_id=intent["tenant_id"],
                     user_id=intent["user_id"], session_id=intent["session_id"],
                     intent_id=intent_id, ticket_id=ticket_id,
                     detail=result_json)
            conn.execute("COMMIT")
        except BaseException:
            db.tx_rollback(conn)
            raise

        ctx.crash("after_commit")
        return {"ok": True, "outcome": "applied", "result": result}
    finally:
        conn.close()


def _replay_response(prior: sqlite3.Row, ticket: sqlite3.Row) -> dict:
    return {
        "ok": True,
        "outcome": prior["outcome"],
        "idempotent_replay": True,
        "replayed_at": db.now_ms(),
        "original_executed_at": prior["executed_at"],
        "result": json.loads(prior["result_json"]),
    }
