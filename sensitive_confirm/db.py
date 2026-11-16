"""SQLite schema, connection hardening and small persistence helpers.

Design notes
------------
* Every service process opens its own connections; the WAL database is the
  only shared state (plus the local confirm key, which is a server-side secret
  provisioned by the init command).
* Security relevant tables are protected with triggers so that even a buggy
  query cannot resurrect a consumed session / ticket or rewrite an immutable
  intent.  The triggers are deliberately part of the schema, not of the
  application, and are demonstrated by ``selftest``.
* Time is measured in integer milliseconds since the Unix epoch (UTC).
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = "1"
BUSY_TIMEOUT_MS = 30_000

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    login_name  TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    UNIQUE (tenant_id, login_name)
);

CREATE TABLE IF NOT EXISTS configs (
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    config_id  TEXT NOT NULL,
    version    INTEGER NOT NULL CHECK (version >= 1),
    value      TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, config_id)
);

-- A login session.  ``token_hash`` is the sha256 of the secret session token;
-- the raw token is never stored.  ``rotated_at`` implements "session rotation":
-- a rotated session can never be used again (nor can its outstanding tickets).
CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    token_hash     TEXT NOT NULL UNIQUE,
    tenant_id      TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    revoked_at     INTEGER,
    revoke_reason  TEXT,
    rotated_at     INTEGER
);

-- Immutable operation intent captured by /v1/prepare.  Anything that is
-- confirmed lives here and nowhere else; /v1/execute never reads desired
-- fields from the request body.
CREATE TABLE IF NOT EXISTS intents (
    intent_id      TEXT PRIMARY KEY,
    challenge_hash TEXT NOT NULL UNIQUE,
    tenant_id      TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    config_id      TEXT NOT NULL,
    expected_version INTEGER NOT NULL,
    new_value      TEXT NOT NULL,
    summary_json   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL
);

-- One approval per challenge (= per intent).  The UNIQUE(intent_id) plus the
-- single-transaction check "not exists" guarantee at most one approval row.
CREATE TABLE IF NOT EXISTS approvals (
    approval_id     TEXT PRIMARY KEY,
    intent_id       TEXT NOT NULL UNIQUE REFERENCES intents(intent_id),
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    confirmed_at    INTEGER NOT NULL
);

-- One conjunction record per intent.  It is only inserted in the same
-- transaction that flips a ticket to ``used``; its PRIMARY KEY makes a second
-- execution of the same intent impossible.
CREATE TABLE IF NOT EXISTS executions (
    intent_id  TEXT PRIMARY KEY REFERENCES intents(intent_id),
    ticket_id  TEXT NOT NULL UNIQUE,
    outcome    TEXT NOT NULL,
    result_json TEXT NOT NULL,
    executed_at INTEGER NOT NULL
);

-- An issued one-time ticket.  ``payload`` is the client-visible signed blob;
-- ``state`` moves issued -> used exactly once.
CREATE TABLE IF NOT EXISTS tickets (
    ticket_id   TEXT PRIMARY KEY,
    payload     TEXT NOT NULL UNIQUE,
    intent_id   TEXT NOT NULL REFERENCES intents(intent_id),
    approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
    tenant_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('issued', 'used')),
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);

-- Failed-confirmation counter, so an 8 digit code cannot be brute forced.
-- Mutable by design; it carries no authority.
CREATE TABLE IF NOT EXISTS verify_attempts (
    challenge_hash TEXT PRIMARY KEY,
    attempts       INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    action     TEXT NOT NULL,
    tenant_id  TEXT,
    user_id    TEXT,
    session_id TEXT,
    intent_id  TEXT,
    ticket_id  TEXT,
    detail     TEXT
);

-- Append-only audit log.
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

-- A revoked or rotated session stays revoked.
CREATE TRIGGER IF NOT EXISTS sessions_no_resurrect
BEFORE UPDATE OF revoked_at, rotated_at ON sessions
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'session cannot be un-revoked');
END;

CREATE TRIGGER IF NOT EXISTS sessions_no_unrotate
BEFORE UPDATE OF rotated_at ON sessions
WHEN OLD.rotated_at IS NOT NULL AND NEW.rotated_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'session cannot be un-rotated');
END;

-- Intents are immutable.  UPDATE is rejected outright; we never need to update
-- an intent (expiry is stored at creation time).
CREATE TRIGGER IF NOT EXISTS intents_no_update
BEFORE UPDATE ON intents
BEGIN
    SELECT RAISE(ABORT, 'intent is immutable');
END;

CREATE TRIGGER IF NOT EXISTS approvals_no_update
BEFORE UPDATE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approval is immutable');
END;

CREATE TRIGGER IF NOT EXISTS executions_no_update
BEFORE UPDATE ON executions
BEGIN
    SELECT RAISE(ABORT, 'execution record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS executions_no_delete
BEFORE DELETE ON executions
BEGIN
    SELECT RAISE(ABORT, 'execution record is immutable');
END;

-- A consumed ticket can never go back to issued.
CREATE TRIGGER IF NOT EXISTS tickets_no_reissue
BEFORE UPDATE OF state ON tickets
WHEN OLD.state = 'used' AND NEW.state <> 'used'
BEGIN
    SELECT RAISE(ABORT, 'used ticket cannot be re-issued');
END;

-- A ticket's identity and lifetime are fixed when it is issued.  Only the
-- state column may change (issued -> used).  This makes it impossible for a
-- future code change, or an operator with a SQL prompt, to re-point a ticket at
-- another session / intent or to extend its life.
CREATE TRIGGER IF NOT EXISTS tickets_binding_immutable
BEFORE UPDATE OF ticket_id, payload, intent_id, approval_id, tenant_id,
                 user_id, session_id, issued_at, expires_at ON tickets
WHEN NEW.ticket_id IS NOT OLD.ticket_id
  OR NEW.payload IS NOT OLD.payload
  OR NEW.intent_id IS NOT OLD.intent_id
  OR NEW.approval_id IS NOT OLD.approval_id
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.user_id IS NOT OLD.user_id
  OR NEW.session_id IS NOT OLD.session_id
  OR NEW.issued_at IS NOT OLD.issued_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
    SELECT RAISE(ABORT, 'ticket binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS tickets_no_delete
BEFORE DELETE ON tickets
BEGIN
    SELECT RAISE(ABORT, 'ticket cannot be deleted');
END;
"""


def now_ms() -> int:
    return int(time.time() * 1000)


def connect(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open a hardened connection.

    ``check_same_thread=False`` lets one connection be used by the test harness
    after it has been spawned in another thread; each process still creates its
    own connections and never shares one between threads concurrently.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_MS / 1000.0,
                           isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL gives concurrent readers with a single writer; FULL makes a committed
    # transaction durable on power loss / hard process kill (SQLite flushes and
    # fsyncs the WAL on commit).  Checking the mode first keeps this a read on
    # the hot path instead of a schema-lock write on every request.
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    if str(mode).lower() != "wal":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO NOTHING", (SCHEMA_VERSION,))


def tx_begin(conn: sqlite3.Connection) -> None:
    """Start a deferred transaction.  The first statement inside it must be a
    read that acquires the required lock (see services._lock_row)."""
    conn.execute("BEGIN")


def tx_commit(conn: sqlite3.Connection) -> None:
    conn.execute("COMMIT")


def tx_rollback(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def audit(conn: sqlite3.Connection, action: str, *, tenant_id=None,
          user_id=None, session_id=None, intent_id=None, ticket_id=None,
          detail=None, at=None) -> None:
    conn.execute(
        "INSERT INTO audit_log(at, action, tenant_id, user_id, session_id,"
        " intent_id, ticket_id, detail) VALUES (?,?,?,?,?,?,?,?)",
        (at if at is not None else now_ms(), action, tenant_id, user_id,
         session_id, intent_id, ticket_id, detail))


def database_integrity(db_path: str) -> tuple[bool, str]:
    try:
        conn = connect(db_path)
        row = conn.execute("PRAGMA integrity_check").fetchone()
        fk = conn.execute("PRAGMA foreign_key_check").fetchall()
        conn.close()
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        return False, f"sqlite error: {exc}"
    if row is None or row[0] != "ok":
        return False, f"integrity_check: {row[0] if row else 'no result'}"
    if fk:
        return False, f"foreign_key_check: {len(fk)} violation(s)"
    return True, "ok"
