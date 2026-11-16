"""``init`` / ``check`` / ``selftest`` command line entry point."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import db, security
from .init_data import SEED_CONFIGS, SEED_TENANTS, preset_users
from .security import ConfirmKey


def _open_or_create(db_path: str) -> sqlite3.Connection:
    conn = db.connect(db_path)
    db.init_schema(conn)
    return conn


def cmd_init(args) -> int:
    db_path = str(Path(args.db))
    key_path = str(Path(args.key))
    db_file = Path(db_path)
    if db_file.exists() and not args.force:
        print(json.dumps({"ok": False, "error": "database_exists",
                          "message": f"{db_path} exists; pass --force to reset"}))
        return 1
    if db_file.exists() and args.force:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(db_path + suffix)
            if candidate.exists():
                candidate.unlink()

    key = ConfirmKey.save(key_path) if (args.force or not Path(key_path).exists()) \
        else ConfirmKey.load(key_path)

    conn = _open_or_create(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        for tenant in SEED_TENANTS:
            conn.execute("INSERT OR IGNORE INTO tenants(tenant_id) VALUES (?)",
                         (tenant,))
        for user in preset_users():
            salt, digest = security.hash_password(user["password"])
            conn.execute(
                "INSERT OR REPLACE INTO users(user_id, tenant_id, login_name,"
                " password_salt, password_hash, disabled)"
                " VALUES (?,?,?,?,?,0)",
                (user["user_id"], user["tenant_id"], user["login_name"],
                 salt, digest))
        for cfg in SEED_CONFIGS:
            conn.execute(
                "INSERT OR REPLACE INTO configs(tenant_id, config_id, version,"
                " value, updated_by, updated_at) VALUES (?,?,?,?,'bootstrap',?)",
                (cfg["tenant_id"], cfg["config_id"], cfg["version"],
                 cfg["value"], db.now_ms()))
        conn.execute("INSERT INTO meta(key, value) VALUES ('initialised_at', ?)"
                     " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                     (str(db.now_ms()),))
        conn.execute("COMMIT")
    except Exception:
        db.tx_rollback(conn)
        raise
    finally:
        conn.close()

    print(json.dumps({
        "ok": True,
        "database": db_path,
        "confirm_key_file": key_path,
        "confirm_key_fingerprint": key.fingerprint,
        "admin_key": key.raw.hex(),
        "tenants": SEED_TENANTS,
        "users": [{k: u[k] for k in ("tenant_id", "login_name", "user_id",
                                     "password")} for u in preset_users()],
        "configs": SEED_CONFIGS,
        "note": "The admin key is printed once here for local testing; it is "
                "also the hex of confirm_key in the key file. Never serve it.",
    }, indent=2))
    return 0


_PROBE_INTENT = {
    "intent_id": "probe_intent", "challenge_hash": "probe_challenge",
    "tenant_id": "probe", "user_id": "probe", "session_id": "probe",
    "config_id": "probe", "expected_version": 1, "new_value": "v",
    "summary_json": "{}", "created_at": 0, "expires_at": 0,
}


def _expect_abort(fn) -> bool:
    try:
        fn()
    except sqlite3.DatabaseError:
        return True
    return False


def _probe_intent_immutable(conn) -> bool:
    conn.execute(
        "INSERT OR IGNORE INTO intents(intent_id, challenge_hash, tenant_id,"
        " user_id, session_id, config_id, expected_version, new_value,"
        " summary_json, created_at, expires_at)"
        " VALUES ('probe_intent','probe_challenge','probe','probe','probe',"
        "'probe',1,'v','{}',0,0)")
    return _expect_abort(lambda: conn.execute(
        "UPDATE intents SET new_value = 'tampered' WHERE intent_id = 'probe_intent'"))


def _probe_audit_append_only(conn) -> bool:
    conn.execute("INSERT INTO audit_log(at, action) VALUES (0, 'probe')")
    return _expect_abort(lambda: conn.execute(
        "DELETE FROM audit_log WHERE action = 'probe'"))


def _probe_ticket_delete(conn) -> bool:
    conn.execute(
        "INSERT OR IGNORE INTO approvals(approval_id, intent_id, tenant_id,"
        " user_id, session_id, confirmed_at)"
        " VALUES ('probe_apr','probe_intent','probe','probe','probe',0)")
    conn.execute(
        "INSERT OR IGNORE INTO tickets(ticket_id, payload, intent_id,"
        " approval_id, tenant_id, user_id, session_id, state, issued_at,"
        " expires_at) VALUES ('probe_tkt','probe_payload','probe_intent',"
        "'probe_apr','probe','probe','probe','issued',0,0)")
    return _expect_abort(lambda: conn.execute(
        "DELETE FROM tickets WHERE ticket_id = 'probe_tkt'"))


def cmd_check(args) -> int:
    db_path = Path(args.db)
    problems: list[str] = []
    info: dict = {"database": str(db_path), "database_exists": db_path.exists()}
    if not db_path.exists():
        problems.append("database missing")
    else:
        ok, msg = db.database_integrity(str(db_path))
        info["integrity"] = msg
        if not ok:
            problems.append(msg)
        conn = db.connect(str(db_path))
        try:
            expected = {
                "schema_version": db.SCHEMA_VERSION,
            }
            meta = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM meta")}
            info["schema_version"] = meta.get("schema_version")
            if meta.get("schema_version") != expected["schema_version"]:
                problems.append("schema version mismatch")
            # Run the trigger-level guarantees, not just table existence.
            # Each probe writes throw-away rows and is rolled back.
            probes = [
                ("intent immutable", _probe_intent_immutable),
                ("audit append-only", _probe_audit_append_only),
                ("ticket not deletable", _probe_ticket_delete),
            ]
            for name, probe in probes:
                try:
                    conn.execute("SAVEPOINT chk")
                    fired = probe(conn)
                    conn.execute("ROLLBACK TO chk")
                    conn.execute("RELEASE chk")
                    if not fired:
                        problems.append(f"guard trigger missing: {name}")
                except sqlite3.DatabaseError:
                    try:
                        conn.execute("ROLLBACK TO chk")
                        conn.execute("RELEASE chk")
                    except sqlite3.Error:
                        pass
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            cfg_count = conn.execute("SELECT COUNT(*) FROM configs").fetchone()[0]
            info["users"] = user_count
            info["configs"] = cfg_count
            if user_count == 0:
                problems.append("no users provisioned")
            if cfg_count == 0:
                problems.append("no configs provisioned")
            orphan_tickets = conn.execute(
                "SELECT COUNT(*) FROM tickets t LEFT JOIN intents i"
                " ON i.intent_id = t.intent_id WHERE i.intent_id IS NULL"
            ).fetchone()[0]
            if orphan_tickets:
                problems.append(f"{orphan_tickets} ticket(s) without intent")
            pending = conn.execute(
                "SELECT COUNT(*) FROM tickets t LEFT JOIN executions e"
                " ON e.ticket_id = t.ticket_id WHERE t.state = 'used'"
                " AND e.ticket_id IS NULL").fetchone()[0]
            info["consumed_without_execution"] = pending
            info["consumed_without_execution_note"] = (
                "expected for tickets consumed by logout, disable or by"
                " a crashed uncommitted transaction; these must never execute")
            dup_intents = conn.execute(
                "SELECT COUNT(*) FROM (SELECT intent_id FROM approvals"
                " GROUP BY intent_id HAVING COUNT(*) > 1)").fetchone()[0]
            if dup_intents:
                problems.append(f"{dup_intents} intent(s) with multiple approvals")
            info["approvals"] = conn.execute(
                "SELECT COUNT(*) FROM approvals").fetchone()[0]
            info["executions"] = conn.execute(
                "SELECT COUNT(*) FROM executions").fetchone()[0]
        finally:
            conn.close()
    if args.key:
        key_path = Path(args.key)
        if not key_path.exists():
            problems.append("confirm key file missing")
        else:
            try:
                k = ConfirmKey.load(key_path)
                info["confirm_key_fingerprint"] = k.fingerprint
            except Exception as exc:
                problems.append(f"confirm key unreadable: {exc}")
    print(json.dumps({"ok": not problems, "problems": problems, **info}, indent=2))
    return 0 if not problems else 1


def cmd_code(args) -> int:
    """Derive the one-time confirmation code for a challenge.

    This is the *out-of-band* channel: an operator holding the locally
    provisioned key file (which is never served over HTTP) reads the pending
    action out of the database and computes the code.  It proves the code is
    bound to the exact stored intent, not to anything the caller supplies.
    """
    conn = db.connect(args.db)
    try:
        row = conn.execute(
            "SELECT * FROM intents WHERE challenge_hash = ?",
            (security.sha256_hex(args.challenge),)).fetchone()
        if row is None:
            print(json.dumps({"ok": False, "error": "unknown_challenge"}))
            return 1
    finally:
        conn.close()
    key = ConfirmKey.load(args.key)
    code = key.confirmation_code(
        row["tenant_id"], row["user_id"], args.challenge, row["expires_at"],
        "update_config", row["intent_id"],
        [("config_id", row["config_id"]),
         ("expected_version", str(row["expected_version"])),
         ("new_value", row["new_value"])])
    print(json.dumps({
        "ok": True, "challenge": args.challenge, "confirmation_code": code,
        "intent": {k: row[k] for k in ("intent_id", "tenant_id", "user_id",
                                       "session_id", "config_id",
                                       "expected_version", "new_value",
                                       "expires_at")},
        "confirm_key_fingerprint": key.fingerprint,
    }, indent=2))
    return 0


def cmd_show(args) -> int:
    conn = db.connect(args.db)
    try:
        rows = conn.execute(
            "SELECT tenant_id, config_id, version, value, updated_by, updated_at"
            " FROM configs ORDER BY tenant_id, config_id").fetchall()
        print(json.dumps({"ok": True,
                          "configs": [dict(r) for r in rows]}, indent=2))
    finally:
        conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sensitive_confirm",
        description="Local sensitive-operation second confirmation service")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="create DB, confirm key and seed data")
    p_init.add_argument("--db", default="data/confirm.db")
    p_init.add_argument("--key", default="data/confirm_key.json")
    p_init.add_argument("--force", action="store_true",
                        help="delete an existing DB and create a fresh key")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="verify DB, guards and seed data")
    p_check.add_argument("--db", default="data/confirm.db")
    p_check.add_argument("--key", default=None)
    p_check.set_defaults(func=cmd_check)

    p_code = sub.add_parser(
        "code", help="derive the out-of-band confirmation code for a challenge")
    p_code.add_argument("--db", default="data/confirm.db")
    p_code.add_argument("--key", default="data/confirm_key.json")
    p_code.add_argument("--challenge", required=True)
    p_code.set_defaults(func=cmd_code)

    p_show = sub.add_parser("show", help="print current config rows")
    p_show.add_argument("--db", default="data/confirm.db")
    p_show.set_defaults(func=cmd_show)

    p_serve = sub.add_parser("serve", help="run the HTTP service")
    p_serve.add_argument("--db", default="data/confirm.db")
    p_serve.add_argument("--key", default="data/confirm_key.json")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.set_defaults(func=None)

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        from .server import serve
        serve(args.db, args.key, args.host, args.port)
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
