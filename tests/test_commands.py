"""Command-line surface: init / check / code, plus the no-echo deployment.

In the no-echo configuration no HTTP response ever contains the code.  The
caller must obtain it out of band; here an operator with the local key file
uses ``python -m sensitive_confirm code``.  This proves the code is derived from
the *stored* intent, not from anything the request supplied.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from . import kit


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "sensitive_confirm", *args],
                          cwd=kit.ROOT, capture_output=True, text=True,
                          timeout=120)


class TestCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = kit.fresh_dir("commands")
        cls.db = str(cls.workdir / "confirm.db")
        cls.key = str(cls.workdir / "confirm_key.json")

    def test_init_check_code_and_out_of_band_verify(self):
        r = run_cli("init", "--db", self.db, "--key", self.key)
        self.assertEqual(r.returncode, 0, r.stderr)
        init_info = json.loads(r.stdout)
        self.assertTrue(init_info["ok"])
        self.assertEqual(len(init_info["configs"]), 4)
        r = run_cli("check", "--db", self.db, "--key", self.key)
        chk = json.loads(r.stdout)
        self.assertEqual(r.returncode, 0, chk)
        self.assertTrue(chk["ok"], chk)
        # The key file is not world readable where the OS supports chmod.
        if os.name != "nt":
            self.assertEqual(os.stat(self.key).st_mode & 0o777, 0o600)

        # Start WITHOUT SC_CODE_ECHO: no endpoint reveals the code.
        svc = kit.Service(self.db, self.key, name="noecho").start()
        try:
            cl = kit.Client(svc.port)
            self.assertTrue(cl.login("alice", "Alice-Passw0rd!").ok)
            v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
            prep = cl.prepare("svc-worker", v, "oob-value")
            self.assertTrue(prep.ok, prep)
            self.assertNotIn("confirmation_code", prep.body)
            # A guess is rejected and counted.
            bad = cl.verify(prep["challenge"], "00000000")
            self.assertEqual(bad.status, 403, bad)
            # Operator derives the code from the provisioned key + DB state.
            rc = run_cli("code", "--db", self.db, "--key", self.key,
                         "--challenge", prep["challenge"])
            self.assertEqual(rc.returncode, 0, rc.stderr)
            code = json.loads(rc.stdout)["confirmation_code"]
            if code == "00000000":  # astronomically unlikely; avoid flake
                self.skipTest("code happened to equal the guessed value")
            ok = cl.verify(prep["challenge"], code)
            self.assertTrue(ok.ok, ok)
            ex = cl.execute(ok["ticket"])
            self.assertTrue(ex.ok, ex)
            self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")
                             ["value"], "oob-value")
            self.assertNotIn("confirmation_code", ok.body)
        finally:
            svc.stop()

    def test_init_refuses_to_clobber_without_force(self):
        r = run_cli("init", "--db", self.db, "--key", self.key)
        self.assertEqual(r.returncode, 1)
        info = json.loads(r.stdout)
        self.assertEqual(info["error"], "database_exists")

    def test_brute_force_is_rate_limited(self):
        wd = kit.fresh_dir("bruteforce")
        db, key, _ = kit.init_db(wd)
        svc = kit.Service(db, key, name="bf").start()
        try:
            cl = kit.Client(svc.port)
            cl.login("alice", "Alice-Passw0rd!")
            v = kit.config_row(db, "tenant-alpha", "svc-worker")["version"]
            prep = cl.prepare("svc-worker", v, "brute")
            codes = [f"{i:08d}" for i in range(1, 12)]
            statuses = []
            for code in codes:
                r = cl.verify(prep["challenge"], code)
                statuses.append(r.status)
                if r.status == 429:
                    break
            self.assertIn(403, statuses)
            self.assertEqual(statuses[-1], 429, statuses)
            self.assertEqual(kit.scalar(db, "SELECT COUNT(*) FROM approvals"), 0)
        finally:
            svc.stop()


class TestDatabaseGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = kit.fresh_dir("guards")
        cls.db, cls.key, _ = kit.init_db(cls.workdir)

    def test_intent_and_approval_are_immutable(self):
        import sqlite3
        conn = kit.db_connect(self.db)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO intents(intent_id, challenge_hash, tenant_id,"
                " user_id, session_id, config_id, expected_version, new_value,"
                " summary_json, created_at, expires_at)"
                " VALUES ('i1','c1','t','u','s','cfg',1,'v','{}',0,0)")
            conn.execute("COMMIT")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE intents SET new_value = 'x' WHERE intent_id='i1'")
            conn.execute(
                "INSERT INTO approvals(approval_id, intent_id, tenant_id,"
                " user_id, session_id, confirmed_at)"
                " VALUES ('a1','i1','t','u','s',0)")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE approvals SET confirmed_at = 1")
            # Triggers fire per row, so the append-only check needs a row.
            conn.execute("INSERT INTO audit_log(at, action) VALUES (0,'probe')")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_log")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_log SET action='x'")
        finally:
            conn.close()

    def test_used_ticket_cannot_be_reissued(self):
        import sqlite3
        conn = kit.db_connect(self.db)
        try:
            conn.execute(
                "INSERT OR IGNORE INTO tickets(ticket_id, payload, intent_id,"
                " approval_id, tenant_id, user_id, session_id, state, issued_at,"
                " expires_at) VALUES ('tk1','p1','i1','a1','t','u','s','used',0,0)")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE tickets SET state = 'issued' WHERE ticket_id='tk1'")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM tickets WHERE ticket_id='tk1'")
            # Nor can its binding be re-pointed at another session or extended.
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE tickets SET session_id='other'"
                             " WHERE ticket_id='tk1'")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE tickets SET expires_at=expires_at+60000"
                             " WHERE ticket_id='tk1'")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
