"""Fault injection: a real service process is killed at chosen points.

Each crash point is a *separate process* started by this test; the kill is
``os._exit(9)`` inside the SQLite transaction (or right after COMMIT), so no
Python cleanup runs.  After the kill the database is reopened by a fresh
process and the client retries with the same ticket.  We then prove from
SQLite that:

* the config was updated exactly once, with the *confirmed* value,
* there is exactly one execution row,
* no ticket was left in a half-consumed state that could double-apply.
"""

from __future__ import annotations

import json
import unittest

from . import kit


class CrashTestBase(unittest.TestCase):
    def setUp(self):
        self.workdir = kit.fresh_dir(f"crash_{self._testMethodName}")
        self.db, self.key, self.admin = kit.init_db(self.workdir)
        self._running: list[kit.Service] = []

    def tearDown(self):
        for svc in self._running:
            svc.stop()

    def _svc(self, name="svc", **env) -> kit.Service:
        e = {"SC_CODE_ECHO": "1"}
        e.update(env)
        svc = kit.Service(self.db, self.key, name=name, env=e).start()
        self._running.append(svc)
        return svc

    def _setup_ticket(self, config_id="svc-worker", value="crashed-value",
                      user=("alice", "Alice-Passw0rd!", "tenant-alpha")):
        svc = self._svc()
        cl = kit.Client(svc.port)
        self.assertTrue(cl.login(*user).ok)
        v = kit.config_row(self.db, "tenant-alpha", config_id)["version"]
        prep = cl.prepare(config_id, v, value)
        self.assertTrue(prep.ok, prep)
        t = cl.verify(prep["challenge"], prep["confirmation_code"])
        self.assertTrue(t.ok, t)
        return svc, cl, prep.body, t.body

    def _execute_expect_kill(self, svc: kit.Service, token: str,
                             ticket: str) -> None:
        cl = kit.Client(svc.port)
        cl.token = token
        try:
            cl.execute(ticket)
        except (ConnectionError, OSError, kit.http.client.HTTPException):
            # Connection reset is the expected shape; the exit code below is
            # what proves the process really died at the crash point.
            pass
        code = svc.wait_exit(timeout=30)
        self.assertNotEqual(code, 0, "service was expected to die at the crash point")
        svc.stop()

    def _assert_applied_once(self, config_id, expected_value, expected_prev,
                             intent_id, previous_version):
        final = kit.config_row(self.db, "tenant-alpha", config_id)
        self.assertEqual(final["value"], expected_value)
        self.assertEqual(final["version"], previous_version + 1)
        n = kit.scalar(self.db, "SELECT COUNT(*) FROM executions WHERE intent_id = ?",
                       (intent_id,))
        self.assertEqual(n, 1)
        applied = kit.rows(self.db, "SELECT result_json FROM executions"
                           " WHERE intent_id = ?", (intent_id,))
        result = json.loads(applied[0]["result_json"])
        self.assertEqual(result["value"], expected_value)
        self.assertEqual(result["previous_value"], expected_prev)
        self.assertEqual(result["version"], previous_version + 1)
        audit = kit.scalar(self.db, "SELECT COUNT(*) FROM audit_log"
                           " WHERE action = 'execute_applied' AND intent_id = ?",
                           (intent_id,))
        self.assertEqual(audit, 1)
        # A single config mutation happened: version moved by exactly 1.
        self.assertEqual(final["version"], previous_version + 1)

    def _assert_untouched(self, config_id, snapshot, intent_id):
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", config_id),
                         snapshot)
        n = kit.scalar(self.db, "SELECT COUNT(*) FROM executions WHERE intent_id = ?",
                       (intent_id,))
        self.assertEqual(n, 0)

    def _retry_and_assert_replay(self, ticket, token, intent_id, config_id,
                                 expected_value, prev_version):
        svc = self._svc(name="restart")
        try:
            cl = kit.Client(svc.port)
            cl.token = token
            r = cl.execute(ticket)
            self.assertTrue(r.ok, r)
            if r.body.get("idempotent_replay"):
                self.assertTrue(r["result"]["value"], expected_value)
            self._assert_applied_once(config_id, expected_value,
                                      r["result"]["previous_value"],
                                      intent_id, prev_version)
            # A second retry is still idempotent.
            r2 = cl.execute(ticket)
            self.assertTrue(r2.ok, r2)
            self.assertTrue(r2["idempotent_replay"])
            return r
        finally:
            svc.stop()


class TestCrashPoints(CrashTestBase):
    def test_crash_after_ticket_marked_used_before_config_update(self):
        svc, cl, prep, ticket = self._setup_ticket(value="after-claim")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        crash = self._svc(name="crasher", SC_CRASHPOINT="ticket_marked_used")
        self._execute_expect_kill(crash, cl.token, ticket["ticket"])
        # Transaction rolled back by SQLite: nothing visible changed.
        self._assert_untouched("svc-worker", before, prep["intent_id"])
        self.assertEqual(
            kit.rows(self.db, "SELECT state FROM tickets WHERE ticket_id = ?",
                     (ticket["ticket_id"],))[0]["state"], "issued")
        # Restart and retry the same ticket: exactly one application.
        r = self._retry_and_assert_replay(ticket["ticket"], cl.token,
                                          prep["intent_id"], "svc-worker",
                                          "after-claim", before["version"])
        self.assertFalse(r.body.get("idempotent_replay"))

    def test_crash_after_config_updated_before_commit(self):
        svc, cl, prep, ticket = self._setup_ticket(value="after-update")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        crash = self._svc(name="crasher", SC_CRASHPOINT="config_updated")
        self._execute_expect_kill(crash, cl.token, ticket["ticket"])
        self._assert_untouched("svc-worker", before, prep["intent_id"])
        self.assertEqual(
            kit.rows(self.db, "SELECT state FROM tickets WHERE ticket_id = ?",
                     (ticket["ticket_id"],))[0]["state"], "issued")
        r = self._retry_and_assert_replay(ticket["ticket"], cl.token,
                                          prep["intent_id"], "svc-worker",
                                          "after-update", before["version"])
        self.assertFalse(r.body.get("idempotent_replay"))

    def test_crash_after_commit_before_response(self):
        svc, cl, prep, ticket = self._setup_ticket(value="after-commit")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        crash = self._svc(name="crasher", SC_CRASHPOINT="after_commit")
        self._execute_expect_kill(crash, cl.token, ticket["ticket"])
        # The COMMIT did happen before the kill.
        self._assert_applied_once("svc-worker", "after-commit", before["value"],
                                 prep["intent_id"], before["version"])
        r = self._retry_and_assert_replay(ticket["ticket"], cl.token,
                                          prep["intent_id"], "svc-worker",
                                          "after-commit", before["version"])
        self.assertTrue(r.body.get("idempotent_replay"))
        self.assertEqual(r["result"]["value"], "after-commit")

    def test_crash_before_ticket_claim_writes_nothing(self):
        svc, cl, prep, ticket = self._setup_ticket(value="before-claim")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        crash = self._svc(name="crasher", SC_CRASHPOINT="before_claim")
        self._execute_expect_kill(crash, cl.token, ticket["ticket"])
        self._assert_untouched("svc-worker", before, prep["intent_id"])
        r = self._retry_and_assert_replay(ticket["ticket"], cl.token,
                                          prep["intent_id"], "svc-worker",
                                          "before-claim", before["version"])
        self.assertFalse(r.body.get("idempotent_replay"))

    def test_crash_after_logout_commit_before_response(self):
        # Logout committed (session revoked, tickets burned) but the response
        # never reached the client.  Retrying the execution must fail closed.
        svc, cl, prep, ticket = self._setup_ticket(value="never-applied")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        crash = self._svc(name="crasher", SC_CRASHPOINT="after_session_revoke")
        try:
            kit.Client(crash.port).post("/v1/logout", token=cl.token)
        except (ConnectionError, OSError):
            pass
        code = crash.wait_exit(timeout=30)
        self.assertNotEqual(code, 0)
        crash.stop()
        self._assert_untouched("svc-worker", before, prep["intent_id"])
        st = kit.rows(self.db, "SELECT state FROM tickets WHERE ticket_id = ?",
                      (ticket["ticket_id"],))[0]["state"]
        self.assertEqual(st, "used")
        restarted = self._svc(name="restart")
        try:
            cl2 = kit.Client(restarted.port)
            cl2.token = cl.token
            r = cl2.execute(ticket["ticket"])
            self.assertEqual(r.status, 401, r)
            self.assertEqual(r["error"], "session_revoked")
        finally:
            restarted.stop()
        self._assert_untouched("svc-worker", before, prep["intent_id"])

    def test_crash_twice_same_ticket_committed_then_retried(self):
        """Crash at after_commit, then crash the retry at 'before_claim', then
        retry again: still exactly one update."""
        svc, cl, prep, ticket = self._setup_ticket(value="double-crash")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        c1 = self._svc(name="crasher1", SC_CRASHPOINT="after_commit")
        self._execute_expect_kill(c1, cl.token, ticket["ticket"])
        self._assert_applied_once("svc-worker", "double-crash", before["value"],
                                 prep["intent_id"], before["version"])
        c2 = self._svc(name="crasher2", SC_CRASHPOINT="before_claim")
        self._execute_expect_kill(c2, cl.token, ticket["ticket"])
        r = self._retry_and_assert_replay(ticket["ticket"], cl.token,
                                          prep["intent_id"], "svc-worker",
                                          "double-crash", before["version"])
        self.assertTrue(r.body.get("idempotent_replay"))
        final = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self.assertEqual(final["version"], before["version"] + 1)


class TestCrashIntegrity(CrashTestBase):
    def test_check_command_after_all_crashes(self):
        import subprocess
        import sys
        # Seed some crashed executions first.
        for point in ("ticket_marked_used", "config_updated", "after_commit"):
            svc, cl, prep, ticket = self._setup_ticket(
                value=f"integrity-{point}")
            crash = self._svc(name=f"c-{point}", SC_CRASHPOINT=point)
            try:
                self._execute_expect_kill(crash, cl.token, ticket["ticket"])
            finally:
                # always let the retry commit, so the DB ends fully consistent
                s2 = self._svc(name=f"r-{point}")
                try:
                    kit.Client(s2.port).request(
                        "POST", "/v1/execute", {"ticket": ticket["ticket"]},
                        token=cl.token)
                finally:
                    s2.stop()
        proc = subprocess.run(
            [sys.executable, "-m", "sensitive_confirm", "check",
             "--db", self.db, "--key", self.key],
            cwd=kit.ROOT, capture_output=True, text=True, timeout=60)
        info = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, info)
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["integrity"], "ok")
        self.assertEqual(info["executions"], 3)
        # No intent has more than one execution + exactly one approval.
        self.assertEqual(kit.scalar(
            self.db, "SELECT COUNT(*) FROM (SELECT intent_id FROM executions"
            " GROUP BY intent_id HAVING COUNT(*) > 1)"), 0)
        self.assertEqual(kit.scalar(
            self.db, "SELECT COUNT(*) FROM (SELECT intent_id FROM approvals"
            " GROUP BY intent_id HAVING COUNT(*) > 1)"), 0)


if __name__ == "__main__":
    unittest.main()


class TestCrashWithFourProcesses(CrashTestBase):
    """A paused process is killed from the outside while it holds an open
    transaction; the other (still healthy) 4-process fleet then retries the
    same ticket concurrently.  Proves the DB, not a single process, is truth."""

    def _start_fleet(self, n=4):
        return [self._svc(name=f"fleet{i}") for i in range(n)]

    def _kill_paused_inside_tx(self, crashpoint: str, token: str,
                               ticket: str) -> None:
        import threading
        paused = self._svc(name="paused", SC_CRASHPOINT=crashpoint,
                           SC_CRASHPOINT_MODE="pause")
        holder: dict = {}

        def run():
            try:
                holder["resp"] = kit.Client(paused.port).request(
                    "POST", "/v1/execute", {"ticket": ticket}, token=token,
                    timeout=120)
            except Exception as exc:  # connection dies with the process
                holder["error"] = exc

        th = threading.Thread(target=run)
        th.start()
        paused.wait_line('"crashpoint"', timeout=30)
        # Hard kill from outside: no Python cleanup, transaction still open.
        paused.proc.kill()
        code = paused.wait_exit(timeout=30)
        th.join(60)
        self.assertNotEqual(code, 0)
        self.assertNotIn("resp", holder, holder)

    def test_hard_kill_while_ticket_used_then_fleet_retries(self):
        import threading

        fleet = self._start_fleet()
        cl = kit.Client(fleet[0].port)
        self.assertTrue(cl.login("alice", "Alice-Passw0rd!").ok)
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = cl.prepare("svc-worker", v, "hard-kill-claim")
        self.assertTrue(prep.ok, prep)
        tv = cl.verify(prep["challenge"], prep["confirmation_code"])
        self.assertTrue(tv.ok, tv)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self._kill_paused_inside_tx("ticket_marked_used", cl.token,
                                    tv["ticket"])
        # Nothing was committed.
        self._assert_untouched("svc-worker", before, prep.body["intent_id"])
        self.assertEqual(kit.rows(
            self.db, "SELECT state FROM tickets WHERE ticket_id = ?",
            (tv["ticket_id"],))[0]["state"], "issued")

        results = [None] * 4
        barrier = threading.Barrier(4)

        def worker(i):
            client = kit.Client(fleet[i].port)
            client.token = cl.token
            barrier.wait()
            results[i] = client.execute(tv["ticket"])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(90)
        applied = [r for r in results if r.ok and not r.body.get("idempotent_replay")]
        self.assertEqual(len(applied), 1, [r.body for r in results])
        for r in results:
            self.assertTrue(r is not None and r.ok, r)
        self._assert_applied_once("svc-worker", "hard-kill-claim",
                                  before["value"], prep.body["intent_id"],
                                  before["version"])

    def test_hard_kill_after_config_update_then_fleet_retries(self):
        import threading
        fleet = self._start_fleet()
        cl = kit.Client(fleet[0].port)
        self.assertTrue(cl.login("alice", "Alice-Passw0rd!").ok)
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = cl.prepare("svc-worker", v, "hard-kill-update")
        self.assertTrue(prep.ok, prep)
        tv = cl.verify(prep["challenge"], prep["confirmation_code"])
        self.assertTrue(tv.ok, tv)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self._kill_paused_inside_tx("config_updated", cl.token, tv["ticket"])
        self._assert_untouched("svc-worker", before, prep.body["intent_id"])

        results = [None] * 4
        barrier = threading.Barrier(4)

        def worker(i):
            client = kit.Client(fleet[i].port)
            client.token = cl.token
            barrier.wait()
            results[i] = client.execute(tv["ticket"])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(90)
        for r in results:
            self.assertTrue(r is not None and r.ok, r)
        self._assert_applied_once("svc-worker", "hard-kill-update",
                                  before["value"], prep.body["intent_id"],
                                  before["version"])
