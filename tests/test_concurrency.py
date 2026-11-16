"""Concurrency: 4+ service processes, same DB.

The proof is always two-part: the HTTP responses *and* the number of config
mutations / execution rows in SQLite.
"""

from __future__ import annotations

import threading
import time

from . import kit
from .test_functional import Base


class TestConcurrency(Base):
    PROCESSES = 4

    def setUp(self):
        self.workdir = kit.fresh_dir(f"conc_{self._testMethodName}")
        self.db, self.key, self.admin = kit.init_db(self.workdir)
        self.fleet = kit.Fleet(self.db, self.key, count=self.PROCESSES)
        for svc in self.fleet.services:
            svc.env["SC_CODE_ECHO"] = "1"
        self.fleet.start()
        self.c = self.fleet.client(0)

    def tearDown(self):
        self.fleet.stop()

    # ------------------------------------------------------------------
    def test_four_processes_same_ticket_only_one_update(self):
        sessions = [self.login() for _ in range(4)]
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(sessions[0], "svc-worker", v, "single-winner")
        ticket = self.approve(sessions[0], prep)["ticket"]
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")

        results: list = [None] * 4
        barrier = threading.Barrier(4)

        def worker(i):
            cl = sessions[0]  # same caller session, 4 *different* processes
            client = kit.Client(self.fleet.services[i].port)
            client.token = cl.token
            barrier.wait()
            results[i] = client.execute(ticket)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)

        applied = [r for r in results if r and r.ok and not r.body.get("idempotent_replay")]
        replays = [r for r in results if r and r.ok and r.body.get("idempotent_replay")]
        self.assertEqual(len(applied), 1, [r.body for r in results])
        self.assertGreaterEqual(len(replays), 0)
        for r in results:
            self.assertTrue(r is not None and r.ok, r)
        after = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self.assertEqual(after["version"], before["version"] + 1)
        self.assertEqual(after["value"], "single-winner")
        self.assertEqual(kit.scalar(
            self.db, "SELECT COUNT(*) FROM executions WHERE intent_id = ?",
            (prep["intent_id"],)), 1)
        versions = [r["result"]["version"] for r in applied + replays]
        self.assertEqual(set(versions), {before["version"] + 1})
        # Every response describes the one committed mutation.
        for r in applied + replays:
            self.assertEqual(r["result"]["previous_value"], before["value"])

    def test_two_intents_same_expected_version_only_one_wins(self):
        a = self.login("alice", "Alice-Passw0rd!", "tenant-alpha")
        b = self.login("bob", "Bob-Passw0rd!", "tenant-alpha")
        v = kit.config_row(self.db, "tenant-alpha", "svc-api")["version"]
        ta = self.approve(a, self.prepare_ok(a, "svc-api", v, "alice-value"))["ticket"]
        tb = self.approve(b, self.prepare_ok(b, "svc-api", v, "bob-value"))["ticket"]

        results: dict = {}
        barrier = threading.Barrier(2)

        def run(name, token, ticket, idx):
            cl = kit.Client(self.fleet.services[idx].port)
            cl.token = token
            barrier.wait()
            results[name] = cl.execute(ticket)

        t1 = threading.Thread(target=run, args=("a", a.token, ta, 0))
        t2 = threading.Thread(target=run, args=("b", b.token, tb, 1))
        t1.start(); t2.start(); t1.join(60); t2.join(60)

        winners = [k for k, r in results.items() if r.ok]
        losers = [k for k, r in results.items() if not r.ok]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(results[losers[0]]["error"], "version_conflict")
        final = kit.config_row(self.db, "tenant-alpha", "svc-api")
        expected_value = "alice-value" if winners[0] == "a" else "bob-value"
        self.assertEqual(final["value"], expected_value)
        self.assertEqual(kit.scalar(self.db,
                                    "SELECT COUNT(*) FROM executions"), 1)

    def test_parallel_independent_intents_serialise_versions(self):
        # 6 intents prepared at *different* expected versions must each be
        # rejected once the version moved; only the first can apply.
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        tickets = []
        for i in range(6):
            # prepare expects the *current* version at that moment
            cur = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
            prep = self.prepare_ok(cl, "svc-worker", cur, f"batch-{i}")
            tickets.append(self.approve(cl, prep)["ticket"])
            # force all intents to share the same expected version
        # Rewriting expected versions is impossible (intents are immutable);
        # they all captured the same version because nobody executed yet:
        versions = {kit.rows(self.db, "SELECT expected_version, COUNT(*) c"
                             " FROM intents WHERE config_id='svc-worker'"
                             " GROUP BY expected_version")[0]["expected_version"]}
        self.assertEqual(versions, {v})

        results: list = [None] * len(tickets)
        barrier = threading.Barrier(len(tickets))

        def run(i):
            client = kit.Client(self.fleet.services[i % self.PROCESSES].port)
            client.token = cl.token
            barrier.wait()
            results[i] = client.execute(tickets[i])

        threads = [threading.Thread(target=run, args=(i,)) for i in range(len(tickets))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        ok = [r for r in results if r.ok]
        conflict = [r for r in results if not r.ok]
        self.assertEqual(len(ok), 1, [r.body for r in results])
        self.assertEqual({r["error"] for r in conflict}, {"version_conflict"})
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 1)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"],
                         v + 1)

    def test_concurrent_verify_same_challenge_single_approval(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "one-approval")
        results: list = [None] * 8
        barrier = threading.Barrier(8)

        def run(i):
            client = kit.Client(self.fleet.services[i % self.PROCESSES].port)
            client.token = cl.token
            barrier.wait()
            results[i] = client.verify(prep["challenge"], prep["confirmation_code"])

        threads = [threading.Thread(target=run, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        ok = [r for r in results if r.ok]
        self.assertEqual(len(ok), 1, [r.body for r in results])
        self.assertEqual({r["error"] for r in results if not r.ok}, {"already_confirmed"})
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM approvals"), 1)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM tickets"), 1)

    def test_verify_and_execute_race_on_different_processes(self):
        # Many clients approve then execute at once for *different* configs;
        # every execution must land exactly once and versions must increase by 1.
        sessions = [self.login() for _ in range(8)]
        configs = ["svc-api", "svc-worker"]
        start_versions = {c: kit.config_row(self.db, "tenant-alpha", c)["version"]
                          for c in configs}
        # Prepare each against the *current* version and make them contend.
        pending = []
        for i, cl in enumerate(sessions):
            cfg = configs[i % 2]
            cur = kit.config_row(self.db, "tenant-alpha", cfg)["version"]
            pinnable = start_versions[cfg]  # same expected version for all
            prep = self.prepare_ok(cl, cfg, pinnable, f"contend-{i}")
            pending.append((i, cl, cfg, self.approve(cl, prep)["ticket"]))
        results: list = [None] * len(pending)
        barrier = threading.Barrier(len(pending))

        def run(i, cl, ticket):
            client = kit.Client(self.fleet.services[i % self.PROCESSES].port)
            client.token = cl.token
            barrier.wait()
            results[i] = client.execute(ticket)

        threads = [threading.Thread(target=run, args=(i, cl, t))
                   for i, cl, _, t in pending]
        for t in threads:
            t.start()
        for t in threads:
            t.join(90)
        for r in results:
            self.assertIsNotNone(r, "a worker produced no response")
        ok = [r for r in results if r.ok]
        self.assertEqual(len(ok), len(configs))  # exactly one per config
        for cfg in configs:
            final = kit.config_row(self.db, "tenant-alpha", cfg)
            self.assertEqual(final["version"], start_versions[cfg] + 1)
        self.assertEqual(kit.scalar(self.db,
                                    "SELECT COUNT(*) FROM executions"), len(configs))
        self.assertEqual(
            kit.scalar(self.db, "SELECT COUNT(*) FROM executions e JOIN tickets t"
                       " ON t.ticket_id = e.ticket_id WHERE t.state <> 'used'"), 0)


class TestLogoutDisableRace(Base):
    def setUp(self):
        self.workdir = kit.fresh_dir(f"race_{self._testMethodName}")
        self.db, self.key, self.admin = kit.init_db(self.workdir)
        self.fleet = kit.Fleet(self.db, self.key, count=2)
        for svc in self.fleet.services:
            svc.env["SC_CODE_ECHO"] = "1"
        self.fleet.start()
        self.c = self.fleet.client(0)

    def tearDown(self):
        self.fleet.stop()

    def _pause_service(self, env: dict) -> kit.Service:
        svc = kit.Service(self.db, self.key, name="svc-paused", env=env)
        svc.start()
        return svc

    def test_logout_commits_before_execution_writes(self):
        """A verified execution is paused before BEGIN; logout commits first;
        the execution must not apply."""
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "revoked-before-write")
        ticket = self.approve(cl, prep)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")

        paused = self._pause_service({
            "SC_CODE_ECHO": "1",
            "SC_CRASHPOINT": "before_begin",
            "SC_CRASHPOINT_MODE": "pause",
        })
        try:
            holder: dict = {}

            def run():
                client = kit.Client(paused.port)
                client.token = cl.token
                holder["resp"] = client.execute(ticket["ticket"])

            th = threading.Thread(target=run)
            th.start()
            line = paused.wait_line('"crashpoint"', timeout=30)
            self.assertIn("before_begin", line)
            # Execution is parked before BEGIN; logout on another process now
            # commits revocation + ticket invalidation.
            other = kit.Client(self.fleet.services[0].port)
            other.token = cl.token
            r = other.post("/v1/logout")
            self.assertTrue(r.ok, r)
            paused.release()
            th.join(60)
            resp = holder["resp"]
            self.assertFalse(resp.ok, resp)
            self.assertIn(resp["error"], {"session_revoked", "ticket_invalidated"})
        finally:
            paused.stop()

        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 0)
        st = kit.rows(self.db, "SELECT state FROM tickets WHERE ticket_id = ?",
                      (ticket["ticket_id"],))[0]
        self.assertEqual(st["state"], "used")
        # Replay is refused too: the session is dead.
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 401, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)

    def test_disable_commits_before_execution_writes(self):
        cl = self.login("bob", "Bob-Passw0rd!", "tenant-alpha")
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "disabled-before-write")
        ticket = self.approve(cl, prep)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")

        # Park *before* the execution transaction takes the write lock, so the
        # disable can commit first -- the ordering the requirement is about.
        paused = self._pause_service({
            "SC_CRASHPOINT": "before_begin",
            "SC_CRASHPOINT_MODE": "pause",
        })
        try:
            holder: dict = {}
            th = threading.Thread(target=lambda: holder.update(
                resp=kit.Client(paused.port).request(
                    "POST", "/v1/execute", {"ticket": ticket["ticket"]},
                    token=cl.token)))
            th.start()
            line = paused.wait_line('"crashpoint"', timeout=30)
            self.assertIn("before_begin", line)
            r = kit.Client(self.fleet.services[0].port).post(
                "/admin/disable-user",
                {"tenant_id": "tenant-alpha", "login_name": "bob", "disabled": True},
                token=None, headers={"X-Admin-Key": self.admin})
            self.assertTrue(r.ok, r)
            paused.release()
            th.join(60)
            resp = holder["resp"]
            self.assertFalse(resp.ok, resp)
            self.assertIn(resp["error"], {"account_disabled", "session_revoked",
                                          "ticket_invalidated"})
        finally:
            paused.stop()
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 0)

    def test_execution_commits_before_logout_then_logout_wins_retry(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "committed-then-logout")
        ticket = self.approve(cl, prep)
        r = cl.execute(ticket["ticket"])
        self.assertTrue(r.ok, r)
        after = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self.assertTrue(cl.post("/v1/logout").ok)
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 401, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), after)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 1)

    def test_logout_alone_invalidates_pending_ticket(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "never-runs")
        ticket = self.approve(cl, prep)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self.assertTrue(cl.post("/v1/logout").ok)
        # Even re-logging in as the same user does not resurrect the ticket.
        cl2 = self.login()
        r = cl2.execute(ticket["ticket"])
        self.assertEqual(r.status, 401, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)

    def test_session_rotation_invalidates_ticket(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "rotated-away")
        ticket = self.approve(cl, prep)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        r = cl.post("/v1/session/rotate")
        self.assertTrue(r.ok, r)
        old_token = cl.token
        cl.token = r["session_token"]
        # The ticket belongs to the old session: use of the old token fails...
        r_old = cl.execute(ticket["ticket"], token=old_token)
        self.assertEqual(r_old.status, 401, r_old)
        # ...and the new session cannot adopt the ticket: the originating
        # session is rotated, so the ticket is dead (401), not merely refused.
        r_new = cl.execute(ticket["ticket"])
        self.assertEqual(r_new.status, 401, r_new)
        self.assertEqual(r_new["error"], "session_rotated")
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 0)


if __name__ == "__main__":
    import unittest
    unittest.main()


class TestExecutionHoldsLock(Base):
    """The other ordering: the execution already holds the write lock when the
    logout arrives.  Logout must wait, and the execution's commit stands."""

    def setUp(self):
        self.workdir = kit.fresh_dir(f"lock_{self._testMethodName}")
        self.db, self.key, self.admin = kit.init_db(self.workdir)
        self.svc = kit.Service(self.db, self.key, name="svc",
                               env={"SC_CODE_ECHO": "1"}).start()
        self.fleet = kit.Fleet.__new__(kit.Fleet)
        self.fleet.services = [self.svc]
        self.fleet.count = 1
        self.c = kit.Client(self.svc.port)

    def tearDown(self):
        self.svc.stop()

    def test_logout_waits_for_inflight_execution(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "inflight")
        ticket = self.approve(cl, prep)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")

        paused = kit.Service(self.db, self.key, name="svc-paused", env={
            "SC_CRASHPOINT": "ticket_marked_used",
            "SC_CRASHPOINT_MODE": "pause"}).start()
        try:
            holder: dict = {}

            def run_exec():
                c = kit.Client(paused.port)
                c.token = cl.token
                holder["exec"] = c.execute(ticket["ticket"])

            def run_logout():
                c = kit.Client(self.svc.port)
                c.token = cl.token
                holder["logout"] = c.post("/v1/logout")

            th_exec = threading.Thread(target=run_exec)
            th_exec.start()
            paused.wait_line('"crashpoint"', timeout=30)
            th_logout = threading.Thread(target=run_logout)
            th_logout.start()
            # The logout must be blocked while the execution transaction holds
            # the write lock; it cannot sneak in between ticket claim and commit.
            time.sleep(1.0)
            self.assertTrue(th_logout.is_alive(), "logout raced past the writer")
            paused.release()
            th_exec.join(60)
            th_logout.join(60)
        finally:
            paused.stop()

        # Execution committed first: config changed exactly once; then the
        # logout revoked the session.  The retry afterwards must be refused.
        after = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self.assertEqual(after["version"], before["version"] + 1)
        self.assertEqual(after["value"], "inflight")
        self.assertTrue(holder["exec"].ok, holder["exec"])
        self.assertTrue(holder["logout"].ok, holder["logout"])
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 1)
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 401, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), after)

    def test_disable_after_verify_blocks_execute(self):
        cl = self.login("bob", "Bob-Passw0rd!", "tenant-alpha")
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "disabled-after-verify")
        ticket = self.approve(cl, prep)
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        r = kit.Client(self.svc.port).post(
            "/admin/disable-user",
            {"tenant_id": "tenant-alpha", "login_name": "bob", "disabled": True},
            headers={"X-Admin-Key": self.admin})
        self.assertTrue(r.ok, r)
        # Both signals are correct and both are fail-closed: the disable
        # revoked the session and burned the ticket.  Either code is acceptable;
        # what matters is the refusal and the untouched config.
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 401, r)
        self.assertIn(r["error"], {"session_revoked", "account_disabled",
                                   "ticket_invalidated"})
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 0)
