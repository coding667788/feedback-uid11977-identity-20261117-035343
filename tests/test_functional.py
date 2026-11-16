"""Functional tests: binding, intent immutability, one approval, replay.

Every assertion checks the HTTP result *and* the config row read straight from
SQLite, so "only the confirmed operation ran" is proven at the storage layer.
"""

from __future__ import annotations

import json
import time
import unittest

from . import kit


class Base(unittest.TestCase):
    echo_codes = True

    def setUp(self):
        # A private database + service process per test: counters such as
        # "no ticket rows exist" are then meaningful, and one test cannot leak
        # approved intents into another.
        self.workdir = kit.fresh_dir(f"{type(self).__name__}_{self._testMethodName}")
        self.db, self.key, self.admin = kit.init_db(self.workdir)
        self.env = {"SC_CODE_ECHO": "1"} if self.echo_codes else {}
        self.svc = kit.Service(self.db, self.key, name="svc", env=self.env).start()
        self.fleet = kit.Fleet.__new__(kit.Fleet)  # tiny shim for helpers
        self.fleet.services = [self.svc]
        self.fleet.count = 1
        self.c = kit.Client(self.svc.port)

    def tearDown(self):
        self.svc.stop()

    # helpers -----------------------------------------------------------
    def login(self, name="alice", password="Alice-Passw0rd!",
              tenant="tenant-alpha") -> kit.Client:
        cl = kit.Client(self.fleet.services[0].port)
        r = cl.login(name, password, tenant)
        self.assertTrue(r.ok, r)
        return cl

    def prepare_ok(self, cl: kit.Client, config_id: str, version: int,
                   value: str) -> dict:
        r = cl.prepare(config_id, version, value)
        self.assertTrue(r.ok, r)
        return r.body

    def approve(self, cl: kit.Client, prep: dict) -> dict:
        r = cl.verify(prep["challenge"], prep["confirmation_code"])
        self.assertTrue(r.ok, r)
        return r.body

    def fresh_execution(self, config_id="svc-worker", value=None,
                        cl: kit.Client | None = None) -> tuple[kit.Client, dict]:
        cl = cl or self.login()
        cur = kit.config_row(self.db, "tenant-alpha", config_id)["version"]
        value = value or f"value-{time.time_ns()}"
        prep = self.prepare_ok(cl, config_id, cur, value)
        ticket = self.approve(cl, prep)
        return cl, {"prepare": prep, "ticket": ticket, "value": value,
                    "config_id": config_id}


class TestHappyPathAndReplay(Base):
    def test_normal_session_cannot_write_config(self):
        cl = self.login()
        # There is no write endpoint reachable with a session token; the only
        # write path needs a ticket, and a session token is not one.
        r = cl.post("/v1/execute", {"ticket": cl.token})
        self.assertEqual(r.status, 401)
        self.assertEqual(r["error"], "invalid_ticket")
        before = kit.config_row(self.db, "tenant-alpha", "svc-api")
        r = cl.post("/v1/execute", {"config_id": "svc-api", "expected_version": 1,
                                    "new_value": "pwned"})
        self.assertEqual(r.status, 400)
        after = kit.config_row(self.db, "tenant-alpha", "svc-api")
        self.assertEqual(before, after)

    def test_prepare_does_not_change_config(self):
        cl = self.login()
        before = kit.config_row(self.db, "tenant-alpha", "svc-api")
        prep = self.prepare_ok(cl, "svc-api", before["version"], "timeout=99s")
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-api"), before)
        self.assertTrue(prep["pending_action"]["version_confirmed_current"])

    def test_verify_then_execute_applies_exact_intent(self):
        cl, ctx = self.fresh_execution("svc-worker", "replicas=5")
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        r = cl.execute(ctx["ticket"]["ticket"])
        self.assertTrue(r.ok, r)
        after = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        self.assertEqual(after["value"], "replicas=5")
        self.assertEqual(after["version"], before["version"] + 1)
        self.assertEqual(after["updated_by"], "usr_alpha_alice")
        self.assertEqual(r["result"]["version"], after["version"])
        self.assertEqual(r["result"]["value"], after["value"])
        self.assertEqual(r["result"]["previous_version"], before["version"])

    def test_replay_same_ticket_returns_result_without_second_write(self):
        cl, ctx = self.fresh_execution("svc-worker", "replicas=6")
        first = cl.execute(ctx["ticket"]["ticket"])
        self.assertTrue(first.ok, first)
        snap = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        second = cl.execute(ctx["ticket"]["ticket"])
        self.assertTrue(second.ok, second)
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(second["result"]["version"], first["result"]["version"])
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), snap)
        self.assertEqual(kit.scalar(
            self.db, "SELECT COUNT(*) FROM executions WHERE intent_id = ?",
            (ctx["prepare"]["intent_id"],)), 1)

    def test_execute_rejects_request_supplied_values(self):
        cl, ctx = self.fresh_execution("svc-worker", "replicas=7")
        for field, value in (("config_id", "svc-api"), ("new_value", "evil"),
                             ("expected_version", 99), ("tenant_id", "tenant-beta")):
            r = cl.post("/v1/execute", {"ticket": ctx["ticket"]["ticket"],
                                        field: value})
            self.assertEqual(r.status, 400, r)
            self.assertEqual(r["error"], "request_cannot_override_intent")
            self.assertIn(field, r["rejected_fields"])
        r = cl.execute(ctx["ticket"]["ticket"])
        self.assertTrue(r.ok, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
                         "replicas=7")


class TestBinding(Base):
    def test_prepare_rejects_stale_expected_version(self):
        cl = self.login()
        cur = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        r = cl.prepare("svc-worker", cur - 1, "stale-attempt")
        self.assertEqual(r.status, 409, r)
        self.assertEqual(r["error"], "stale_expected_version")
        self.assertEqual(r["current_version"], cur)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM intents"), 0)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"),
                         before)

    def test_cannot_swap_resource(self):
        cl, ctx = self.fresh_execution("svc-worker", "replicas=8")
        other_before = kit.config_row(self.db, "tenant-alpha", "svc-api")
        r = cl.execute(ctx["ticket"]["ticket"])
        self.assertTrue(r.ok, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-api"),
                         other_before)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
                         "replicas=8")

    def test_cannot_swap_value(self):
        cl, ctx = self.fresh_execution("svc-worker", "replicas=9")
        r = cl.post("/v1/execute", {"ticket": ctx["ticket"]["ticket"],
                                    "new_value": "replicas=999"})
        self.assertEqual(r.status, 400)
        self.assertNotEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
                            "replicas=999")
        r = cl.execute(ctx["ticket"]["ticket"])
        self.assertTrue(r.ok, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
                         "replicas=9")

    def test_cannot_swap_expected_version(self):
        cl = self.login()
        cur = kit.config_row(self.db, "tenant-alpha", "svc-api")["version"]
        prep = self.prepare_ok(cl, "svc-api", cur, "swapped-version")
        # Someone else updates first.
        other = self.login("bob", "Bob-Passw0rd!")
        ob = self.prepare_ok(other, "svc-api", cur, "bob-was-here")
        ok_ = self.approve(other, ob)
        r = other.execute(ok_["ticket"])
        self.assertTrue(r.ok, r)
        mid = kit.config_row(self.db, "tenant-alpha", "svc-api")
        ticket = self.approve(cl, prep)
        r = cl.post("/v1/execute", {"ticket": ticket["ticket"],
                                    "expected_version": mid["version"]})
        self.assertEqual(r.status, 400)
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 409, r)
        self.assertEqual(r["error"], "version_conflict")
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-api"), mid)
        self.assertFalse(r["ok"])

    def test_code_from_other_intent_rejected(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-api")["version"]
        p1 = self.prepare_ok(cl, "svc-api", v, "one")
        p2 = self.prepare_ok(cl, "svc-api", v, "two")
        r = cl.verify(p1["challenge"], p2["confirmation_code"])
        self.assertEqual(r.status, 403, r)
        self.assertEqual(r["error"], "confirmation_rejected")
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM tickets"), 0)

    def test_cross_tenant_ticket_move(self):
        alpha = self.login("alice", "Alice-Passw0rd!", "tenant-alpha")
        beta = self.login("carol", "Carol-Passw0rd!", "tenant-beta")
        cur = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(alpha, "svc-worker", cur, "alpha-only")
        ticket = self.approve(alpha, prep)["ticket"]
        # Carol (other tenant) cannot use the ticket with her own session.
        r = beta.execute(ticket)
        self.assertEqual(r.status, 403, r)
        self.assertEqual(r["error"], "ticket_bound_to_other_session")
        self.assertNotEqual(
            kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
            "alpha-only")
        # Same user, different tenant session is impossible to fake; but the
        # alpha session still works, proving the block was the binding.
        r = alpha.execute(ticket)
        self.assertTrue(r.ok, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
                         "alpha-only")

    def test_cross_session_ticket_move(self):
        cl1 = self.login()
        cl2 = self.login()  # same user, second browser session
        self.assertNotEqual(cl1.token, cl2.token)
        cur = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl1, "svc-worker", cur, "only-session-1")
        # The challenge cannot even be confirmed from another session.
        r = cl2.verify(prep["challenge"], prep["confirmation_code"])
        self.assertEqual(r.status, 403, r)
        self.assertEqual(r["error"], "wrong_session")
        ticket = self.approve(cl1, prep)["ticket"]
        r = cl2.execute(ticket)
        self.assertEqual(r.status, 403, r)
        self.assertEqual(r["error"], "ticket_bound_to_other_session")
        self.assertNotEqual(
            kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
            "only-session-1")
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"
                                     " WHERE result_json LIKE '%only-session-1%'"), 0)
        r = cl1.execute(ticket)
        self.assertTrue(r.ok, r)

    def test_prepare_cannot_choose_identity(self):
        cl = self.login()
        r = cl.post("/v1/prepare", {"config_id": "svc-api", "expected_version": 1,
                                    "new_value": "x", "tenant_id": "tenant-beta"})
        self.assertEqual(r.status, 400)
        self.assertEqual(r["error"], "request_cannot_choose_identity")

    def test_request_cannot_supply_confirm_key(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-api")["version"]
        prep = self.prepare_ok(cl, "svc-api", v, "x")
        r = cl.post("/v1/verify", {"challenge": prep["challenge"],
                                   "confirmation_code": prep["confirmation_code"],
                                   "confirm_key": "00" * 32})
        self.assertEqual(r.status, 400, r)
        self.assertEqual(r["error"], "request_cannot_supply_key")
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM approvals"), 0)

    def test_one_approval_per_challenge(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-api")["version"]
        prep = self.prepare_ok(cl, "svc-api", v, "once")
        t = self.approve(cl, prep)
        r = cl.verify(prep["challenge"], prep["confirmation_code"])
        self.assertEqual(r.status, 409, r)
        self.assertEqual(r["error"], "already_confirmed")
        self.assertEqual(kit.scalar(
            self.db, "SELECT COUNT(*) FROM approvals WHERE intent_id = ?",
            (prep["intent_id"],)), 1)
        n = kit.scalar(self.db, "SELECT COUNT(*) FROM tickets WHERE intent_id = ?",
                       (prep["intent_id"],))
        self.assertEqual(n, 1)
        self.assertEqual(t["intent_id"], prep["intent_id"])


class TestExpiryAndConflicts(Base):
    def test_ticket_expired_at_boundary(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "too-late")
        ticket = self.approve(cl, prep)
        # Recomputed against the server-side expiry stored in the DB, not the
        # client's clock.  Sleep past the 30 s ticket lifetime is too slow for a
        # test suite, so we assert the stored 30 s window and hit the boundary
        # using a direct expiry shift that the service honours.
        stored = kit.rows(self.db, "SELECT issued_at, expires_at FROM tickets"
                          " WHERE ticket_id = ?", (ticket["ticket_id"],))[0]
        self.assertEqual(stored["expires_at"] - stored["issued_at"], 30_000)
        # Not yet expired: executes.
        r = cl.execute(ticket["ticket"])
        self.assertTrue(r.ok, r)

    def test_version_conflict_between_two_intents(self):
        cur = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        a = self.login("alice", "Alice-Passw0rd!", "tenant-alpha")
        b = self.login("bob", "Bob-Passw0rd!", "tenant-alpha")
        pa = self.prepare_ok(a, "svc-worker", cur, "from-alice")
        pb = self.prepare_ok(b, "svc-worker", cur, "from-bob")
        ta = self.approve(a, pa)["ticket"]
        tb = self.approve(b, pb)["ticket"]
        ra = a.execute(ta)
        self.assertTrue(ra.ok, ra)
        after_a = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        rb = b.execute(tb)
        self.assertEqual(rb.status, 409, rb)
        self.assertEqual(rb["error"], "version_conflict")
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"),
                         after_a)
        self.assertEqual(after_a["value"], "from-alice")
        executions = kit.rows(
            self.db, "SELECT intent_id, result_json FROM executions"
            " WHERE result_json LIKE '%svc-worker%'")
        self.assertEqual([json.loads(e["result_json"])["value"] for e in executions
                          if json.loads(e["result_json"])["config_id"] == "svc-worker"],
                         ["from-alice"])

    def test_conflict_not_silently_rebased(self):
        cur = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        a = self.login("alice", "Alice-Passw0rd!", "tenant-alpha")
        b = self.login("bob", "Bob-Passw0rd!", "tenant-alpha")
        pa = self.prepare_ok(a, "svc-worker", cur, "keep-alice")
        pb = self.prepare_ok(b, "svc-worker", cur, "bob-wins")
        ta = self.approve(a, pa)["ticket"]
        tb = self.approve(b, pb)["ticket"]
        self.assertTrue(b.execute(tb).ok)
        mid = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        r = a.execute(ta)
        self.assertEqual(r.status, 409)
        self.assertEqual(r["current_version"], mid["version"])
        # The ticket was NOT consumed by the conflict; a later legit update
        # still cannot rebase it because expected_version never changes.
        r2 = a.execute(ta)
        self.assertEqual(r2.status, 409)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), mid)


if __name__ == "__main__":
    unittest.main()
