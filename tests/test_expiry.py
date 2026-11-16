"""Expiry boundaries, using a shortened ticket lifetime for the test process.

The production lifetime is 30 s; the test process is started with
``SC_TICKET_TTL_MS`` so the boundary can be crossed in real time.  To prove the
30 s default is real, one test also reads the stored row from a normally
configured process.
"""

from __future__ import annotations

import time

from . import kit
from .test_functional import Base


class TestTicketExpiry(Base):
    TTL_MS = 1_200

    def setUp(self):
        super().setUp()
        self.svc.stop()
        self.svc = kit.Service(self.db, self.key, name="svc",
                               env={"SC_CODE_ECHO": "1",
                                    "SC_TICKET_TTL_MS": str(self.TTL_MS),
                                    "SC_INTENT_TTL_MS": "4000"}).start()
        self.fleet.services = [self.svc]
        self.c = kit.Client(self.svc.port)

    def _issued(self, cl, config_id="svc-worker", value="expiring"):
        v = kit.config_row(self.db, "tenant-alpha", config_id)["version"]
        prep = self.prepare_ok(cl, config_id, v, value)
        return self.approve(cl, prep)

    def test_execute_just_before_expiry_succeeds(self):
        cl = self.login()
        ticket = self._issued(cl, value="just-in-time")
        time.sleep(self.TTL_MS / 1000 * 0.4)
        r = cl.execute(ticket["ticket"])
        self.assertTrue(r.ok, r)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker")["value"],
                         "just-in-time")

    def test_execute_after_expiry_rejected_and_no_write(self):
        cl = self.login()
        before = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        ticket = self._issued(cl, value="too-late")
        time.sleep(self.TTL_MS / 1000 + 0.4)
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 410, r)
        self.assertEqual(r["error"], "ticket_expired")
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), before)
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM executions"), 0)
        # The expired ticket is not consumed and never becomes usable again.
        r = cl.execute(ticket["ticket"])
        self.assertEqual(r.status, 410, r)

    def test_replay_after_ticket_expiry_still_returns_original_result(self):
        # The ticket's expiry gates *execution*, not result retrieval: once the
        # action committed, a late retry with the same ticket must still return
        # the recorded result (and not write again).  Identity, session and
        # disabled state are still re-checked on that retry.
        cl = self.login()
        ticket = self._issued(cl, value="replayed-late")
        first = cl.execute(ticket["ticket"])
        self.assertTrue(first.ok, first)
        snap = kit.config_row(self.db, "tenant-alpha", "svc-worker")
        time.sleep(self.TTL_MS / 1000 + 0.4)
        late = cl.execute(ticket["ticket"])
        self.assertTrue(late.ok, late)
        self.assertTrue(late["idempotent_replay"])
        self.assertEqual(late["result"]["version"], first["result"]["version"])
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), snap)
        # ...but the same late retry after logout is refused.
        self.assertTrue(cl.post("/v1/logout").ok)
        refused = cl.execute(ticket["ticket"])
        self.assertEqual(refused.status, 401, refused)
        self.assertEqual(kit.config_row(self.db, "tenant-alpha", "svc-worker"), snap)

    def test_challenge_expiry_blocks_verify(self):
        cl = self.login()
        v = kit.config_row(self.db, "tenant-alpha", "svc-worker")["version"]
        prep = self.prepare_ok(cl, "svc-worker", v, "late-confirm")
        time.sleep(4.3)
        r = cl.verify(prep["challenge"], prep["confirmation_code"])
        self.assertEqual(r.status, 410, r)
        self.assertEqual(r["error"], "challenge_expired")
        self.assertEqual(kit.scalar(self.db, "SELECT COUNT(*) FROM tickets"), 0)

    def test_default_ttl_is_30_seconds(self):
        svc = kit.Service(self.db, self.key, name="svc30",
                          env={"SC_CODE_ECHO": "1"}).start()
        try:
            cl = kit.Client(svc.port)
            self.assertTrue(cl.login("carol", "Carol-Passw0rd!", "tenant-beta").ok)
            v = kit.config_row(self.db, "tenant-beta", "svc-billing")["version"]
            prep = cl.prepare("svc-billing", v, "currency=EUR")
            self.assertTrue(prep.ok, prep)
            t = cl.verify(prep["challenge"], prep["confirmation_code"])
            self.assertTrue(t.ok, t)
            self.assertEqual(t["expires_in_ms"], 30_000)
            row = kit.rows(self.db, "SELECT * FROM tickets WHERE ticket_id = ?",
                           (t["ticket_id"],))[0]
            self.assertEqual(row["expires_at"] - row["issued_at"], 30_000)
        finally:
            svc.stop()
