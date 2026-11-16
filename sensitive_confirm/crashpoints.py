"""Controllable synchronisation points used by the fault-injection tests.

Environment variables (all optional, all read once per process):

``SC_CRASHPOINT``
    Comma separated list of crash point names active in this process.
``SC_CRASHPOINT_MODE``
    ``kill`` (default) -- ``os._exit(9)`` at the point, so the process dies
    *inside* the surrounding transaction.  ``pause`` -- signal readiness on
    stdout and then block until the parent writes to stdin.
``SC_SYNC_FILE``
    When set, readiness is also written to this file as a JSON line, so the
    test harness does not have to scrape stdout.
``SC_CRASH_EXIT_CODE``
    Exit code used by ``kill`` (default 9).

Points used by the service:

``before_begin``
    After the caller session has been read and before BEGIN.  Lets a competing
    logout / disable transaction commit first (that is the interesting order);
    everything the execution relies on is then re-read inside the transaction.
``before_claim``
    After BEGIN, row locks acquired, ticket validation *on paper* done, but
    before any row is written.  (Used to widen the pre-commit race window.)
``ticket_marked_used``
    After the ticket has been flipped to ``used`` inside the transaction and
    before the config CAS update / execution record.  Killing here must leave
    the ticket untouched and no config change -- the transaction was never
    committed.
``config_updated``
    After the config row UPDATE inside the transaction, before COMMIT.  Same
    requirement: no partial state after a kill.
``after_commit``
    After COMMIT has durably returned, before the HTTP response is written.
    Retrying with the same ticket must return the stored result and must not
    touch the config again.
``after_session_revoke``
    After the COMMIT of a logout / disable that races with an execution.
"""

from __future__ import annotations

import json
import os
import sys


class CrashPoint:
    def __init__(self, name: str, mode: str, sync_file: str | None):
        self.name = name
        self.mode = mode
        self.sync_file = sync_file

    def _announce(self) -> None:
        line = json.dumps({"event": "crashpoint", "name": self.name,
                           "pid": os.getpid(), "mode": self.mode})
        try:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except Exception:
            pass
        if self.sync_file:
            try:
                with open(self.sync_file, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass

    def hit(self) -> None:
        self._announce()
        if self.mode == "pause":
            try:
                sys.stdin.readline()
            except Exception:
                pass
            return
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(int(os.environ.get("SC_CRASH_EXIT_CODE", "9")))


def for_process(service_name: str) -> dict[str, CrashPoint]:
    raw = os.environ.get("SC_CRASHPOINT", "")
    names = [n.strip() for n in raw.split(",") if n.strip()]
    mode = os.environ.get("SC_CRASHPOINT_MODE", "kill")
    sync_file = os.environ.get("SC_SYNC_FILE") or None
    return {n: CrashPoint(f"{service_name}:{n}", mode, sync_file) for n in names}
