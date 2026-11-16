"""Shared test kit: service process management + a tiny JSON HTTP client.

Everything here is stdlib.  The service is always started as a *separate
process* (``python -m sensitive_confirm serve ...``) so that killing it is a
real fault-injection, not a simulated exception.
"""

from __future__ import annotations

import http
import http.client
import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


# ---------------------------------------------------------------------------
# paths / bootstrap
# ---------------------------------------------------------------------------

def fresh_dir(name: str) -> Path:
    base = ROOT / ".runtime-tmp" / "tests" / name
    if base.exists():
        import shutil
        shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    return base


def init_db(workdir: Path) -> tuple[str, str, str]:
    db_path = str(workdir / "confirm.db")
    key_path = str(workdir / "confirm_key.json")
    proc = subprocess.run(
        [PY, "-m", "sensitive_confirm", "init", "--db", db_path,
         "--key", key_path],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"init failed: {proc.stdout}\n{proc.stderr}")
    info = json.loads(proc.stdout)
    return db_path, key_path, info["admin_key"]


def read_key_hex(key_path: str) -> str:
    from sensitive_confirm.security import ConfirmKey
    return ConfirmKey.load(key_path).raw.hex()


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class ApiError(AssertionError):
    pass


@dataclass
class Resp:
    status: int
    body: dict

    @property
    def ok(self) -> bool:
        return self.body.get("ok") is True

    def __getitem__(self, key):
        return self.body[key]

    def __repr__(self) -> str:
        return f"Resp({self.status}, {json.dumps(self.body, ensure_ascii=False)[:300]})"


class Client:
    def __init__(self, port: int, host: str = "127.0.0.1"):
        self.port = port
        self.host = host
        self.token: str | None = None

    def request(self, method: str, path: str, body: dict | None = None,
                *, token: str | None = "__default__", headers: dict | None = None,
                timeout: float = 60.0) -> Resp:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        hdrs = {"Content-Type": "application/json"}
        tok = self.token if token == "__default__" else token
        if tok:
            hdrs["Authorization"] = f"Bearer {tok}"
        if headers:
            hdrs.update(headers)
        payload = None if body is None else json.dumps(body).encode()
        if payload is not None:
            hdrs["Content-Length"] = str(len(payload))
        try:
            conn.request(method, path, body=payload, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        finally:
            conn.close()
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {"ok": False, "raw": raw.decode("utf-8", "replace")}
        return Resp(status, data)

    # -- convenience ---------------------------------------------------
    def get(self, path: str, **kw) -> Resp:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: dict | None = None, **kw) -> Resp:
        return self.request("POST", path, body or {}, **kw)

    def login(self, login_name: str, password: str,
              tenant_id: str = "tenant-alpha") -> Resp:
        r = self.post("/v1/login", {"tenant_id": tenant_id,
                                    "login_name": login_name,
                                    "password": password})
        if r.ok:
            self.token = r["session_token"]
        return r

    def whoami(self) -> Resp:
        return self.get("/v1/whoami")

    def prepare(self, config_id: str, expected_version: int,
                new_value: str, **kw) -> Resp:
        return self.post("/v1/prepare", {"config_id": config_id,
                                         "expected_version": expected_version,
                                         "new_value": new_value}, **kw)

    def verify(self, challenge: str, code: str, **kw) -> Resp:
        return self.post("/v1/verify", {"challenge": challenge,
                                        "confirmation_code": code}, **kw)

    def execute(self, ticket: str, **kw) -> Resp:
        return self.post("/v1/execute", {"ticket": ticket}, **kw)


# ---------------------------------------------------------------------------
# service process management
# ---------------------------------------------------------------------------

def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Service:
    """One service process."""

    def __init__(self, db_path: str, key_path: str, *, name: str = "svc",
                 env: dict | None = None, port: int | None = None):
        self.db_path = db_path
        self.key_path = key_path
        self.name = name
        self.port = port or free_port()
        self.env = dict(os.environ)
        self.env.pop("SC_CRASHPOINT", None)
        self.env.pop("SC_CRASHPOINT_MODE", None)
        if env:
            self.env.update(env)
        self.proc: subprocess.Popen | None = None
        self._lines: queue.Queue[str] = queue.Queue()
        self.log: list[str] = []

    # -- lifecycle ------------------------------------------------------
    def start(self, timeout: float = 30.0) -> "Service":
        self.proc = subprocess.Popen(
            [PY, "-m", "sensitive_confirm", "serve", "--db", self.db_path,
             "--key", self.key_path, "--port", str(self.port)],
            cwd=ROOT, env=self.env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._lines.get(timeout=0.2)
            except queue.Empty:
                if self.proc.poll() is not None:
                    raise RuntimeError(
                        f"service {self.name} died during startup:\n"
                        + "\n".join(self.log[-20:]))
                continue
            if '"listening"' in line:
                return self
            self.log.append(line)
        raise RuntimeError(f"service {self.name} did not start")

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            self.log.append(line.rstrip("\n"))
            self._lines.put(line.rstrip("\n"))

    def wait_line(self, needle: str, timeout: float = 60.0) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._lines.get(timeout=0.2)
            except queue.Empty:
                if self.proc is not None and self.proc.poll() is not None:
                    raise RuntimeError(
                        f"service {self.name} exited before '{needle}':\n"
                        + "\n".join(self.log[-25:]))
                continue
            if needle in line:
                return line
            self.log.append(line)
        raise TimeoutError(f"service {self.name}: no '{needle}' within {timeout}s")

    def wait_exit(self, timeout: float = 30.0) -> int:
        assert self.proc is not None
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise

    def release(self) -> None:  # for SC_CRASHPOINT_MODE=pause
        assert self.proc and self.proc.stdin
        self.proc.stdin.write("\n")
        self.proc.stdin.flush()

    def kill(self) -> None:
        assert self.proc is not None
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=30)
        self._close_pipes()

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=10)
            except Exception:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self._close_pipes()

    def _close_pipes(self) -> None:
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


class Fleet:
    """N service processes sharing one database."""

    def __init__(self, db_path: str, key_path: str, count: int = 4):
        self.services = [Service(db_path, key_path, name=f"svc{i}")
                         for i in range(count)]
        self.count = count

    def start(self) -> "Fleet":
        for svc in self.services:
            svc.start()
        return self

    def stop(self) -> None:
        for svc in self.services:
            svc.stop()

    def client(self, index: int = 0) -> Client:
        return Client(self.services[index % self.count].port)

    def kill_all(self) -> None:
        for svc in self.services:
            svc.kill()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


# ---------------------------------------------------------------------------
# DB helpers (direct reads to prove effects independently of HTTP)
# ---------------------------------------------------------------------------

def db_connect(db_path: str):
    from sensitive_confirm import db
    return db.connect(db_path)


def config_row(db_path: str, tenant_id: str, config_id: str) -> dict:
    conn = db_connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM configs WHERE tenant_id = ? AND config_id = ?",
            (tenant_id, config_id)).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def scalar(db_path: str, sql: str, params=()):
    conn = db_connect(db_path)
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def rows(db_path: str, sql: str, params=()) -> list[dict]:
    conn = db_connect(db_path)
    try:
        return [dict(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()


def audit_count(db_path: str, action: str | None = None) -> int:
    if action is None:
        return scalar(db_path, "SELECT COUNT(*) FROM audit_log")
    return scalar(db_path, "SELECT COUNT(*) FROM audit_log WHERE action = ?",
                  (action,))
