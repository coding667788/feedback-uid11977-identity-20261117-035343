"""HTTP layer: a small stdlib server with JSON in / JSON out.

Only loopback is bound by default (``--host 127.0.0.1``); there is no TLS and no
frontend by design.  Each request is handled on its own thread with its own
SQLite connection -- all state lives in the shared database, so any number of
these processes can run against it.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import signal
import sqlite3
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import services
from .crashpoints import for_process

MAX_BODY = 64 * 1024
INFO = {
    "service": "sensitive-operation-confirm",
    "version": "1.0.0",
    "scheme": "prepare -> verify(confirm key) -> execute(30s single-use ticket)",
    "time_source": "unix epoch milliseconds (UTC)",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "SensitiveConfirm/1.0"
    protocol_version = "HTTP/1.1"

    ctx: services.Ctx  # set by serve()
    crash_control: dict = {}  # crashpoint name -> CrashPoint (for tests)

    # -- plumbing --------------------------------------------------------
    def log_message(self, fmt, *args):
        if os.environ.get("SC_HTTP_LOG"):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise services.ServiceError(413, "body_too_large",
                                        "request body too large")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except ValueError:
            raise services.ServiceError(400, "invalid_json", "body is not JSON")
        if not isinstance(value, dict):
            raise services.ServiceError(400, "invalid_request",
                                        "body must be an object")
        return value

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return self.headers.get("X-Session-Token")

    def _dispatch(self, method: str) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        try:
            body = self._read_json() if method == "POST" else {}
            status, payload = self._route(method, path, body)
        except services.ServiceError as exc:
            status, payload = exc.status, exc.body()
        except sqlite3.OperationalError as exc:
            # Lock contention surfaces as a retryable 503 rather than a 500:
            # nothing was committed, the caller may safely retry.
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                status, payload = 503, {
                    "ok": False, "error": "database_busy", "retryable": True,
                    "message": "database is busy; nothing was committed"}
            else:
                traceback.print_exc()
                status, payload = 500, {"ok": False, "error": "internal_error",
                                        "message": "internal error"}
        except Exception:
            traceback.print_exc()
            status, payload = 500, {"ok": False, "error": "internal_error",
                                    "message": "internal error"}
        self._send(status, payload)

    def _require_admin(self, body: dict) -> None:
        """Admin endpoints accept the provisioned confirm key (raw hex) in
        ``X-Admin-Key``.  A normal login token is deliberately not enough."""
        supplied = (self.headers.get("X-Admin-Key") or "").strip().lower()
        if not hmac.compare_digest(supplied,
                                   self.ctx.confirm_key.raw.hex()):
            raise services.ServiceError(403, "forbidden",
                                        "a valid X-Admin-Key is required")

    def _route(self, method: str, path: str, body: dict) -> tuple[int, dict]:
        ctx = self.ctx
        tok = self._token()

        if method == "GET" and path == "/health":
            return 200, {"ok": True, "pid": os.getpid()}
        if method == "GET" and path == "/v1/meta":
            return 200, {"ok": True, **INFO}
        if method == "GET" and path == "/v1/whoami":
            return 200, services.whoami(ctx, tok)
        if method == "GET" and path == "/v1/configs":
            return 200, services.list_configs(ctx, tok)
        if method == "GET" and path.startswith("/v1/configs/"):
            return 200, services.get_config(ctx, tok, path.split("/", 3)[3])

        if method == "POST" and path == "/v1/login":
            return 200, services.login(ctx, body.get("tenant_id"),
                                       body.get("login_name"),
                                       body.get("password"))
        if method == "POST" and path == "/v1/logout":
            return 200, services.logout(ctx, tok)
        if method == "POST" and path == "/v1/session/rotate":
            return 200, services.rotate_session(ctx, tok)
        if method == "POST" and path == "/v1/prepare":
            return 200, services.prepare(ctx, tok, body)
        if method == "POST" and path == "/v1/verify":
            return 200, services.verify(ctx, tok, body)
        if method == "POST" and path == "/v1/execute":
            return 200, services.execute(ctx, tok, body)

        if method == "POST" and path == "/admin/disable-user":
            self._require_admin(body)
            return 200, services.admin_set_disabled(
                ctx, body.get("tenant_id"), body.get("login_name"),
                bool(body.get("disabled", True)))

        raise services.ServiceError(404, "not_found",
                                    f"no route for {method} {path}")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def serve(db_path: str, key_path: str, host: str, port: int) -> None:
    crashes = for_process("svc")
    ctx = services.Ctx.load(db_path, key_path, crashes)
    Handler.ctx = ctx
    Handler.crash_control = crashes
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True

    def _shutdown(signum, frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
    except ValueError:  # pragma: no cover
        pass

    sys.stdout.write(json.dumps({
        "event": "listening", "pid": os.getpid(), "host": host,
        "port": httpd.server_address[1]}) + "\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever(poll_interval=0.05)
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sensitive_confirm.server")
    parser.add_argument("--db", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not os.path.exists(args.db):
        sys.stderr.write("database not initialised; run the `init` command\n")
        return 2
    serve(args.db, args.key, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
