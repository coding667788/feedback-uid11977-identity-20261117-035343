"""End-to-end demo against a running service (no test framework).

    python -m sensitive_confirm init --db data/demo.db --key data/demo_key.json --force
    python -m sensitive_confirm serve --db data/demo.db --key data/demo_key.json --port 8765

    :: in another shell (codes are echoed only with SC_CODE_ECHO=1)
    set SC_CODE_ECHO=1 && python -m sensitive_confirm serve ...

    python demo.py --port 8765 --admin-key <hex from init>

Shows: login -> read config -> prepare -> verify -> execute -> idempotent
retry, printing the config row straight from SQLite after each step.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests import kit  # noqa: E402  (reuses the tiny JSON client)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="data/demo.db")
    ap.add_argument("--admin-key", default=None,
                    help="hex confirm key; only needed for the disable demo")
    ap.add_argument("--config-id", default="svc-api")
    ap.add_argument("--new-value", default="timeout=45s")
    args = ap.parse_args()

    cl = kit.Client(args.port)
    print("meta        :", cl.get("/v1/meta").body)
    login = cl.login("alice", "Alice-Passw0rd!")
    print("login       :", login.status, login.body.get("user_id"))
    cfg = cl.get(f"/v1/configs/{args.config_id}")
    print("config before:", cfg.body)
    version = cfg.body["version"]

    prep = cl.prepare(args.config_id, version, args.new_value)
    print("prepare     :", prep.status,
          json.dumps(prep.body.get("pending_action"), ensure_ascii=False))
    print("db after prepare:", kit.config_row(args.db, "tenant-alpha", args.config_id))

    code = prep.body.get("confirmation_code")
    if not code:
        print("server does not echo codes; derive it with:")
        print(f"  python -m sensitive_confirm code --db {args.db} "
              f"--key <keyfile> --challenge {prep.body['challenge']}")
        return 2
    ver = cl.verify(prep.body["challenge"], code)
    print("verify      :", ver.status, "ticket expires in",
          ver.body.get("expires_in_ms"), "ms")

    ex = cl.execute(ver.body["ticket"])
    print("execute     :", ex.status, json.dumps(ex.body.get("result"),
                                                 ensure_ascii=False))
    print("config after:", kit.config_row(args.db, "tenant-alpha", args.config_id))
    again = cl.execute(ver.body["ticket"])
    print("retry       :", again.status, "idempotent_replay =",
          again.body.get("idempotent_replay"))
    print("db after retry:", kit.config_row(args.db, "tenant-alpha", args.config_id))
    print("execution rows:", kit.scalar(args.db,
          "SELECT COUNT(*) FROM executions WHERE intent_id = ?",
          (prep.body["intent_id"],)))

    tamper = cl.post("/v1/execute", {"ticket": ver.body["ticket"],
                                     "new_value": "something-else"})
    print("tampered exec:", tamper.status, tamper.body.get("error"))
    print("config final :", kit.config_row(args.db, "tenant-alpha", args.config_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
