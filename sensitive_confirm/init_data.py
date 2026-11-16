"""Preset identities and configuration rows used by ``init``."""

from __future__ import annotations

SEED_TENANTS = ["tenant-alpha", "tenant-beta"]

_USERS = [
    # tenant, login_name, password, user_id, disabled
    ("tenant-alpha", "alice", "Alice-Passw0rd!", "usr_alpha_alice", 0),
    ("tenant-alpha", "bob", "Bob-Passw0rd!", "usr_alpha_bob", 0),
    ("tenant-beta", "carol", "Carol-Passw0rd!", "usr_beta_carol", 0),
]

SEED_CONFIGS = [
    {"tenant_id": "tenant-alpha", "config_id": "svc-api", "version": 1,
     "value": "timeout=30s"},
    {"tenant_id": "tenant-alpha", "config_id": "svc-worker", "version": 3,
     "value": "replicas=2"},
    {"tenant_id": "tenant-beta", "config_id": "svc-api", "version": 1,
     "value": "timeout=10s"},
    {"tenant_id": "tenant-beta", "config_id": "svc-billing", "version": 7,
     "value": "currency=USD"},
]


def preset_users() -> list[dict]:
    return [{"tenant_id": t, "login_name": n, "password": p, "user_id": u,
             "disabled": d} for t, n, p, u, d in _USERS]


def preset_configs() -> list[dict]:
    return [dict(c) for c in SEED_CONFIGS]
