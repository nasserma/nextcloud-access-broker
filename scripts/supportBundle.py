"""Support bundle generator (W3): the remote-debug channel.

Run ON THE BROKER HOST when something misbehaves:

    .venv/bin/python scripts/supportBundle.py
    # or inside the container:
    docker exec nc-access-broker python /app/scripts/supportBundle.py

Produces ONE timestamped file (stdout path or --out) containing:
  - broker version, python version, platform
  - SANITIZED config (secrets replaced with [redacted])
  - grant store state (ids, states, items — no secrets)
  - audit chain verification result (tamper evidence check)
  - last N audit records
  - recent docker/container logs if reachable (best effort)
  - config validation result

Every section is sanitized against the actual secret values from
config.yaml — by construction, not convention. The bundle is safe to
send to the maintainer/agent for remote debugging.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def collect_config_secrets(config_path: str) -> list[str]:
    """Extract every secret VALUE from config.yaml for scrubbing."""
    import yaml

    secrets = []
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    except Exception:  # noqa: BLE001 (missing config: no secrets to find)
        return secrets
    for block in (raw.get("instances") or {}).values():
        if block.get("password"):
            secrets.append(str(block["password"]))
    mx = raw.get("matrix") or {}
    if mx.get("bot_token"):
        secrets.append(str(mx["bot_token"]))
    ag = raw.get("agent") or {}
    if ag.get("token"):
        secrets.append(str(ag["token"]))
    return [s for s in secrets if s]


def scrub(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s in text:
            text = text.replace(s, "[redacted]")
    return text


def build_bundle(config_path: str, audit_tail: int = 40) -> dict:
    import subprocess

    from broker.audit import verify_chain
    from broker.config import ConfigError, load_config

    bundle = {
        "generated_at": datetime.now(UTC).isoformat(),
        "bundle_version": 1,
        "platform": {
            "python": sys.version.split()[0],
            "system": platform.platform(),
        },
    }

    # secrets from the raw config (never included, only used to scrub)
    secrets = collect_config_secrets(config_path)

    # config validation + sanitized view
    try:
        config = load_config(config_path)
        bundle["config_validation"] = "ok"
        bundle["config_sanitized"] = {
            "matrix": {
                "homeserver": config.matrix["homeserver"],
                "bot_user": config.matrix["bot_user"],
                "room_id": config.matrix["room_id"],
                "approver": config.matrix["approver"],
                "bot_token": "[redacted]",
            },
            "agent": {"token": "[redacted]"},
            "server": config.server,
            "lifecycle": config.lifecycle,
            "logging": config.logging_level,
            "audit_path": config.audit["path"],
            "instances": {
                name: {
                    "url": block["url"],
                    "username": block["username"],
                    "discovery": block.get("discovery", False),
                    "password": "[redacted]",
                }
                for name, block in config.instances.items()
            },
        }
    except ConfigError as exc:
        bundle["config_validation"] = f"FAILED: {scrub(str(exc), secrets)}"
        bundle["config_sanitized"] = None

    # audit chain verification + tail
    if bundle.get("config_sanitized"):
        audit_path = bundle["config_sanitized"]["audit_path"]
        try:
            result = verify_chain(audit_path)
            bundle["audit_chain"] = {
                "ok": result.ok,
                "error": result.error,
                "lines": result.lines,
            }
            tail = []
            p = Path(audit_path)
            if p.exists():
                lines = p.read_text().splitlines()[-audit_tail:]
                for line in lines:
                    tail.append(json.loads(line) if line.strip() else {})
            bundle["audit_tail"] = tail
        except Exception as exc:  # noqa: BLE001 (bundle must complete)
            bundle["audit_chain"] = {"ok": False, "error": scrub(str(exc), secrets)}

    # grant store state (from the audit dir, next to the audit log)
    if bundle.get("config_sanitized"):
        audit_dir = str(bundle["config_sanitized"]["audit_path"]).rsplit("/", 1)[0]
        db_path = Path(audit_dir) / "grants.sqlite3"
        grants = []
        if db_path.exists():
            try:
                import sqlite3

                db = sqlite3.connect(str(db_path))
                db.row_factory = sqlite3.Row
                for row in db.execute(
                    "SELECT id, instance, reason, items, created_at, decided_at,"
                    " expires_at, state, state_source FROM grants ORDER BY id"
                ):
                    grants.append(dict(row))
                db.close()
            except Exception as exc:  # noqa: BLE001
                grants.append({"error": scrub(str(exc), secrets)})
        bundle["grants"] = grants

    # recent container logs (best effort; only works with docker access)
    try:
        out = subprocess.run(
            ["docker", "logs", "--tail", "200", "nc-access-broker"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        bundle["container_logs"] = {
            "stdout": scrub(out.stdout[-20000:], secrets),
            "stderr": scrub(out.stderr[-20000:], secrets),
        }
    except Exception as exc:  # noqa: BLE001 (optional section)
        bundle["container_logs"] = {"unavailable": scrub(str(exc), secrets)}

    return bundle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default=None)
    parser.add_argument("--tail", type=int, default=40)
    args = parser.parse_args()

    bundle = build_bundle(args.config, audit_tail=args.tail)

    # final scrub pass over the whole rendered bundle
    secrets = collect_config_secrets(args.config)
    rendered = json.dumps(bundle, indent=1, default=str)
    rendered = scrub(rendered, secrets)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_path = args.out or f"supportBundle-{stamp}.json"
    Path(out_path).write_text(rendered)
    print(f"bundle written: {out_path} ({len(rendered)} bytes)")
    # verify no secret survived into the file
    leaked = [s for s in secrets if s in rendered]
    if leaked:
        print(f"ERROR: {len(leaked)} secret value(s) survived scrubbing - DO NOT SEND")
        sys.exit(1)
    print("sanity check: no secrets present in bundle - safe to share")


if __name__ == "__main__":
    main()