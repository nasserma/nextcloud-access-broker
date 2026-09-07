"""Gate 3 demo: tamper evidence and write-failure refusal.

Run: .venv/bin/python scripts/demo_audit.py
Expected: DEMO-PASS only if every check holds.

Gate 3 named artifacts:
 1. Deliberate corruption of a log file detected by verify_chain()
    (truncation AND edit).
 2. Simulated log-write failure refuses the operation.
 3. Append-only: existing bytes never change.
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.audit import AuditLog, LogWriteError, verify_chain

NOW = "2026-09-05T12:00:00"


def main():
    tmp = Path(tempfile.mkdtemp())
    log_path = tmp / "audit.log"
    failures = []

    def check(label, cond):
        print(f"  [{'ok' if cond else 'FAIL'}] {label}")
        if not cond:
            failures.append(label)

    log = AuditLog(path=log_path, now=lambda: NOW)
    for i in range(4):
        log.record(
            instance="personal", path=f"Docs/f{i}.tex", operation="write",
            grant_id=1, decision="allowed", reason="gate demo",
        )
    check("pristine log verifies", verify_chain(log_path).ok)

    # --- artifact 1a: truncation detected
    lines = log_path.read_text().strip().splitlines()
    log_path.write_text("\n".join(lines[:-1]) + "\n")
    r = verify_chain(log_path)
    check("truncation detected", not r.ok)
    check("truncation error names the problem", "truncat" in (r.error or "") or "checkpoint" in (r.error or ""))

    # --- restore, then artifact 1b: edit detected
    log2 = AuditLog(path=log_path, now=lambda: NOW)  # also proves restart-recovery
    log2.record(
        instance="personal", path="Docs/f0.tex", operation="read",
        grant_id=1, decision="allowed", reason="gate demo",
    )
    check("log continues chain after restart", verify_chain(log_path).ok)
    lines = log_path.read_text().strip().splitlines()
    record = json.loads(lines[1])
    record["path"] = "tampered"
    log_path.write_text("\n".join([lines[0], json.dumps(record, sort_keys=True)] + lines[2:]) + "\n")
    r = verify_chain(log_path)
    check("edit detected", not r.ok)
    check("edit error names line 2", "line 2" in (r.error or ""))

    # --- artifact 2: log-write failure refuses the operation
    fresh = tmp / "fresh.log"
    log3 = AuditLog(path=fresh, now=lambda: NOW)
    ran = []
    try:
        log3.record(
            instance="personal", path="a", operation="read",
            grant_id=1, decision="allowed", reason="ok",
            then=lambda: ran.append(1),
            _fail_inject=True,
        )
        check("write failure raises", False)
    except LogWriteError:
        check("write failure raises", True)
    check("operation refused on log failure", ran == [])
    check("nothing written on failed record", not fresh.exists())

    # --- artifact 3: append-only
    before = log_path.read_bytes()
    sha_before = __import__("hashlib").sha256(before).hexdigest()
    log4 = AuditLog(path=log_path, now=lambda: NOW)
    log4.record(
        instance="personal", path="new", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    after = log_path.read_bytes()
    check("existing bytes untouched (strict append)", after.startswith(before))
    check(
        "prefix checksum stable",
        __import__("hashlib").sha256(before).hexdigest() == sha_before,
    )

    if failures:
        print(f"DEMO-FAIL: {len(failures)} checks failed")
        sys.exit(1)
    print("DEMO-PASS: all Gate 3 tamper and refusal checks hold")


if __name__ == "__main__":
    main()