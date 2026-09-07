"""Gate 2 demo: grant survives restart, expiry refuses operations.

Run: .venv/bin/python scripts/demo_restart.py
Expected output: the sequence of state transitions, ending in
DEMO-PASS only if every assertion holds.

This is the machine-checkable restart artifact named by Gate 2 of the
goal contract: create a grant, "restart" the process (reopen the DB),
verify the grant survives; expire it via injected clock; verify refusal.
"""

import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.grants import ACTIVE, EXPIRED, REJECTED, GrantStore
from broker.paths import Grant, check_access

T0 = datetime(2026, 9, 5, 12, 0, 0)  # noqa: DTZ001 (injected clock)


def main():
    db = Path(tempfile.mkdtemp()) / "demo.sqlite3"
    failures = []

    def check(label, cond):
        print(f"  [{'ok' if cond else 'FAIL'}] {label}")
        if not cond:
            failures.append(label)

    # Session 1: create request, approve it, leave another pending.
    s1 = GrantStore(db_path=db, now=lambda: T0)
    r1 = s1.create_request(
        instance="personal",
        reason="demo task",
        items=[
            {"path": "Documents/paper", "mode": "read"},
            {"path": "Documents/paper/figures", "mode": "write"},
        ],
    )
    s1.approve(r1.id, expiry="24h")
    r2 = s1.create_request(
        instance="personal", reason="pending demo", items=[{"path": "Photos", "mode": "read"}]
    )
    s1.close()  # process dies

    # Session 2: "restart" — reopen the same file.
    s2 = GrantStore(db_path=db, now=lambda: T0)
    g = s2.get(r1.id)
    check("active grant survives restart", g.state == ACTIVE)
    check("expiry timestamp unchanged", g.expires_at == T0 + timedelta(hours=24))
    p = s2.get(r2.id)
    check("pending request discarded on restart", p.state == REJECTED)
    check("discard source recorded", p.state_source == "restart_discard")

    # Path checker consumes the surviving grant.
    grants = [
        Grant(path=item["path"], mode=item["mode"], expires_at=g.expires_at, id=g.id)
        for item in g.items
    ]
    d = check_access("Documents/paper/draft.tex", "read", grants, T0)
    check("read inside granted scope allowed after restart", d.allowed)
    d = check_access("Documents/paper/figures/fig1.pdf", "write", grants, T0)
    check("write inside granted scope allowed after restart", d.allowed)
    d = check_access("Documents/paper/../../secret.txt", "read", grants, T0)
    check("traversal outside scope refused", not d.allowed)

    # Expiry via injected clock: the next operation is refused.
    later = T0 + timedelta(hours=25)
    d = check_access("Documents/paper/draft.tex", "read", grants, later)
    check("expired grant refuses operations", not d.allowed)
    s2._now = lambda: later  # advance the store's own clock
    check("store reports expiry", s2.get(r1.id).state == EXPIRED)

    # One-time numbers survive restart too.
    try:
        s2.approve(r1.id)
        check("decided number not reusable after restart", False)
    except ValueError:
        check("decided number not reusable after restart", True)

    s2.close()

    if failures:
        print(f"DEMO-FAIL: {len(failures)} checks failed")
        sys.exit(1)
    print("DEMO-PASS: all Gate 2 restart checks hold")


if __name__ == "__main__":
    main()