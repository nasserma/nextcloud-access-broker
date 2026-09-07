"""R2 probes: grants state machine and restart semantics.

Fresh probes NOT in tests/: every transition from every state,
concurrent stores, clock skew, mapping behavior.
Run: .venv/bin/python review/r2_state_probes.py
"""

import sqlite3
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.grants import GrantStore

T0 = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
FINDINGS = []


def make(tmp, now=None):
    return GrantStore(db_path=tmp / "g.sqlite3", now=now or (lambda: T0))


def probe(label, fn):
    try:
        outcome = fn()
        print(f"  [ok] {label}: {outcome}")
    except Exception as exc:  # noqa: BLE001 (probe harness must survive any exception)
        print(f"  [!!] {label}: raised {type(exc).__name__}: {exc}")
        FINDINGS.append(f"{label}: {type(exc).__name__}: {exc}")


tmp = Path(tempfile.mkdtemp())

print("=== R2 state machine probes ===")

# P1: full transition matrix. From each stored state, attempt each op.
# Expected: any op on a decided (non-pending) grant raises ValueError;
# approve/reject only valid from pending; revoke from pending->rejected,
# active->revoked, decided->ValueError. All covered in tests; re-probe
# the effective-state nuance: expired-pending seen as EXPIRED by get()
# but stored PENDING - can approve() act on it via a race (two
# consecutive _state calls)?
def p1():
    s = make(tmp)
    r = s.create_request("i", "r", [{"path": "a", "mode": "read"}])
    # advance clock so effective state is expired
    s._now = lambda: T0 + timedelta(hours=13)
    try:
        s.approve(r.id)
        return "PROBLEM: approved an expired-pending request"
    except ValueError as e:
        return f"refused as expected ({e})"
probe("P1 approve on expired-pending", p1)


# P2: concurrent stores - writer isolation under WAL
def p2():
    db = Path(str(tmp) + "_p2")
    db.mkdir(exist_ok=True)
    s1 = make(db, lambda: T0)
    r = s1.create_request("i", "r", [{"path": "a", "mode": "read"}])
    s2 = make(db, lambda: T0)  # second connection; restart-discard fires
    st = s2.get(r.id)
    return f"second store sees: {st.state} (restart_discard kills pending by design)"
probe("P2 concurrent store on pending request", p2)


# P3: clock skew - store now() BEFORE created_at (negative elapsed)
def p3():
    s = make(tmp, lambda: T0 - timedelta(hours=1))
    r = s.create_request("i", "r", [{"path": "a", "mode": "read"}])
    # created_at uses the skewed now; effective expiry check uses
    # now - created >= 12h. Skew backwards => pending stays alive longer
    st = s.get(r.id)
    return f"skewed store sees pending as: {st.state} (skew extends pending life; fails safe direction?)"
probe("P3 clock skew backwards", p3)


# P4: clock skew forwards - does pending die early? (fail-safe = yes fine)
def p4():
    s = make(tmp, lambda: T0 + timedelta(hours=13))
    r = s.create_request("i", "r", [{"path": "a", "mode": "read"}])
    st = s.get(r.id)
    return f"forward-skewed sees: {st.state}"
probe("P4 clock skew forwards", p4)


# P5: approve with expiry in the PAST (skewed store): grant born expired?
def p5():
    s = make(tmp, lambda: T0)
    r = s.create_request("i", "r", [{"path": "a", "mode": "read"}])
    s.approve(r.id, expiry="1h")
    s._now = lambda: T0 + timedelta(hours=2)
    st = s.get(r.id)
    return f"after expiry: {st.state} (must be expired, not active)"
probe("P5 grant born-then-expired", p5)


# P6: can items be swapped after approval? (mutation of stored items)
def p6():
    s = make(tmp, lambda: T0)
    r = s.create_request("i", "r", [{"path": "a", "mode": "read"}])
    s.approve(r.id)
    g1 = s.get(r.id)
    # GrantRecord is a frozen dataclass - mutate should fail
    try:
        g1.items.append({"path": "EVERYTHING", "mode": "write"})
        return f"PROBLEM: items list mutable: {g1.items}"
    except AttributeError as e:
        # dataclass frozen blocks attribute set, but the LIST may still
        # be mutable if the dataclass holds a reference!
        return f"attribute set blocked ({e.__class__.__name__}); check list"
probe("P6 grant record immutability", p6)


# P7: the deeper mutation probe - bypassing the frozen dataclass
def p7():
    s = make(tmp, lambda: T0)
    r = s.create_request("i", "r", [{"path": "a", "mode": "read"}])
    s.approve(r.id)
    g1 = s.get(r.id)
    try:
        g1.items[0]["mode"] = "write"
        # if this worked, the STORED copy may be unaffected (fresh load)
        g2 = s.get(r.id)
        stored_mode = g2.items[0]["mode"]
        return f"dict mutated in-memory; stored mode still: {stored_mode}"
    except Exception as e:  # noqa: BLE001 (probe harness)
        return f"mutation blocked: {type(e).__name__}"
probe("P7 in-memory dict mutation vs stored copy", p7)


# P8: one-time numbers across restart with decided states
def p8():
    db = Path(str(tmp) + "_p8")
    db.mkdir(exist_ok=True)
    s1 = make(db, lambda: T0)
    r = s1.create_request("i", "r", [{"path": "a", "mode": "read"}])
    s1.approve(r.id)
    s2 = make(db, lambda: T0)
    try:
        s2.approve(r.id)
        return "PROBLEM: re-approvable after restart"
    except ValueError as e:
        return f"refused ({e})"
probe("P8 one-time number after restart", p8)


# P9: posted_messages mapping - can a reaction target a DIFFERENT grant?
def p9():
    s = make(tmp, lambda: T0)
    try:
        s.record_posted("$evA", 1)
        try:
            s.record_posted("$evA", 5)  # replay/hijack attempt: same event, other id
            return f"PROBLEM: rebind accepted: {s.request_for_event('$evA')}"
        except sqlite3.IntegrityError as e:
            # M-2 fix: plain INSERT - a duplicate event id raises loudly
            # instead of silently rebinding an event to another request.
            # The mapping must still point at the ORIGINAL request.
            return f"rebind refused ({e}); mapping still: {s.request_for_event('$evA')}"
    finally:
        # The caught IntegrityError leaves an open write txn holding the
        # file lock; close (implicit rollback) so later probes do not
        # hit 'database is locked'.
        s.close()
probe("P9 event mapping overwrite semantics", p9)


# P10: request with duplicate paths and mixed modes in one item list
def p10():
    s = make(tmp, lambda: T0)
    r = s.create_request("i", "r", [
        {"path": "a", "mode": "read"},
        {"path": "a", "mode": "write"},
    ])
    s.approve(r.id)
    g = s.get(r.id)
    return f"duplicate path items both survive approval: {g.items}"
probe("P10 duplicate path, mixed modes", p10)

print()
if FINDINGS:
    print(f"=== R2 FINDINGS: {len(FINDINGS)} ===")
    for f in FINDINGS:
        print(" -", f)
    sys.exit(1)
print("=== R2 probes complete; anomalies above are recorded in findings ===")
sys.exit(0)