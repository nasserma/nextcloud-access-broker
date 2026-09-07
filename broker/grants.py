"""Grant store and lifecycle (Gate 2).

Design document section 3.4. SQLite-backed; state machine:

    pending --approve--> active --expiry--> expired
    pending --reject----> rejected        active --revoke--> revoked
    pending --12h silence--> expired     pending --revoke--> rejected
    pending --restart--> rejected (restart_discard)

Rules enforced here:
- Request numbers are one-time. Once decided (active/rejected/expired/
  revoked), a number can never change state again except the single
  expiry/revocation transition from active. approve/reject on a decided
  number raises ValueError.
- Active grants persist across restart. Pending requests are discarded
  at reopen (state rejected, source restart_discard) - a stale pending
  request grants nothing and is worthless after a restart.
- No auto-renewal: expiry timestamps are written once at approval and
  never touched again.
- The clock is injected. No function in this module reads the wall clock.
- Item paths and modes are validated at creation time using the same
  rules the path checker enforces (normalize_path; read/write modes).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from broker.paths import READ, WRITE, normalize_path

PENDING = "pending"
ACTIVE = "active"
EXPIRED = "expired"
REVOKED = "revoked"
REJECTED = "rejected"

_DECIDED = {ACTIVE, REJECTED, EXPIRED, REVOKED}

DEFAULT_PENDING_TIMEOUT = timedelta(hours=12)
DEFAULT_GRANT_DURATION = timedelta(hours=24)

_EXPIRY_RE = re.compile(r"^(\d{1,3})(h|m|d)$")
_UNIT_SECONDS = {"h": 3600, "m": 60, "d": 86400}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance TEXT NOT NULL,
    reason TEXT NOT NULL,
    items TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    expires_at TEXT,
    state TEXT NOT NULL,
    state_source TEXT
);
CREATE TABLE IF NOT EXISTS posted_messages (
    event_id TEXT PRIMARY KEY,
    request_id INTEGER NOT NULL
);
"""


def parse_expiry(text: str | None) -> timedelta | None:
    """Parse an expiry string like '8h', '30m', '2d'. None -> None (default).

    Raises ValueError on anything else. Zero and negative values are
    rejected: a grant that is born expired is a configuration mistake.
    """
    if text is None:
        return None
    m = _EXPIRY_RE.match(text.strip())
    if not m:
        raise ValueError(f"invalid expiry string: {text!r}")
    value, unit = int(m.group(1)), m.group(2)
    if value <= 0:
        raise ValueError(f"expiry must be positive: {text!r}")
    return timedelta(seconds=value * _UNIT_SECONDS[unit])


@dataclass(frozen=True)
class GrantRecord:
    """Immutable view of one grant row for callers outside this module.

    state is the EFFECTIVE state (time-based transitions applied on read),
    not the raw stored state: a row stored 'pending' but past its pending
    timeout reads here as 'expired'. state_source names who decided it
    ('approval', 'rejection', 'restart_discard', 'pending_timeout',
    'grant_expiry', ...). items is deep-copied so callers cannot mutate
    the store's authorization payload through a returned record.
    """

    id: int
    instance: str
    reason: str
    items: list  # list of {path, mode} dicts; [] for pending->rejected
    state: str
    expires_at: datetime | None
    created_at: datetime
    state_source: str | None

    @property
    def path(self) -> str | None:
        """First item's path, for single-item convenience (path checker
        consumes active_grants() output instead)."""
        return self.items[0]["path"] if self.items else None

    @property
    def mode(self) -> str | None:
        """First item's mode, mirroring path() (None when items is empty)."""
        return self.items[0]["mode"] if self.items else None


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _from_iso(text: str) -> datetime:
    return datetime.fromisoformat(text)


class GrantStore:
    """SQLite-backed grant store. Open one per process; reopening the same
    file is the restart path (pending -> rejected on open)."""

    def __init__(
        self,
        db_path,
        now: Callable[[], datetime],
        pending_timeout: timedelta = DEFAULT_PENDING_TIMEOUT,
        default_duration: timedelta = DEFAULT_GRANT_DURATION,
        allowed_instances: set | None = None,
    ):
        """Open (creating if needed) the grant database and apply the
        restart-discard rule.

        db_path: SQLite file backing the store. now: injected clock
        (invariant: no wall-clock reads inside this module, so tests and
        audit tooling control time). allowed_instances restricts
        create_request() to a known instance set; None disables that
        restriction (test-only). MUST be constructed before the transport
        starts serving requests: the restart-discard pass on open is what
        guarantees a stale pending request from a previous process lifetime
        can never be approved.
        """
        self._now = now
        self._pending_timeout = pending_timeout
        self._default_duration = default_duration
        self.allowed_instances = allowed_instances  # None = no restriction (tests)
        self._db = sqlite3.connect(str(db_path))
        self._db.row_factory = sqlite3.Row
        # WAL: allows a reader (backfill/inspection tooling) while the
        # server loop holds its connection. The right mode for a
        # long-running process.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._restart_discard_pending()

    def close(self):
        self._db.close()

    # ------------------------------------------------------------ restart rule

    def _restart_discard_pending(self):
        """Restart-discard rule: pending requests never survive a restart.

        Called ONLY from __init__, before anything else can observe the
        store. A pending request that outlived its process is stale: the
        Matrix message may already have been reacted to, duplicated, or
        lost, so human intent can no longer be established - every such
        row is moved to rejected with state_source='restart_discard'.
        """
        cur = self._db.execute(
            "UPDATE grants SET state=?, state_source=? WHERE state=?",
            (REJECTED, "restart_discard", PENDING),
        )
        if cur.rowcount:
            self._db.commit()

    # ------------------------------------------------------------- transitions

    def create_request(self, instance: str, reason: str, items: list) -> GrantRecord:
        """Record a new pending request. This grants NOTHING - the path
        checker only sees output of active_grants().

        instance: target Nextcloud instance name (checked against the
        allow-list when one is configured). reason: non-empty human
        explanation shown to the approver. items: list of {path, mode}
        dicts; every path is normalized with the SAME normalize_path()
        the path checker uses and every mode must be READ or WRITE, so a
        grant can never be created with a path the checker would deny
        structurally. Raises ValueError on any invalid input.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")
        if not items:
            raise ValueError("items must be a non-empty list")
        if self.allowed_instances is not None and instance not in self.allowed_instances:
            raise ValueError(f"unknown instance: {instance!r}")
        clean_items = []
        for item in items:
            path = item.get("path")
            mode = item.get("mode")
            if mode not in (READ, WRITE):
                raise ValueError(f"invalid mode: {mode!r}")
            norm = normalize_path(path)
            if norm is None:
                raise ValueError(f"invalid path: {path!r}")
            clean_items.append({"path": norm, "mode": mode})
        now = self._now()
        cur = self._db.execute(
            "INSERT INTO grants (instance, reason, items, created_at, state, state_source)"
            " VALUES (?,?,?,?,?,NULL)",
            (instance, reason.strip(), json.dumps(clean_items), _iso(now), PENDING),
        )
        self._db.commit()
        return self._get_row(cur.lastrowid)  # type: ignore[arg-type]  # lastrowid is int here

    def _assert_pending(self, rid: int):
        """One-time-use guard for decision transitions.

        Raises LookupError for unknown ids and ValueError for any grant
        already in a decided state (including effective-expired pending).
        Returns the raw row only when the transition may proceed; every
        approve/reject/revoke path funnels through this so a decided
        request number can never be re-decided.
        """
        row = self._row(rid)
        if row is None:
            raise LookupError(f"no grant with id {rid}")
        if self._state(row) in _DECIDED:
            raise ValueError(f"grant {rid} already decided ({self._state(row)})")
        return row

    def approve(self, rid: int, expiry: str | None = None, item_numbers=None) -> GrantRecord:
        """The human yes: pending -> active, the ONLY transition that can
        create an active grant.

        expiry: duration string ('8h'/'30m'/'2d') or None for the default
        duration. The expiry timestamp is computed once here and written
        immediately - no auto-renewal ever touches it again. item_numbers:
        optional 1-based subset of the request's items to approve;
        approving an empty subset records the whole batch as rejected
        (state_source='partial_empty'). Raises ValueError for invalid
        numbers or an already-decided request.
        """
        # _assert_pending raises "already decided (expired)" for expired
        # pending requests, so no separate expired check is needed here.
        row = self._assert_pending(rid)
        duration = parse_expiry(expiry) or self._default_duration
        items = json.loads(row["items"])
        if item_numbers is not None:
            chosen = []
            for n in item_numbers:
                if not isinstance(n, int) or n < 1 or n > len(items):
                    raise ValueError(f"invalid item number: {n!r}")
                chosen.append(items[n - 1])
            if not chosen:
                # approving an empty subset is a rejection of the whole batch
                self._db.execute(
                    "UPDATE grants SET state=?, decided_at=?, state_source=? WHERE id=?",
                    (REJECTED, _iso(self._now()), "partial_empty", rid),
                )
                self._db.commit()
                return self._get_row(rid)
            items = chosen
        now = self._now()
        self._db.execute(
            "UPDATE grants SET items=?, state=?, decided_at=?, expires_at=?,"
            " state_source=? WHERE id=?",
            (json.dumps(items), ACTIVE, _iso(now), _iso(now + duration), "approval", rid),
        )
        self._db.commit()
        return self._get_row(rid)

    def reject(self, rid: int) -> GrantRecord:
        """The human no: pending -> rejected (state_source='rejection').

        Raises the same errors as approve() via _assert_pending; a
        rejected number is final and can never be re-approved.
        """
        self._assert_pending(rid)
        self._db.execute(
            "UPDATE grants SET state=?, decided_at=?, state_source=? WHERE id=?",
            (REJECTED, _iso(self._now()), "rejection", rid),
        )
        self._db.commit()
        return self._get_row(rid)

    def revoke(self, rid: int) -> GrantRecord:
        """Withdraw a grant early, at any point before its natural end.

        pending -> rejected (state_source='pending_revoke') and
        active -> revoked (state_source='revocation'). Unlike
        approve/reject this does NOT require the pending state: revoking
        a live grant is the operator kill switch and must always work.
        Raises LookupError for unknown ids and ValueError for grants
        already in a terminal state.
        """
        row = self._row(rid)
        if row is None:
            raise LookupError(f"no grant with id {rid}")
        effective = self._state(row)
        if effective == PENDING:
            self._db.execute(
                "UPDATE grants SET state=?, decided_at=?, state_source=? WHERE id=?",
                (REJECTED, _iso(self._now()), "pending_revoke", rid),
            )
        elif effective == ACTIVE:
            self._db.execute(
                "UPDATE grants SET state=?, state_source=? WHERE id=?",
                (REVOKED, "revocation", rid),
            )
        else:
            raise ValueError(f"grant {rid} already decided ({effective})")
        self._db.commit()
        return self._get_row(rid)

    # ---------------------------------------------------------------- reading

    def _row(self, rid: int):
        cur = self._db.execute("SELECT * FROM grants WHERE id=?", (rid,))
        return cur.fetchone()

    def _state(self, row) -> str:
        """Effective state: applies time-based transitions on read.

        Pending rows expire after pending_timeout; active rows expire at
        expires_at. Nothing is written here - expiry is a read-time view,
        so an expired grant is denied by _get_row/active_grants() even
        though the stored state column still says pending/active.
        """
        if row["state"] == PENDING:
            created = _from_iso(row["created_at"])
            if self._now() - created >= self._pending_timeout:
                return EXPIRED
            return PENDING
        if row["state"] == ACTIVE:
            expires = _from_iso(row["expires_at"])
            if self._now() >= expires:
                return EXPIRED
            return ACTIVE
        return row["state"]

    def _get_row(self, rid: int) -> GrantRecord:
        """Load one row and return it as an effective-state GrantRecord.

        Raises LookupError when the id is unknown (never returns None).
        When the effective state is expired but the stored state is not,
        the state_source is synthesized ('pending_timeout' or
        'grant_expiry') so audit trails always name why a grant died.
        """
        row = self._row(rid)
        if row is None:
            raise LookupError(f"no grant with id {rid}")
        effective = self._state(row)
        source = row["state_source"]
        if effective == EXPIRED and row["state"] == PENDING:
            source = "pending_timeout"
        elif effective == EXPIRED and row["state"] == ACTIVE:
            source = "grant_expiry"
        import copy

        return GrantRecord(
            id=row["id"],
            instance=row["instance"],
            reason=row["reason"],
            items=copy.deepcopy(json.loads(row["items"])),
            state=effective,
            expires_at=_from_iso(row["expires_at"]) if row["expires_at"] else None,
            created_at=_from_iso(row["created_at"]),
            state_source=source,
        )

    def get(self, rid: int) -> GrantRecord:
        """Fetch one grant by id, effective state applied.

        Raises LookupError for unknown ids (never returns None).
        """
        return self._get_row(rid)

    def active_grants(self, instance: str | None = None) -> list[GrantRecord]:
        """All grants currently effective-ACTIVE, as GrantRecords, optionally
        filtered by instance. Output feeds the path checker via broker.paths.

        Invariant: every returned record re-checks effective state via
        _get_row, so a grant that expired between the SQL query and this
        read is dropped rather than handed to the checker.
        """
        cur = self._db.execute(
            "SELECT * FROM grants WHERE state=? ORDER BY id", (ACTIVE,)
        )
        out = []
        for row in cur.fetchall():
            if instance is not None and row["instance"] != instance:
                continue
            rec = self._get_row(row["id"])
            if rec.state == ACTIVE:
                out.append(rec)
        return out

    def summary(self, now: datetime | None = None) -> str:
        """Human-readable status block: active grants with time remaining,
        pending request count. Shown in the Matrix room after decisions."""
        lines = []
        for rec in self.active_grants():
            assert rec.expires_at is not None  # active grants always have expiry
            remaining = rec.expires_at - (now or self._now())
            hours = remaining.total_seconds() / 3600
            paths = ", ".join(f"{i['mode'].upper()} {i['path']}" for i in rec.items)
            lines.append(
                f"Grant #{rec.id} active - {rec.instance} - {paths} - {hours:.0f}h left"
            )
        cur = self._db.execute("SELECT COUNT(*) c FROM grants WHERE state=?", (PENDING,))
        pending = cur.fetchone()["c"]
        if lines:
            lines.append(f"Pending: {pending}")
        else:
            lines.append("No active grants." + (f" Pending: {pending}" if pending else " Pending: none"))
        return "\n".join(lines)

    def all_records(self) -> list[GrantRecord]:
        """Every request id known to the store, any state. The bot uses
        this to distinguish 'unknown request' from 'already decided'."""
        cur = self._db.execute("SELECT id FROM grants ORDER BY id")
        return [self._get_row(row["id"]) for row in cur.fetchall()]

    def pending_records(self) -> list[GrantRecord]:
        """Requests stored as pending; effective state (pending_timeout)
        is applied by get()."""
        cur = self._db.execute("SELECT id FROM grants WHERE state=? ORDER BY id", (PENDING,))
        return [self._get_row(row["id"]) for row in cur.fetchall()]

    # ------------------------------------------------- posted-message mapping

    def record_posted(self, event_id: str, request_id: int):
        """Persist the Matrix event id that carries a request, so ANY
        process (or a restarted one) can map reactions to requests.

        M-2 fix (see review findings): plain INSERT - a duplicate event id
        raises loudly (sqlite3.IntegrityError) instead of silently
        rebinding an event to a different request. A malicious or buggy
        client replaying an event id therefore cannot hijack the
        approval routing.
        """
        # M-2 fix: plain INSERT - a duplicate event id raises loudly
        # instead of silently rebinding to a different request.
        self._db.execute(
            "INSERT INTO posted_messages (event_id, request_id) VALUES (?, ?)",
            (event_id, request_id),
        )
        self._db.commit()

    def request_for_event(self, event_id: str) -> int | None:
        """Map a Matrix reaction event's parent id back to a request id.

        Returns None when the event id was never posted (unknown
        reaction); the bot must treat None as 'no such request', never
        as a default target.
        """
        cur = self._db.execute(
            "SELECT request_id FROM posted_messages WHERE event_id=?", (event_id,)
        )
        row = cur.fetchone()
        return row["request_id"] if row else None