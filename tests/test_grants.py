"""Test battery for the grant store and lifecycle (Gate 2).

Design document section 3.4 and the goal contract, Gate 2:

- States: pending -> active -> (expired | revoked | rejected).
- Pending requests die at 12h (default, configurable). Silence grants nothing.
- Active grants default to 24h, per-request override via expiry strings
  ("8h", "30m", "2d").
- No auto-renewal, ever.
- Grants survive process restart (SQLite). Pending requests are DISCARDED
  on restart (a stale pending request is worthless).
- Request numbers are one-time: a decided number can never be reused.
- Revocation is immediate and recorded.

The clock is injected everywhere (Clock protocol); no test depends on
real time passing, and no production code calls datetime.now() directly.
"""

from datetime import datetime, timedelta

import pytest

from broker.grants import (
    ACTIVE,
    EXPIRED,
    PENDING,
    REJECTED,
    REVOKED,
    GrantStore,
    parse_expiry,
)

T0 = datetime(2026, 9, 5, 9, 0, 0)  # noqa: DTZ001 (injected clock)


def make_store(tmp_path):
    return GrantStore(db_path=tmp_path / "grants.sqlite3", now=lambda: T0)


# ------------------------------------------------------------ request creation


def test_create_pending_request(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal",
        reason="CHT paper",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    assert req.id == 1
    assert store.get(req.id).state == PENDING
    assert store.get(req.id).items[0]["path"] == "Documents/paper"


def test_pending_request_expires_after_12h_silence(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    # 11h59m later: still pending
    store._now = lambda: T0 + timedelta(hours=11, minutes=59)
    assert store.get(req.id).state == PENDING
    # 12h later: expired, silence granted nothing
    store._now = lambda: T0 + timedelta(hours=12)
    assert store.get(req.id).state == EXPIRED
    assert store.get(req.id).state_source == "pending_timeout"


def test_pending_timeout_configurable(tmp_path):
    store = GrantStore(
        db_path=tmp_path / "g.sqlite3",
        now=lambda: T0,
        pending_timeout=timedelta(hours=1),
    )
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store._now = lambda: T0 + timedelta(minutes=61)
    assert store.get(req.id).state == EXPIRED


# ------------------------------------------------------------------- approval


def test_approve_activates_grant_with_default_24h(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal",
        reason="r",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    store.approve(req.id)
    g = store.get(req.id)
    assert g.state == ACTIVE
    assert g.expires_at == T0 + timedelta(hours=24)


def test_approve_with_custom_expiry_string(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id, expiry="8h")
    assert store.get(req.id).expires_at == T0 + timedelta(hours=8)


def test_partial_approval_grants_only_listed_items(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal",
        reason="r",
        items=[
            {"path": "Documents/paper", "mode": "read"},
            {"path": "Photos", "mode": "write"},
        ],
    )
    store.approve(req.id, item_numbers=[1])
    g = store.get(req.id)
    assert g.state == ACTIVE
    assert len(g.items) == 1
    assert g.items[0]["path"] == "Documents/paper"


def test_partial_approval_with_no_items_is_rejection(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id, item_numbers=[])
    assert store.get(req.id).state == REJECTED


def test_reject(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.reject(req.id)
    assert store.get(req.id).state == REJECTED


def test_expired_pending_cannot_be_approved(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store._now = lambda: T0 + timedelta(hours=13)
    with pytest.raises(ValueError, match="expired"):
        store.approve(req.id)


# ------------------------------------------------------ one-time request numbers


def test_decided_number_never_reusable(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id)
    with pytest.raises(ValueError, match="already decided"):
        store.approve(req.id)


def test_rejected_number_never_reusable(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.reject(req.id)
    with pytest.raises(ValueError, match="already decided"):
        store.approve(req.id)


def test_ids_are_sequential_and_never_recycled_even_after_decisions(tmp_path):
    store = make_store(tmp_path)
    r1 = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.reject(r1.id)
    r2 = store.create_request(
        instance="personal", reason="r", items=[{"path": "b", "mode": "read"}]
    )
    assert r2.id == r1.id + 1


# ------------------------------------------------------------------- revocation


def test_revoke_active_grant(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id)
    store.revoke(req.id)
    g = store.get(req.id)
    assert g.state == REVOKED


def test_revoke_pending_request_rejects_it(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.revoke(req.id)
    assert store.get(req.id).state == REJECTED


def test_revoke_unknown_id_raises(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(LookupError):
        store.revoke(999)


# --------------------------------------------------------------------- expiry


def test_active_grant_expires_at_its_expiry_time(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id, expiry="2h")
    store._now = lambda: T0 + timedelta(hours=1, minutes=59)
    assert store.get(req.id).state == ACTIVE
    store._now = lambda: T0 + timedelta(hours=2)
    assert store.get(req.id).state == EXPIRED
    assert store.get(req.id).state_source == "grant_expiry"


def test_no_auto_renewal_expired_stays_expired(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id, expiry="1h")
    store._now = lambda: T0 + timedelta(hours=5)
    assert store.get(req.id).state == EXPIRED
    assert store.get(req.id).expires_at == T0 + timedelta(hours=1)  # unchanged


# ------------------------------------------------------------------- restart


def test_active_grant_survives_restart_pending_discarded(tmp_path):
    """The core persistence contract. Write with one store, reopen a new
    store on the same file: active grants intact, pending gone."""
    db = tmp_path / "restart.sqlite3"
    s1 = GrantStore(db_path=db, now=lambda: T0)
    r_active = s1.create_request(
        instance="personal",
        reason="keep",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    s1.approve(r_active.id, expiry="24h")
    r_pending = s1.create_request(
        instance="personal",
        reason="drop",
        items=[{"path": "Photos", "mode": "read"}],
    )

    s2 = GrantStore(db_path=db, now=lambda: T0)  # "restart"
    g = s2.get(r_active.id)
    assert g.state == ACTIVE
    assert g.expires_at == T0 + timedelta(hours=24)
    p = s2.get(r_pending.id)
    assert p.state == REJECTED
    assert p.state_source == "restart_discard"


def test_decided_numbers_still_one_time_after_restart(tmp_path):
    db = tmp_path / "onetime.sqlite3"
    s1 = GrantStore(db_path=db, now=lambda: T0)
    r = s1.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    s1.reject(r.id)
    s2 = GrantStore(db_path=db, now=lambda: T0)
    with pytest.raises(ValueError, match="already decided"):
        s2.approve(r.id)


# ------------------------------------------------------------------- listing


def test_active_grants_listing_for_path_checker(tmp_path):
    store = make_store(tmp_path)
    r1 = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(r1.id)
    r2 = store.create_request(
        instance="org", reason="r", items=[{"path": "b", "mode": "write"}]
    )
    store.approve(r2.id, expiry="1h")
    store.create_request(
        instance="personal", reason="r", items=[{"path": "c", "mode": "read"}]
    )  # left pending
    active = store.active_grants(instance="personal")
    assert len(active) == 1
    assert active[0].id == r1.id
    assert active[0].mode == "read"
    assert active[0].path == "a"


def test_summary_block_lists_active_and_pending(tmp_path):
    store = make_store(tmp_path)
    r1 = store.create_request(
        instance="personal",
        reason="paper work",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    store.approve(r1.id, expiry="8h")
    store.create_request(
        instance="org", reason="later", items=[{"path": "proj", "mode": "read"}]
    )
    summary = store.summary(now=T0)
    assert "1" in summary and "active" in summary
    assert "personal" in summary
    assert "pending" in summary.lower()


# ------------------------------------------------------- expiry string parsing


@pytest.mark.parametrize(
    "text,expected",
    [
        ("8h", timedelta(hours=8)),
        ("30m", timedelta(minutes=30)),
        ("2d", timedelta(days=2)),
        ("24h", timedelta(hours=24)),
    ],
)
def test_parse_expiry_valid(text, expected):
    assert parse_expiry(text) == expected


@pytest.mark.parametrize("bad", ["8 hours", "forever", "", "0h", "-1h", "8x", "h8", "8.5h"])
def test_parse_expiry_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_expiry(bad)


def test_parse_expiry_none_returns_none(tmp_path):
    """None (not provided in the reply) means the store default applies."""
    assert parse_expiry(None) is None


# ------------------------------------------------------------- input validation


def test_create_request_rejects_empty_items(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        store.create_request(instance="personal", reason="r", items=[])


def test_create_request_rejects_bad_mode(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        store.create_request(
            instance="personal", reason="r", items=[{"path": "a", "mode": "admin"}]
        )


def test_create_request_rejects_bad_path(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        store.create_request(
            instance="personal",
            reason="r",
            items=[{"path": "../escape", "mode": "read"}],
        )


def test_unknown_instance_rejected_at_creation(tmp_path):
    """Only configured instances exist; an unconfigured instance is an error
    before anything is stored (corporate stays unconfigured by design)."""
    store = make_store(tmp_path)
    store.allowed_instances = {"personal", "org", "work"}
    with pytest.raises(ValueError):
        store.create_request(
            instance="corporate", reason="r", items=[{"path": "a", "mode": "read"}]
        )


def test_create_request_rejects_blank_reason(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="reason"):
        store.create_request(instance="personal", reason="   ", items=[{"path": "a", "mode": "read"}])


def test_close_is_idempotent_enough(tmp_path):
    store = make_store(tmp_path)
    store.close()  # no error


def test_get_unknown_id_raises(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(LookupError):
        store.get(4242)


def test_partial_approval_rejects_out_of_range_item_number(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal",
        reason="r",
        items=[{"path": "a", "mode": "read"}, {"path": "b", "mode": "read"}],
    )
    with pytest.raises(ValueError, match="item number"):
        store.approve(req.id, item_numbers=[1, 9])
    with pytest.raises(ValueError, match="item number"):
        store.approve(req.id, item_numbers=["x"])


def test_revoke_already_decided_grant_raises(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.reject(req.id)
    with pytest.raises(ValueError, match="already decided"):
        store.revoke(req.id)


def test_summary_with_no_active_grants_and_none_pending(tmp_path):
    store = make_store(tmp_path)
    summary = store.summary()
    assert "No active grants" in summary
    assert "Pending: none" in summary


def test_summary_with_no_active_but_pending_present(tmp_path):
    store = make_store(tmp_path)
    store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    summary = store.summary()
    assert "No active grants" in summary
    assert "Pending: 1" in summary


def test_expired_pending_get_raises_via_get_missing(tmp_path):
    """get() on an id that never existed raises LookupError even when the
    store has other rows (covers the _get_row guard)."""
    store = make_store(tmp_path)
    store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    with pytest.raises(LookupError):
        store.get(99)


def test_approve_unknown_id_raises(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(LookupError):
        store.approve(31337)


def test_reject_unknown_id_raises(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(LookupError):
        store.reject(31337)


def test_expired_pending_revoke_is_a_rejection(tmp_path):
    """A pending request that timed out, then revoked: it is decided
    (expired as pending), so revoke raises already-decided."""
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store._now = lambda: T0 + timedelta(hours=13)
    with pytest.raises(ValueError, match="already decided"):
        store.revoke(req.id)


def test_active_grants_excludes_expired_by_time(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    store.approve(req.id, expiry="1h")
    store._now = lambda: T0 + timedelta(hours=2)
    assert store.active_grants(instance="personal") == []
