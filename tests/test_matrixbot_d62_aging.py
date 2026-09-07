"""D6.2 aging-marker tests (#8, user-approved Sept 7 2026).

The Awaiting-your-approval section marks pending request age:
- < 1h: unchanged ("waiting 23m")
- >= 1h: appends the wall-clock creation time ("waiting 1h (since 09:00)")
- >= 4h: adds a bold stale flag ("— stale?")

Display only: no state changes, no early expiry, no auto-nudging
(nudging cadence is D6.3, separate decision).
"""

from datetime import datetime, timedelta

import pytest

from broker.grants import GrantStore
from broker.matrixbot import ApprovalBot

T0 = datetime(2026, 9, 7, 9, 0, 0)  # noqa: DTZ001
OWNER = "@owner:matrix.example.com"


class FakeTransport:
    def __init__(self):
        self.sent = []
        self._n = 1000

    async def send_message(self, room, text):
        eid = f"$ev{self._n}"
        self._n += 1
        self.sent.append({"room": room, "text": text, "event_id": eid})
        return eid

    async def add_reaction(self, room, event_id, emoji):
        pass


@pytest.fixture()
def env(tmp_path):
    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    transport = FakeTransport()
    bot = ApprovalBot(store=store, transport=transport, room="!r:x", approver=OWNER, now=lambda: T0)
    return bot, transport, store


def seed_pending(store):
    return store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )


async def status_text(env):
    b, t, _store = env
    await b._post_summary()
    return t.sent[-1]["text"]


async def test_young_pending_has_no_marker(env):
    _b, _t, store = env
    seed_pending(store)
    text = await status_text(env)
    assert "waiting 0m" in text
    assert "(since" not in text
    assert "stale" not in text


async def test_pending_over_one_hour_shows_since_time(env):
    b, _t, store = env
    seed_pending(store)
    b._now = lambda: T0 + timedelta(hours=1)
    text = await status_text(env)
    # format_remaining shows 60m (minutes below 2h) — the marker is the point
    assert "waiting 60m" in text
    assert "(since 09:00)" in text
    assert "stale" not in text


async def test_pending_over_four_hours_flagged_stale(env):
    b, _t, store = env
    seed_pending(store)
    b._now = lambda: T0 + timedelta(hours=4)
    text = await status_text(env)
    assert "waiting 4h" in text
    assert "(since 09:00)" in text
    assert "**stale?**" in text


async def test_aging_is_display_only(env):
    """No state transitions from aging: the request is still pending,
    and the store's own 12h expiry semantics are untouched."""
    b, _t, store = env
    req = seed_pending(store)
    b._now = lambda: T0 + timedelta(hours=5)
    await status_text(env)
    assert store.get(req.id).state == "pending"


async def test_mixed_ages_each_marked_individually(env):
    b, _t, store = env
    seed_pending(store)  # seeded at T0 — will be 2h old
    b._now = lambda: T0 + timedelta(hours=2)
    store._now = lambda: T0 + timedelta(hours=2)
    store.create_request(instance="personal", reason="r", items=[{"path": "b", "mode": "read"}])  # 0h old
    text = await status_text(env)
    line_old = next(ln for ln in text.split("\n") if "#1" in ln and "⏳" in ln)
    line_new = next(ln for ln in text.split("\n") if "#2" in ln and "⏳" in ln)
    assert "(since" in line_old
    assert "(since" not in line_new
    assert "waiting 2h" in line_old
    assert "waiting 0m" in line_new