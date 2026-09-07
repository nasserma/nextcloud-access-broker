"""D6.2 group-by-instance tests (#9, user-approved Sept 7 2026).

Status block layout: with ONE active instance the output is unchanged
(no header tax for a single group). With MULTIPLE active instances,
grants group under per-instance headers and the instance name drops
from each grant line (it names the group).

Pending (Awaiting your approval) stays flat: pending requests are
rarely numerous and their lines are short.
"""

from datetime import datetime

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


async def grant(env, instance):
    b, _t, store = env
    req = store.create_request(
        instance=instance, reason="r", items=[{"path": "a", "mode": "read"}]
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")


async def status_text(env):
    b, t, _store = env
    await b._post_summary()
    return t.sent[-1]["text"]


async def test_single_instance_status_unchanged(env):
    """No group headers when everything is on one instance."""
    _b, _t, _store = env
    await grant(env, "personal")
    text = await status_text(env)
    assert "**Active grants**" in text
    assert "✅ **#1** — READ, 24h left — personal" in text
    assert text.count("personal:\n") == 0  # no instance headers


async def test_multi_instance_groups_under_headers(env):
    _b, _t, _store = env
    await grant(env, "personal")
    await grant(env, "work")
    text = await status_text(env)
    lines = text.split("\n")
    assert "personal:" in lines
    assert "work:" in lines
    # grant lines carry NO instance suffix when grouped
    line1 = next(ln for ln in lines if "✅ **#1**" in ln)
    line2 = next(ln for ln in lines if "✅ **#2**" in ln)
    assert "— personal" not in line1 and "personal" not in line1
    assert "work" not in line2
    # grouping: header precedes its grant
    assert lines.index("personal:") < lines.index(line1) < lines.index("work:") < lines.index(line2)


async def test_multi_instance_header_order_deterministic(env):
    _b, _t, _store = env
    await grant(env, "work")
    await grant(env, "personal")
    text = await status_text(env)
    lines = text.split("\n")
    assert lines.index("personal:") < lines.index("work:")  # alphabetical


async def test_grouping_switches_by_active_state_not_history(env):
    """Only ACTIVE grants group. A second instance with no active grant
    (rejected/expired) produces no header."""
    b, _t, store = env
    await grant(env, "personal")
    req = store.create_request(
        instance="work", reason="r", items=[{"path": "b", "mode": "read"}]
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"reject {req.id}")
    text = await status_text(env)
    assert "work:" not in text.split("Awaiting")[0]