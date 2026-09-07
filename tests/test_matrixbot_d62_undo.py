"""D6.2-undo tests (#7, user-approved Sept 7 2026 with 15s grace).

Design: reject/revoke confirmations offer `undo <id>` for 15 seconds.
Undo NEVER resurrects the decided number — it creates a NEW pending
request (same instance/items/reason) through the ordinary posted flow,
so one-time numbers stay sacred and the approval path is unchanged.
Expired or absent windows refuse; a second undo of the same id refuses
(deadline consumed on first use). Undo is in-memory: a restart inside
the 15s window loses the chance — acceptable, the restart also
restart-discard'd the original decision context.
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
        self.reactions_added = []
        self._n = 1000

    async def send_message(self, room, text):
        eid = f"$ev{self._n}"
        self._n += 1
        self.sent.append({"room": room, "text": text, "event_id": eid})
        return eid

    async def add_reaction(self, room, event_id, emoji):
        self.reactions_added.append({"event_id": event_id, "emoji": emoji})


@pytest.fixture()
def env(tmp_path):
    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    transport = FakeTransport()
    bot = ApprovalBot(store=store, transport=transport, room="!r:x", approver=OWNER, now=lambda: T0)
    return bot, transport, store


async def seed_approved(env):
    b, t, store = env
    req = store.create_request(
        instance="personal", reason="work", items=[{"path": "Documents/paper", "mode": "read"}]
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    t.sent.clear()
    return req


async def test_revoke_confirmation_offers_undo(env):
    b, t, _store = env
    req = await seed_approved(env)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    text = t.sent[-1]["text"]
    assert "Revoked" in text
    assert f"undo {req.id}" in text
    assert "15s" in text


async def test_reject_confirmation_offers_undo(env):
    b, t, store = env
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"reject {req.id}")
    assert f"undo {req.id}" in t.sent[-1]["text"]


async def test_undo_within_grace_creates_new_pending_request(env):
    b, t, store = env
    req = await seed_approved(env)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    t.sent.clear()
    await b.handle_reply(sender=OWNER, text=f"undo {req.id}")
    # a NEW pending request exists, same instance/items
    pendings = store.pending_records()
    assert len(pendings) == 1
    new = pendings[0]
    assert new.id != req.id  # one-time numbers: the dead id stays dead
    assert new.instance == "personal"
    assert new.items[0]["path"] == "Documents/paper"
    # the new request was POSTED to the room through the normal flow
    assert any(f"PENDING #{new.id}" in s["text"] for s in t.sent)


async def test_undo_after_grace_refuses(env):
    b, t, store = env
    req = await seed_approved(env)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    b._now = lambda: T0 + timedelta(seconds=16)
    t.sent.clear()
    await b.handle_reply(sender=OWNER, text=f"undo {req.id}")
    assert any("closed" in s["text"] for s in t.sent)
    assert store.pending_records() == []


async def test_undo_is_one_shot(env):
    """First undo consumes the grace; the second refuses."""
    b, t, store = env
    req = await seed_approved(env)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    await b.handle_reply(sender=OWNER, text=f"undo {req.id}")
    first_pending = store.pending_records()[0].id
    await b.handle_reply(sender=OWNER, text=f"undo {req.id}")
    assert any("closed" in s["text"] for s in t.sent)
    assert len(store.pending_records()) == 1
    assert store.pending_records()[0].id == first_pending


async def test_undo_unknown_id_refuses_cleanly(env):
    b, t, store = env
    await b.handle_reply(sender=OWNER, text="undo 42")
    assert any("no undo" in s["text"].lower() or "closed" in s["text"].lower() for s in t.sent)
    assert store.pending_records() == []


async def test_undo_of_approved_request_not_offered(env):
    """Undo exists for reject/revoke mistakes. Approve is not a mistake
    shape — revoking already covers it — so no undo line there."""
    b, t, store = env
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    body = t.sent[-1]["text"]
    # the verb-first head carries no undo offer; only the footer names undo
    assert not body.startswith("**Approved") or "Mistake?" not in body
    assert "undo <id>" in body  # footer vocabulary
    assert f"undo {req.id}" not in body  # but no id-targeted undo offer


async def test_undo_preserves_full_item_list_of_revoked_grant(env):
    b, _t, store = env
    req = store.create_request(
        instance="personal",
        reason="r",
        items=[
            {"path": "Documents/paper", "mode": "read"},
            {"path": "Documents/photos", "mode": "write"},
        ],
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    await b.handle_reply(sender=OWNER, text=f"undo {req.id}")
    new = store.pending_records()[0]
    assert {i["mode"] for i in new.items} == {"read", "write"}


async def test_undo_from_non_approver_ignored(env):
    b, t, store = env
    req = await seed_approved(env)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    t.sent.clear()
    await b.handle_reply(sender="@intruder:x", text=f"undo {req.id}")
    assert t.sent == []
    assert store.pending_records() == []