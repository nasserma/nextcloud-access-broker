"""D6.2 status-command-footer tests (user-requested Sept 7 2026).

The status block ends with ONE line naming the commands that act on
the content above it — only when there is content. An empty room
(nothing active, nothing pending) gets no footer: no commands when
there is nothing to command.
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


async def status_text(env):
    b, t, _store = env
    await b._post_summary()
    return t.sent[-1]["text"]


async def test_footer_present_with_active_grant(env):
    b, _t, store = env
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    text = await status_text(env)
    assert "Kill: `revoke <id>`" in text
    assert "Revise: `undo <id>` (15s)" in text
    # nothing pending → NO decide segment
    assert "approve|reject" not in text
    # exactly one footer line
    footer = [ln for ln in text.split("\n") if "revoke <id>" in ln]
    assert len(footer) == 1


async def test_footer_present_with_pending_request(env):
    b, _t, store = env
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    await b.post_request(req)
    text = await status_text(env)
    assert "Decide a request: `approve|reject <id> [expiry]`" in text
    # nothing active → NO revise/kill segment
    assert "revoke" not in text


async def test_footer_absent_when_room_empty(env):
    _b, _t, _store = env
    text = await status_text(env)
    assert "**Active grants**\nnone" in text
    assert "revoke" not in text  # nothing to command, no command line


async def test_confirmation_blocks_carry_footer_too(env):
    """Every rendered status block (including post-decision refreshes)
    ends with the footer — that is where the owner actually is. After
    an approval, only the revise/kill segment (nothing pending)."""
    b, t, store = env
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    text = t.sent[-1]["text"]
    assert "Kill: `revoke <id>`" in text


async def test_footer_both_segments_when_both_present(env):
    """Active grant AND pending request → one line, both segments."""
    b, _t, store = env
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    other = store.create_request(instance="personal", reason="r", items=[{"path": "b", "mode": "read"}])
    await b.post_request(other)
    text = await status_text(env)
    footer = [ln for ln in text.split("\n") if "Decide a request" in ln]
    assert len(footer) == 1
    assert "Decide a request" in footer[0]
    assert "Kill: `revoke <id>`" in footer[0]
    assert "Revise: `undo <id>`" in footer[0]


async def test_request_message_footer_decide_only(env):
    """The pending-request message footer names ONLY the commands that
    act on it: approve/reject. No revoke/undo there (nothing to kill
    or revise yet)."""
    b, t, store = env
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    await b.post_request(req)
    text = t.sent[-1]["text"]
    assert "Decide: `approve|reject <id> [expiry]`" in text
    assert "undo" not in text
    assert "revoke" not in text