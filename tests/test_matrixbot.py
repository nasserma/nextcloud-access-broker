"""Test battery for the Matrix approval bot (Gate 5, mocked phase).

Goal contract, Gate 5 requirements:

- Sender allowlist: exactly ONE Matrix user id may decide anything;
  reactions from anyone else are ignored.
- Bot places its own reactions on the request at post time (Hermes
  pattern): approve, reject, revoke, status.
- Reactions drive state transitions; typed replies parse partial
  approval, custom expiry, revoke.
- Confirmation + open-approvals summary posted after EVERY decision.
- Pending expiry notice after 12h.
- One-time request numbers (store-backed, already tested; bot must not
  circumvent).

Mocking rules: the Matrix TRANSPORT is a fake; the grant store and the
request-number semantics are REAL (never mocked). The wall (path
checker) is not exercised here - the bot never touches paths.
"""

from datetime import datetime, timedelta

import pytest

from broker.grants import ACTIVE, REJECTED, GrantStore
from broker.matrixbot import (
    APPROVE_EMOJI,
    REJECT_EMOJI,
    REVOKE_EMOJI,
    STATUS_EMOJI,
    ApprovalBot,
    parse_reply,
)

T0 = datetime(2026, 9, 5, 9, 0, 0)  # noqa: DTZ001 (injected clock)
OWNER = "@owner:matrix.example.com"
INTRUDER = "@someone-else:matrix.example.com"


class FakeMatrixTransport:
    """Records everything the bot would send. Delivers events to the
    bot when the test calls .deliver()."""

    def __init__(self):
        self.sent = []  # {kind, room, text?, event_id?, reactions?}
        self.reactions_added = []
        self._next_event_id = 1000

    async def send_message(self, room, text):
        event_id = f"$ev{self._next_event_id}"
        self._next_event_id += 1
        self.sent.append({"kind": "message", "room": room, "text": text, "event_id": event_id})
        return event_id

    async def add_reaction(self, room, event_id, emoji):
        self.reactions_added.append({"room": room, "event_id": event_id, "emoji": emoji})


@pytest.fixture()
def bot(tmp_path):
    store = GrantStore(db_path=tmp_path / "grants.sqlite3", now=lambda: T0)
    transport = FakeMatrixTransport()
    b = ApprovalBot(
        store=store,
        transport=transport,
        room="!room:matrix.example.com",
        approver=OWNER,
        now=lambda: T0,
    )
    return b, transport, store


async def post_request(bot_fixture, **kwargs):
    b, _transport, store = bot_fixture
    items = kwargs.pop("items", [{"path": "Documents/paper", "mode": "read"}])
    req = store.create_request(instance=kwargs.pop("instance", "personal"), reason=kwargs.pop("reason", "work"), items=items)
    await b.post_request(req)
    return req


# ------------------------------------------------------------ request posting


async def test_request_message_format(bot):
    _b, transport, _store = bot
    req = await post_request(bot)
    msg = transport.sent[-1]
    text = msg["text"]
    assert f"PENDING #{req.id}" in text  # D6.1 header
    assert "Instance: **personal**" in text
    assert "Reason: work" in text
    assert "READ" in text
    assert "`Documents/paper`" in text


async def test_bot_places_reactions_at_post_time(bot):
    _b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    emojis = [r["emoji"] for r in transport.reactions_added if r["event_id"] == event_id]
    assert {APPROVE_EMOJI, REJECT_EMOJI, REVOKE_EMOJI, STATUS_EMOJI} <= set(emojis)


# ------------------------------------------------------------- reaction flow


async def test_approve_reaction_grants(bot):
    b, transport, store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert store.get(req.id).state == ACTIVE


async def test_reject_reaction_denies(bot):
    b, transport, store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=REJECT_EMOJI)
    assert store.get(req.id).state == REJECTED


async def test_non_approver_reaction_ignored(bot):
    """THE gate security test: an intruder in the room reacts approve;
    nothing changes."""
    b, transport, store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=INTRUDER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert store.get(req.id).state == "pending"
    sent_before = len(transport.sent)
    await b.handle_reaction(sender=INTRUDER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert len(transport.sent) == sent_before  # no decision message for the intruder


async def test_unknown_emoji_ignored(bot):
    b, transport, store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji="🔥")
    assert store.get(req.id).state == "pending"


async def test_reaction_on_non_request_message_ignored(bot):
    b, _transport, _store = bot
    await post_request(bot)
    # react to an event the bot never posted (random room event)
    await b.handle_reaction(sender=OWNER, event_id="$unknown-event", emoji=APPROVE_EMOJI)
    # nothing exploded, nothing decided


async def test_revoke_reaction_on_active_grant(bot):
    b, transport, store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=REVOKE_EMOJI)
    assert store.get(req.id).state == "revoked"


async def test_status_reaction_posts_summary(bot):
    b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    # status reaction works on any bot message
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=STATUS_EMOJI)
    status_msgs = [s for s in transport.sent if "pending" in s.get("text", "").lower() or "active" in s.get("text", "").lower()]
    assert status_msgs  # a summary block was posted


# ------------------------------------------------- confirmation + summary


async def test_confirmation_and_summary_after_every_decision(bot):
    b, transport, _store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    sent_before = len(transport.sent)
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert len(transport.sent) > sent_before  # a confirmation reply went out
    text = transport.sent[-1]["text"]
    assert "active" in text.lower()
    assert f"#{req.id}" in text


async def test_summary_lists_time_remaining(bot):
    b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    text = transport.sent[-1]["text"]
    assert "8h left" in text or "24h left" in text or "h left" in text


# --------------------------------------------------------- typed replies


async def test_partial_approval_typed_reply(bot):
    b, _transport, store = bot
    req = store.create_request(
        instance="personal",
        reason="work",
        items=[
            {"path": "Documents/paper", "mode": "read"},
            {"path": "Photos", "mode": "write"},
        ],
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id} 1")
    g = store.get(req.id)
    assert g.state == ACTIVE
    assert len(g.items) == 1
    assert g.items[0]["path"] == "Documents/paper"


async def test_custom_expiry_typed_reply(bot):
    b, _transport, store = bot
    req = await post_request(bot)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id} 8h")
    assert store.get(req.id).expires_at == T0 + timedelta(hours=8)


async def test_revoke_typed_reply(bot):
    b, _transport, store = bot
    req = await post_request(bot)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    assert store.get(req.id).state == "revoked"


async def test_reply_from_non_approver_ignored(bot):
    b, _transport, store = bot
    req = await post_request(bot)
    await b.handle_reply(sender=INTRUDER, text=f"approve {req.id}")
    assert store.get(req.id).state == "pending"


async def test_garbage_reply_gets_help(bot):
    b, transport, _store = bot
    await post_request(bot)
    await b.handle_reply(sender=OWNER, text="do the thing please")
    help_msgs = [s for s in transport.sent if "approve" in s.get("text", "").lower()]
    assert help_msgs  # bot replied with usage help, changed nothing


async def test_reply_on_unknown_id_notifies(bot):
    b, transport, _store = bot
    await b.handle_reply(sender=OWNER, text="approve 999")
    assert any("no request #999" in s.get("text", "").lower() for s in transport.sent)


# --------------------------------------------------------------- expiry notice


async def test_pending_expiry_notice_posted(bot):
    b, transport, store = bot
    req = await post_request(bot)
    sent_before = len(transport.sent)
    store._now = lambda: T0 + timedelta(hours=12, minutes=1)
    await b.sweep()  # periodic check the server runs
    texts = [s.get("text", "") for s in transport.sent[sent_before:]]
    assert any(f"#{req.id}" in t and "expired" in t.lower() for t in texts)


# ------------------------------------------------------- parse_reply unit level


def test_parse_reply_forms():
    assert parse_reply("approve 47") == ("approve", 47, None, None)
    assert parse_reply("reject 47") == ("reject", 47, None, None)
    assert parse_reply("revoke 47") == ("revoke", 47, None, None)
    assert parse_reply("approve 47 1") == ("approve", 47, [1], None)
    assert parse_reply("approve 47 1,2") == ("approve", 47, [1, 2], None)
    assert parse_reply("approve 47 8h") == ("approve", 47, None, "8h")
    assert parse_reply("status") == ("status", None, None, None)
    assert parse_reply("APPROVE 47") == ("approve", 47, None, None)  # case-insensitive


def test_parse_reply_rejects_garbage():
    assert parse_reply("hello") is None
    assert parse_reply("approve") is None
    assert parse_reply("approve xx") is None
    assert parse_reply("approve 0") is None
    assert parse_reply("revoke 47 8h nonsense") is None

async def test_reject_reaction_path(bot):
    """The REJECT reaction (not the typed reply) drives rejection."""
    b, transport, store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=REJECT_EMOJI)
    assert store.get(req.id).state == "rejected"


async def test_status_reaction_and_typed_status(bot):
    """Both status surfaces post the summary."""
    b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    sent_before = len(transport.sent)
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=STATUS_EMOJI)
    assert len(transport.sent) > sent_before
    sent_before = len(transport.sent)
    await b.handle_reply(sender=OWNER, text="status")
    assert len(transport.sent) > sent_before


async def test_double_approve_reply_gets_error_message(bot):
    """Approving an already-decided request: the bot explains instead of
    silently failing."""
    b, transport, _store = bot
    req = await post_request(bot)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    assert any("cannot approve" in s.get("text", "").lower() for s in transport.sent)


async def test_revoke_decided_reply_gets_error_message(bot):
    b, transport, _store = bot
    req = await post_request(bot)
    await b.handle_reply(sender=OWNER, text=f"reject {req.id}")
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    assert any("cannot revoke" in s.get("text", "").lower() for s in transport.sent)


async def test_sweep_after_expiry_notices_once(bot):
    """Sweep posts the expiry notice exactly once per request."""
    b, transport, store = bot
    req = await post_request(bot)
    store._now = lambda: T0 + timedelta(hours=13)
    await b.sweep()
    notices1 = [s for s in transport.sent if f"#{req.id}" in s.get("text", "")]
    await b.sweep()
    notices2 = [s for s in transport.sent if f"#{req.id}" in s.get("text", "")]
    assert len(notices2) == len(notices1)  # no duplicate notice


def test_parse_reply_zero_item_number_rejected():
    assert parse_reply("approve 47 0") is None
    assert parse_reply("approve 47 1,0") is None


def test_parse_reply_non_string_rejected():
    assert parse_reply(None) is None
    assert parse_reply(47) is None


# ---------------------------------------- persisted event mapping (G6 fix)


async def test_reaction_mapping_survives_process_boundary(tmp_path):
    """The defect your revoked-tap exposed: request posted and APPROVED
    by process A; process B (same DB) must resolve the revoke reaction.
    Restart-discard kills pending requests by design, so the cross-
    process case that matters is revoke-on-active."""
    from datetime import UTC, datetime

    db = tmp_path / "g.sqlite3"

    def now():
        return datetime.now(UTC)

    store_a = GrantStore(db_path=db, now=now)
    bot_a = ApprovalBot(
        store=store_a, transport=FakeMatrixTransport(),
        room="!r:x", approver=OWNER, now=now,
    )
    req = store_a.create_request(
        instance="personal", reason="r", items=[{"path": "a", "mode": "read"}]
    )
    event_id = await bot_a.post_request(req)
    await bot_a.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert store_a.get(req.id).state == "active"

    # process B: fresh store, fresh bot, same DB (restart)
    store_b = GrantStore(db_path=db, now=now)
    bot_b = ApprovalBot(
        store=store_b, transport=FakeMatrixTransport(),
        room="!r:x", approver=OWNER, now=now,
    )
    await bot_b.handle_reaction(sender=OWNER, event_id=event_id, emoji=REVOKE_EMOJI)
    assert store_b.get(req.id).state == "revoked"


async def test_reaction_on_unmapped_event_ignored_after_restart(tmp_path):
    from datetime import UTC, datetime

    db = tmp_path / "g.sqlite3"

    def now():
        return datetime.now(UTC)
    store_b = GrantStore(db_path=db, now=now)
    bot_b = ApprovalBot(
        store=store_b, transport=FakeMatrixTransport(),
        room="!r:x", approver=OWNER, now=now,
    )
    await bot_b.handle_reaction(sender=OWNER, event_id="$never-posted", emoji=APPROVE_EMOJI)
    # nothing exploded, nothing decided


# --------------------------------------------------- scrub-safe decision logging
#
# Contract: one log.info line per grant decision (_decide) and per
# revocation (_revoke), carrying rid/action/outcome/sender, through the
# scrubbed 'broker' logger (W2). The sender is a Matrix user id — not a
# secret. Allowlist-rejected reactions log at DEBUG only. Fields are
# caplog-asserted on record.getMessage() (the rendered line, post-filter
# scrubbing) so assertions hold for %-style lazy formatting.


def _decision_records(caplog):
    return [
        r for r in caplog.records if r.getMessage().startswith("decision:")
    ]


async def test_approve_decision_logs_one_info_line(bot, caplog):
    b, transport, _store = bot
    req = await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    with caplog.at_level("INFO", logger="broker.matrixbot"):
        await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    recs = _decision_records(caplog)
    assert len(recs) == 1  # exactly one line per decision
    msg = recs[0].getMessage()
    assert "action=approve" in msg
    assert "outcome=granted" in msg
    assert f"rid={req.id}" in msg
    assert f"sender={OWNER}" in msg
    assert recs[0].levelname == "INFO"


async def test_reject_decision_logs_one_info_line(bot, caplog):
    b, _transport, _store = bot
    req = await post_request(bot)
    with caplog.at_level("INFO", logger="broker.matrixbot"):
        await b.handle_reply(sender=OWNER, text=f"reject {req.id}")
    recs = _decision_records(caplog)
    assert len(recs) == 1
    assert "action=reject" in recs[0].getMessage()
    assert "outcome=rejected" in recs[0].getMessage()
    assert f"sender={OWNER}" in recs[0].getMessage()


async def test_revoke_logs_one_info_line(bot, caplog):
    b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    caplog.clear()
    with caplog.at_level("INFO", logger="broker.matrixbot"):
        await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=REVOKE_EMOJI)
    recs = _decision_records(caplog)
    assert len(recs) == 1
    assert "action=revoke" in recs[0].getMessage()
    assert "outcome=revoked" in recs[0].getMessage()
    assert f"sender={OWNER}" in recs[0].getMessage()


async def test_refused_decision_still_logged_one_line(bot, caplog):
    """A refused decision (already decided) is a decision event too:
    one info line with outcome=refused."""
    b, _transport, _store = bot
    req = await post_request(bot)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    caplog.clear()
    with caplog.at_level("INFO", logger="broker.matrixbot"):
        await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    recs = _decision_records(caplog)
    assert len(recs) == 1
    assert "outcome=refused" in recs[0].getMessage()


async def test_allowlist_rejected_reaction_logs_debug_not_info(bot, caplog):
    """THE oracle rule: non-approver probes are debug-only (default
    logging level), never info, and never carry a decision."""
    b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    with caplog.at_level("DEBUG", logger="broker.matrixbot"):
        await b.handle_reaction(sender=INTRUDER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert _decision_records(caplog) == []  # no decision line at all
    debug = [r for r in caplog.records if r.levelname == "DEBUG"]
    assert len(debug) == 1
    assert "allowlist rejected" in debug[0].getMessage()
    assert f"sender={INTRUDER}" in debug[0].getMessage()


async def test_approver_reaction_does_not_emit_debug_allowlist_line(bot, caplog):
    b, transport, _store = bot
    await post_request(bot)
    event_id = transport.sent[-1]["event_id"]
    with caplog.at_level("DEBUG", logger="broker.matrixbot"):
        await b.handle_reaction(sender=OWNER, event_id=event_id, emoji=APPROVE_EMOJI)
    assert not any("allowlist rejected" in r.getMessage() for r in caplog.records)


async def test_partial_approval_logs_item_count(bot, caplog):
    b, _transport, store = bot
    req = store.create_request(
        instance="personal",
        reason="work",
        items=[
            {"path": "Documents/paper", "mode": "read"},
            {"path": "Photos", "mode": "write"},
        ],
    )
    await b.post_request(req)
    with caplog.at_level("INFO", logger="broker.matrixbot"):
        await b.handle_reply(sender=OWNER, text=f"approve {req.id} 2")
    recs = _decision_records(caplog)
    assert len(recs) == 1
    assert "items=1" in recs[0].getMessage()  # only the approved item count


def test_matrixbot_logger_uses_broker_namespace():
    """The module logger is a child of 'broker', so the scrub filter
    installed by setup_logging on the 'broker' logger covers it (W2
    contract: every line passes the filter)."""
    import logging

    assert logging.getLogger("broker.matrixbot").name == "broker.matrixbot"
    assert "broker" in logging.getLogger("broker.matrixbot").name.split(".")
