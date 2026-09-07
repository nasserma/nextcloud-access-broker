"""D6.1 formatting tests: message renderers, markdown transport, help,
unknown-command closest match, expiry display.

Design record: DEVIATIONS.md D6 (items 1). Phone-first (design doc
§3.3): every block must stay readable on a phone width; bold only for
#ids and headers; monospace only where alignment earns it (full grant
table).
"""

import html

from broker.grants import GrantStore
from broker.matrixbot import (
    APPROVE_EMOJI,
    REJECT_EMOJI,
    ApprovalBot,
    closest_command,
    format_remaining,
)

T0 = __import__("datetime").datetime(2026, 9, 7, 9, 0, 0)
OWNER = "@owner:matrix.example.com"

# The fake transport's raw text is the FALLBACK body; the rendered
# markdown the approver sees in Element comes from the HTML the
# production transport derives from it. Tests assert on the text the
# bot hands the transport (the same string the HTML is built from).


class MarkdownTransport:
    """Fake transport recording what the bot sends, as the production
    one would: it derives HTML from the text and records both."""

    def __init__(self):
        self.sent = []  # {room, text, html}
        self.reactions_added = []
        self._next = 1000

    async def send_message(self, room, text):
        from broker.markdown_render import text_to_html

        event_id = f"$ev{self._next}"
        self._next += 1
        self.sent.append(
            {"room": room, "text": text, "html": text_to_html(text), "event_id": event_id}
        )
        return event_id

    async def add_reaction(self, room, event_id, emoji):
        self.reactions_added.append({"room": room, "event_id": event_id, "emoji": emoji})


def make_bot(tmp_path, now=None):
    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=now or (lambda: T0))
    transport = MarkdownTransport()
    b = ApprovalBot(
        store=store, transport=transport, room="!r:x", approver=OWNER, now=now or (lambda: T0)
    )
    return b, transport, store


async def seed_active(b, store, items=None):
    req = store.create_request(
        instance="personal",
        reason="work",
        items=items or [{"path": "Documents/paper", "mode": "read"}],
    )
    await b.post_request(req)
    await b.handle_reply(sender=OWNER, text=f"approve {req.id}")
    return req


# ------------------------------------------------------------- renderers


async def test_request_message_has_pending_header_and_compact_items(tmp_path):
    """The request block: header carries PENDING + #id; each item is
    ONE line — mode bold, then the monospace path (user-corrected
    format, Sept 7 2026: mode and filename are never split across
    lines)."""
    b, transport, store = make_bot(tmp_path)
    req = store.create_request(
        instance="personal",
        reason="CHT paper figures",
        items=[
            {"path": "Documents/paper/figures", "mode": "read"},
            {"path": "Documents/paper/paper.tex", "mode": "write"},
        ],
    )
    await b.post_request(req)
    text = transport.sent[-1]["text"]
    assert "PENDING" in text
    assert f"#{req.id}" in text
    assert "awaiting your approval" in text.lower()
    assert "personal" in text
    assert "CHT paper figures" in text
    # each item is a single line: "N. **MODE** `path`"
    lines = text.split("\n")
    assert "1. **READ** `Documents/paper/figures`" in lines
    assert "2. **WRITE** `Documents/paper/paper.tex`" in lines


async def test_request_markdown_bold_header_and_id(tmp_path):
    """Rendered HTML bolds the #id and the PENDING header, escapes the rest."""
    b, transport, store = make_bot(tmp_path)
    req = store.create_request(
        instance="personal",
        reason="work <script>alert(1)</script>",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    await b.post_request(req)
    h = transport.sent[-1]["html"]
    assert "<strong>" in h and "</strong>" in h
    assert f"#{req.id}" in h
    # script tag must be escaped, never executable
    assert "<script>" not in h
    assert html.escape("<script>alert(1)</script>") in h


async def test_grant_confirmation_verb_first_with_separator(tmp_path):
    """Approve confirmation: verb-first sentence, then separator, then
    refreshed status (Active grants / Awaiting your approval)."""
    b, transport, store = make_bot(tmp_path)
    await seed_active(b, store)
    text = transport.sent[-1]["text"]
    assert text.split("\n")[0].startswith("**Approved #")
    assert "24h" in text  # expiry named in the confirmation
    assert "Active grants" in text
    assert "Awaiting your approval" in text


async def test_reject_and_revoke_confirmations_verb_first(tmp_path):
    b, transport, store = make_bot(tmp_path)
    req = await seed_active(b, store)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    text = transport.sent[-1]["text"]
    assert text.split("\n")[0] == f"**Revoked #{req.id}**."
    # separator then status block
    assert "Active grants" in text


async def test_grant_block_header_carries_modes_and_time_left(tmp_path):
    """Confirmation first line, then the refreshed status whose active-
    grant lines carry the design's '✅ #id — MODES, time left' header."""
    b, transport, store = make_bot(tmp_path)
    await seed_active(b, store)
    text = transport.sent[-1]["text"]
    header = text.split("\n")[0]
    assert header.startswith("**Approved #")
    assert "(24h)" in header
    status_lines = text.split("\n")
    active_line = next(ln for ln in status_lines if ln.startswith("✅"))
    assert "READ" in active_line
    assert "left" in active_line
    assert "—" in active_line


# ------------------------------------------------------------ expiry display


def test_format_remaining_hours_above_two():
    assert format_remaining(__import__("datetime").timedelta(hours=23, minutes=59)) == "23h"
    assert format_remaining(__import__("datetime").timedelta(hours=3)) == "3h"
    assert format_remaining(__import__("datetime").timedelta(hours=2, minutes=1)) == "2h"


def test_format_remaining_minutes_below_two_hours():
    assert format_remaining(__import__("datetime").timedelta(minutes=90)) == "90m"
    assert format_remaining(__import__("datetime").timedelta(minutes=1)) == "1m"
    assert format_remaining(__import__("datetime").timedelta(seconds=30)) == "0m"


async def test_summary_uses_minutes_below_two_hours(tmp_path):
    """At T0+23h a 24h grant shows 60m (never '1h left' from a rounded
    1.0); at T0+1h it shows 23h."""
    b, transport, store = make_bot(tmp_path)
    await seed_active(b, store)
    b._now = lambda: T0 + __import__("datetime").timedelta(hours=23)
    await b._post_summary()
    text = transport.sent[-1]["text"]
    assert "60m left" in text or "59m left" in text
    assert "1h left" not in text
    b._now = lambda: T0 + __import__("datetime").timedelta(hours=1)
    await b._post_summary()
    text = transport.sent[-1]["text"]
    assert "23h left" in text


# ------------------------------------------------------------------- help


async def test_help_has_two_sections_and_id_note(tmp_path):
    b, transport, _store = make_bot(tmp_path)
    await b.handle_reply(sender=OWNER, text="garbage")
    text = transport.sent[-1]["text"]
    assert "Reactions" in text
    assert "Commands" in text
    assert "<required>" in text
    assert "[optional]" in text
    assert "#" in text
    assert "not part" in text and "the id" in text
    assert "approve 3 8h" in text  # realistic example


async def test_unknown_command_gets_closest_match(tmp_path):
    b, transport, _store = make_bot(tmp_path)
    await b.handle_reply(sender=OWNER, text="revok 5")
    text = transport.sent[-1]["text"]
    assert "Unknown command 'revok'" in text
    assert "revoke" in text
    assert len(transport.sent[-1]["text"].split("\n")) <= 3  # short pointer, not the help dump


async def test_closest_command_unit():
    assert closest_command("revok") == "revoke"
    assert closest_command("approv") == "approve"
    assert closest_command("stats") == "status"
    assert closest_command("zzzz") is None


# --------------------------------------------------------- vocabulary swap


async def test_status_reaction_uses_new_vocabulary(tmp_path):
    b, transport, store = make_bot(tmp_path)
    await seed_active(b, store)
    # post a second pending request so both sections have content
    store.create_request(instance="personal", reason="r", items=[{"path": "b", "mode": "read"}])
    await b.handle_reply(sender=OWNER, text="status")
    text = transport.sent[-1]["text"]
    assert "Active grants" in text
    assert "Awaiting your approval" in text
    assert "Open approvals" not in text
    assert "pending requests:" not in text.lower()


async def test_rejected_request_shows_in_pending_section_with_zero(tmp_path):
    """A rejected request is not 'awaiting approval': the pending count
    reflects only state=pending rows."""
    b, transport, store = make_bot(tmp_path)
    req = await seed_active(b, store)
    await b.handle_reply(sender=OWNER, text=f"revoke {req.id}")
    text = transport.sent[-1]["text"]
    assert "Awaiting your approval: none" in text


# ------------------------------------------------------------ invariants


async def test_reactions_still_preplaced_and_mapping_recorded(tmp_path):
    """D6.1 changes rendering only: reactions, posted_messages mapping,
    and one-time numbers are untouched."""
    b, transport, store = make_bot(tmp_path)
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    event_id = await b.post_request(req)
    emojis = [r["emoji"] for r in transport.reactions_added if r["event_id"] == event_id]
    assert {APPROVE_EMOJI, REJECT_EMOJI} <= set(emojis)
    assert store.request_for_event(event_id) == req.id


async def test_non_approver_still_silently_ignored(tmp_path):
    b, transport, store = make_bot(tmp_path)
    req = store.create_request(instance="personal", reason="r", items=[{"path": "a", "mode": "read"}])
    await b.post_request(req)
    sent_before = len(transport.sent)
    await b.handle_reply(sender="@intruder:x", text="approve 1")
    assert store.get(req.id).state == "pending"
    assert len(transport.sent) == sent_before  # nothing posted to the oracle