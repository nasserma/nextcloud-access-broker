"""T5.6 live Synapse test (Gate 5 live phase).

Posts a real request into the configured approval room, pre-places the
four reactions, and listens for the approver's decisions. The printed
transcript is the gate artifact.

Run: .venv/bin/python scripts/t56_live.py [--timeout 900]

Exits 0 when the full cycle completes (approve -> active, revoke ->
revoked). Exits 1 on timeout.
"""

import argparse
import asyncio
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nio import ReactionEvent, RoomMessageText

from broker.config import load_config
from broker.grants import GrantStore
from broker.matrixbot import ApprovalBot
from broker.nio_transport import NioTransport


class LiveTransport(NioTransport):
    """NioTransport + sync-loop event delivery to the bot."""

    def __init__(self, homeserver, user_id, access_token, room, bot):
        super().__init__(homeserver, user_id, access_token)
        self._room = room
        self._bot = bot
        self._seen = set()
        self._bot_user = user_id

    async def listen(self, timeout_s: int, store, req_id: int):
        client = self._client
        bot = self._bot

        async def on_event(room, event):
            if room.room_id != self._room:
                return
            eid = getattr(event, "event_id", None)
            if eid and eid in self._seen:
                return
            if eid:
                self._seen.add(eid)
            if isinstance(event, ReactionEvent):
                print(f"[event] reaction {event.key!r} by {event.sender} on {event.reacts_to}")
                await bot.handle_reaction(
                    sender=event.sender, event_id=event.reacts_to, emoji=event.key
                )
            elif isinstance(event, RoomMessageText):
                if event.sender == self._bot_user:
                    return
                print(f"[event] message {event.body!r} by {event.sender}")
                await bot.handle_reply(sender=event.sender, text=event.body)

        client.add_event_callback(on_event, (ReactionEvent, RoomMessageText))

        deadline = asyncio.get_event_loop().time() + timeout_s
        since = None
        while asyncio.get_event_loop().time() < deadline:
            rec = store.get(req_id)
            if rec.state == "revoked":
                return
            resp = await client.sync(timeout=3000, since=since, full_state=True)
            if hasattr(resp, "next_batch"):
                since = resp.next_batch


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=900, help="seconds to wait")
    args = parser.parse_args()

    config = load_config("config.yaml")
    mx = config.matrix

    now = lambda: datetime.now(UTC)
    store = GrantStore(db_path=Path(tempfile.mkdtemp()) / "t56.sqlite3", now=now)

    bot = ApprovalBot(
        store=store,
        transport=None,  # wired below
        room=mx["room_id"],
        approver=mx["approver"],
        now=now,
    )
    transport = LiveTransport(
        homeserver=mx["homeserver"],
        user_id=mx["bot_user"],
        access_token=mx["bot_token"],
        room=mx["room_id"],
        bot=bot,
    )
    bot._transport = transport

    req = store.create_request(
        instance="personal",
        reason="T5.6 live gate test - approve then revoke",
        items=[
            {"path": "Documents/paper", "mode": "read"},
            {"path": "Documents/paper/figures", "mode": "write"},
        ],
    )
    print(f"request #{req.id} created; posting to room {mx['room_id']}")
    await bot.post_request(req)
    print("posted with reactions; waiting for your decisions")
    print(">>> Tap thumbs-up to APPROVE, then react no-entry-sign to REVOKE. <<<")

    await transport.listen(timeout_s=args.timeout, store=store, req_id=req.id)

    rec = store.get(req.id)
    print(f"final state of #{req.id}: {rec.state}")
    if rec.state == "revoked":
        print("T5.6-PASS: full approve->revoke cycle observed live")
        code = 0
    else:
        print(f"T5.6-INCOMPLETE: expected revoked, got {rec.state}")
        code = 1
    await transport.close()
    sys.exit(code)


if __name__ == "__main__":
    asyncio.run(main())