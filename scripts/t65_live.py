"""T6.5 live grant cycle driver.

Attaches a sync loop to the RUNNING broker's store (same DB) so your
reactions are processed: the production run.py lacks the listener
(tracked defect); this script supplies it for the live cycle.

Run: .venv/bin/python scripts/t65_live.py
Exits 0 after the full cycle: approve (already given?) -> the script
performs write/list/read/trash via direct store+layer access ->
waits for revoke -> verifies refusal.
"""

import asyncio
import base64
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml
from nio import ReactionEvent, RoomMessageText

from broker.audit import AuditLog
from broker.grants import GrantStore
from broker.matrixbot import ApprovalBot
from broker.nextcloud import AccessRefused, NextcloudClient, NextcloudLayer
from broker.nio_transport import NioTransport
from broker.webdav_adapter import WebDavAdapter


class Listener(NioTransport):
    def __init__(self, homeserver, user_id, access_token, room, bot):
        super().__init__(homeserver, user_id, access_token)
        self._room = room
        self._bot = bot
        self._seen = set()

    async def listen(self, store, req_id, timeout_s, on_approved):
        client = self._client

        async def on_event(room, event):
            if room.room_id != self._room:
                return
            eid = getattr(event, "event_id", None)
            if eid and eid in self._seen:
                return
            if eid:
                self._seen.add(eid)
            if isinstance(event, ReactionEvent):
                print(f"[event] reaction {event.key!r} by {event.sender}")
                await self._bot.handle_reaction(
                    sender=event.sender, event_id=event.reacts_to, emoji=event.key
                )
            elif isinstance(event, RoomMessageText):
                if event.sender != self._client.user_id:
                    await self._bot.handle_reply(sender=event.sender, text=event.body)

        client.add_event_callback(on_event, (ReactionEvent, RoomMessageText))

        fired = False
        deadline = asyncio.get_event_loop().time() + timeout_s
        since = None
        while asyncio.get_event_loop().time() < deadline:
            rec = store.get(req_id)
            if rec.state == "active" and not fired:
                fired = True
                await on_approved()
            if rec.state == "revoked":
                return
            r = await client.sync(timeout=3000, since=since, full_state=True)
            if hasattr(r, "next_batch"):
                since = r.next_batch


async def main():
    with open("config.yaml") as f:  # noqa: ASYNC230 (startup only)
        cfg = yaml.safe_load(f)
    now = lambda: datetime.now(UTC)
    store = GrantStore(db_path="data/grants.sqlite3", now=now)
    audit = AuditLog(path="data/audit.log", now=lambda: datetime.now(UTC).isoformat())

    block = cfg["instances"]["work"]
    dav = WebDavAdapter(url=block["url"], username=block["username"], password=block["password"])
    layer = NextcloudLayer(
        store=store,
        clients={"work": NextcloudClient(
            url=block["url"], username=block["username"], password=block["password"], dav=dav,
        )},
        audit=audit,
        now=now,
    )

    bot = ApprovalBot(
        store=store,
        transport=None,
        room=cfg["matrix"]["room_id"],
        approver=cfg["matrix"]["approver"],
        now=now,
    )
    listener = Listener(
        homeserver=cfg["matrix"]["homeserver"],
        user_id=cfg["matrix"]["bot_user"],
        access_token=cfg["matrix"]["bot_token"],
        room=cfg["matrix"]["room_id"],
        bot=bot,
    )
    bot._transport = listener

    # 1. create AND post the request in THIS process
    req = store.create_request(
        instance="work",
        reason="T6.5 live grant cycle: write/list/read/trash on scratch folder AgentTest",
        items=[{"path": "AgentTest", "mode": "write"}],
    )
    await bot.post_request(req)
    print(f"request #{req.id} posted; waiting for your thumbs-up")
    rid = req.id

    async def cycle():
        print("GRANT ACTIVE - performing write/list/read/trash via the wall")
        dav._client.mkdir("AgentTest")
        out = layer.write("work", "AgentTest/hello.txt", b"T6.5 live cycle proof\n")
        print("write:", out)
        out = layer.list("work", "AgentTest")
        print("list:", out)
        out = layer.read("work", "AgentTest/hello.txt")
        print("read:", base64.b64encode(out["content"]).decode()[:60])
        out = layer.trash("work", "AgentTest/hello.txt")
        print("trash:", out)
        print("cycle complete - tap the no-entry reaction to REVOKE")

    await listener.listen(store, rid, timeout_s=1200, on_approved=cycle)

    rec = store.get(rid)
    print(f"final state: {rec.state}")
    try:
        layer.read("work", "AgentTest/hello.txt")
        print("REFUSAL CHECK FAILED: read worked after revoke")
        sys.exit(1)
    except AccessRefused as exc:
        print(f"post-revoke refusal verified: {exc}")
    await listener.close()
    print("T6.5-PASS")
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
