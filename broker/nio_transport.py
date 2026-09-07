"""Production Matrix transport: connects ApprovalBot to a real Synapse
homeserver via matrix-nio.

This is the only module that touches the network for the approval
plane. It wraps nio's AsyncClient behind the same interface the fake
transport implements in tests:

    send_message(room, text) -> event_id
    add_reaction(room, event_id, emoji)

The full bot loop (sync, listen, dispatch) lives in BotListener; the
process entrypoint that wires it to the HTTP server is run.py, and
matrixbot.ApprovalBot consumes the events these classes deliver.

T5.6 and the deployment use this module.
"""

from __future__ import annotations

from nio import AsyncClient, RoomSendResponse


class NioTransport:
    """Async transport over matrix-nio. One instance, one homeserver,
    one access token (never logged).

    The two outbound primitives are the approval plane's entire send
    vocabulary: prompt messages (returning the event_id so reactions
    can reference it) and emoji reactions annotating a specific event.
    Every send raises on a homeserver error response rather than
    returning a falsy sentinel, so callers cannot treat a failed
    delivery as success.
    """

    def __init__(self, homeserver: str, user_id: str, access_token: str):
        self._client = AsyncClient(homeserver)
        self._client.access_token = access_token
        self._client.user_id = user_id
        self._user_id = user_id

    async def send_message(self, room: str, text: str) -> str:
        """Send a text message; returns the homeserver-assigned
        event_id so callers (e.g. the pending-request prompt) can be
        reacted to. Raises if the server returned an error response
        (fails closed: no event_id is fabricated).

        D6.1: the text is composed as markdown by the bot; this
        transport derives formatted_body HTML from it (broker.markdown_
        render) and sends both — clients that render formatted_body
        (Element) show bold/code, everything else falls back to the
        plain body, which carries the identical content.
        """
        from broker.markdown_render import text_to_html

        resp = await self._client.room_send(
            room_id=room,
            message_type="m.room.message",
            content={
                "msgtype": "m.text",
                "body": text,
                "format": "org.matrix.custom.html",
                "formatted_body": text_to_html(text),
            },
        )
        if not isinstance(resp, RoomSendResponse):
            raise RuntimeError(f"send failed: {resp}")  # noqa: TRY004 (server error, not type error)
        return resp.event_id

    async def add_reaction(self, room: str, event_id: str, emoji: str):
        """Annotate a prior event with an emoji reaction (m.annotation
        relation). Raises on server error — used for ✓/✗ approval
        marks, so a failed reaction must surface, not vanish."""
        content = {
            "m.relates_to": {
                "rel_type": "m.annotation",
                "event_id": event_id,
                "key": emoji,
            }
        }
        resp = await self._client.room_send(
            room_id=room, message_type="m.reaction", content=content
        )
        if not isinstance(resp, RoomSendResponse):
            raise RuntimeError(f"reaction failed: {resp}")  # noqa: TRY004 (server error, not type error)

    async def whoami(self) -> dict:
        """Connectivity + identity check: verifies the token is valid
        and returns the bot's user id as seen by the server."""
        resp = await self._client.whoami()
        if hasattr(resp, "user_id"):
            return {"ok": True, "user_id": resp.user_id}
        return {"ok": False, "error": str(resp)}

    async def close(self):
        """Release the client's HTTP connections and sync task. Called
        once at process shutdown (run.py) and after each test."""
        await self._client.close()


class BotListener:
    """Production sync loop for the approval plane.

    Runs alongside the HTTP server: syncs the bot account, dispatches
    ReactionEvents and text messages to the ApprovalBot, runs the
    pending-request sweep, and stops cleanly on cancellation.

    Restart-resilience assumptions:
      - Errors inside sync()/sweep() are caught and retried after a
        short backoff; the loop must survive transient homeserver
        outages (no BLE001-style re-raise, no crash of the whole
        broker process over a network blip).
      - `self._since` persists across retries, so after a failure the
        next sync resumes from the last successful next_batch token:
        events delivered once are never re-processed by the server
        side of the timeline.
      - The `_seen` event-id set is the in-process second layer of
        dedupe (belt to the since-token braces). It only ever grows:
        there is no eviction, and growth is bounded in practice by
        the room's event traffic (approvals, replies) — a single
        approval room for one approver, not a firehose.
      - `full_state=True` is requested only on the FIRST sync: the
        initial pass needs room state (memberships) to know where to
        listen; subsequent incremental syncs would waste bandwidth
        re-fetching state they already hold.
    """

    def __init__(self, transport: NioTransport, room: str, bot):
        self._transport = transport
        self._room = room
        self._bot = bot
        self._client = transport._client  # the shared AsyncClient, also used by NioTransport
        self._since = None  # next_batch token; None = full initial sync
        self._seen: set[str] = set()

    async def run(self, sweep_interval_s: int = 300):
        """Run the sync loop until cancelled. `sweep_interval_s` is
        both the long-poll timeout and the cadence for the
        pending-request sweep (expired-request cleanup in the grant
        store)."""
        from nio import InviteMemberEvent, JoinResponse, ReactionEvent, RoomMessageText

        async def on_invite(rm, event):
            # Bot is invited to a new room (e.g. redeployment into a
            # fresh room id): join unconditionally. Access control is
            # done per-event below (only `self._room` is processed),
            # so joining extra rooms widens membership, not authority.
            if isinstance(event, InviteMemberEvent) and event.membership == "invite":
                resp = await self._client.join(rm.room_id)
                if isinstance(resp, JoinResponse):
                    print(f"[bot] joined invited room {rm.room_id}")

        async def on_event(rm, event):
            # Single-room discipline: events from any other room are
            # dropped before dedupe or dispatch.
            if rm.room_id != self._room:
                return
            eid = getattr(event, "event_id", None)
            if eid and eid in self._seen:
                return
            if eid:
                self._seen.add(eid)
            if isinstance(event, ReactionEvent):
                await self._bot.handle_reaction(
                    sender=event.sender, event_id=event.reacts_to, emoji=event.key
                )
            elif isinstance(event, RoomMessageText):
                if event.sender == self._client.user_id:
                    return  # own messages are not commands
                await self._bot.handle_reply(sender=event.sender, text=event.body)

        self._client.add_event_callback(on_invite, InviteMemberEvent)
        self._client.add_event_callback(on_event, (ReactionEvent, RoomMessageText))

        import asyncio as _asyncio

        first = True
        while True:
            try:
                resp = await self._client.sync(
                    timeout=sweep_interval_s * 1000, since=self._since,
                    full_state=first,
                )
                first = False
                if hasattr(resp, "next_batch"):
                    self._since = resp.next_batch
                await self._bot.sweep()
            except Exception as exc:  # noqa: BLE001 (loop must survive)
                print(f"[bot] sync error (retrying): {exc}")
                await _asyncio.sleep(5)

    async def stop(self):
        """Shut down the underlying client (called after the listener
        task is cancelled in run.py's finally block)."""
        await self._transport.close()