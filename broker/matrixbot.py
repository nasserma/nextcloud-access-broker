"""Matrix approval bot: the human gate (Gate 5).

Design document section 3.3. The approval plane: requests posted to a
private room as readable messages with reactions pre-placed by the bot
(the Hermes interaction pattern); the single allowlisted approver
decides by tapping a reaction or typing a reply.

Security invariants enforced here:
- Sender allowlist: exactly one Matrix user id may decide anything.
  Everything from any other sender is ignored silently.
- One-time request numbers: all state transitions go through the grant
  store, which refuses decided numbers. The bot cannot circumvent this.
- Every decision produces a visible confirmation plus a summary of open
  approvals. Silent state changes are forbidden.
- Pending requests expire after 12h of silence with a room notice.

Transport: a thin async interface (send_message, add_reaction) so tests
inject a fake and production injects a matrix-nio adapter (Gate 6/7).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from datetime import datetime, timedelta

from broker.grants import GrantRecord, GrantStore

# Scrub-safe decision logging (W2): every line goes through the broker
# logger (SecretScrubFilter), so a container restart does not destroy
# the only record of who decided what. Fields logged here (rid, action,
# outcome, sender, expiry, item count) are non-secret: the sender is a
# Matrix user id that already appears in the room and the audit trail.
logger = logging.getLogger(__name__)

APPROVE_EMOJI = "\N{THUMBS UP SIGN}"
REJECT_EMOJI = "\N{THUMBS DOWN SIGN}"
REVOKE_EMOJI = "\N{PROHIBITED SIGN}"
STATUS_EMOJI = "\N{CLIPBOARD}"

_HELP_TEXT = """**How to decide**

**Reactions** — tap on a request message:
👍 approve all · 👎 reject all · ⛔ revoke an active grant · 📋 status

**Commands** — type in this room:
`approve <id> [items] [expiry]` — e.g. `approve 3 8h`, `approve 3 1,2 30m`
`reject <id>` · `revoke <id>` · `revoke <instance>` · `revoke all` ·
`undo <id>` (15s after a reject/revoke) · `status`

`<required>` `[optional]`. The **#** shown in messages is **not part** of
the id: type `approve 3`, never `approve #3`. Expiry: `8h`, `30m`, `2d`."""

_REPLY_RE = re.compile(
    r"^(approve|reject|revoke|undo|status)\s*(\d+|[a-z_][a-z0-9_-]*)?"
    r"(?:\s+([\d,]+))?"  # item numbers
    r"(?:\s+(\d{1,3}[hmd]))?$",
    re.IGNORECASE,
)
"""Group 2: request number, or (D6h) a bare target word for 'revoke
all|<instance>'. Anything not matched downstream falls back to None
(unknown command teacher)."""

_REVOKE_TARGET_RE = re.compile(
    r"^revoke\s+(all|([a-z0-9][a-z0-9_-]*))$",
    re.IGNORECASE,
)
"""D6h: 'revoke all' and 'revoke <instance>' — typed-reply mass
revocation. Instance names share the config-key charset (lowercase
alphanumeric, hyphen, underscore); 'all' is reserved."""


def parse_reply(text: str):
    """Parse a typed reply. Returns:
    (action, id|None, item_numbers|None, expiry|None) or None if
    unparseable.

    Forms: 'approve 47', 'approve 47 1,2', 'approve 47 8h',
    'approve 47 1,2 8h', 'reject 47', 'revoke 47', 'undo 47',
    'status'.
    """
    if not isinstance(text, str):
        return None
    m = _REPLY_RE.match(text.strip())
    if not m:
        return None
    action = m.group(1).lower()
    number = m.group(2)
    if action == "status":
        return ("status", None, None, None)
    if number is None:
        return None
    if action != "revoke" and not number.isdigit():
        return None  # D6h: word targets are revoke-only ('approve xx' stays garbage)
    if action == "revoke" and not number.isdigit():
        # D6h: 'revoke all' / 'revoke <instance>' — mass revocation by
        # target. Distinct actions so handle_reply routes them without
        # touching numeric-revoke handling.
        m2 = _REVOKE_TARGET_RE.match(text.strip())
        if m2:
            target = m2.group(1).lower()
            if target == "all":
                return ("revoke_all", None, None, None)
            return ("revoke_instance", target, None, None)
        return None
    rid = int(number)
    if rid <= 0:
        return None
    if action == "undo":
        return ("undo", rid, None, None)
    items = m.group(3)
    item_numbers = [int(x) for x in items.split(",")] if items else None
    if item_numbers and any(n <= 0 for n in item_numbers):
        return None
    return (action, rid, item_numbers, m.group(4))


_COMMANDS = ("approve", "reject", "revoke", "undo", "status")


def closest_command(word: str) -> str | None:
    """Nearest known command for an unrecognized first word, or None
    when nothing is close (distance floor: 'zzzz' suggests nothing).
    Used by the unknown-command reply so the bot teaches instead of
    dumping usage text."""
    if not word:
        return None
    import difflib

    match = difflib.get_close_matches(word.lower(), _COMMANDS, n=1, cutoff=0.6)
    return match[0] if match else None


def format_remaining(delta) -> str:
    """Human time-left for grant headers. Whole hours at/above 2h,
    minutes below (kills the '24h' granted / '23h left' displayed
    rounding inconsistency: 23h59m displays 23h, 89m displays 89m)."""
    seconds = max(0, int(delta.total_seconds()))
    if seconds >= 2 * 3600:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


# Undo grace (D6.2 #7, user-set): seconds after a reject/revoke during
# which `undo <id>` creates a fresh pending request. Deliberately short
# — the owner resolves mistakes in seconds, and a short window keeps
# "undo" from becoming a soft second-thought channel.
UNDO_GRACE_SECONDS = 15


class _UndoWindow:
    """In-memory record that an id was just rejected/revoked and may be
    un-done before the deadline. Deadline consumed on first use (one
    shot). Restarts drop all windows — fail closed: after a restart the
    decision stands and `undo` replies 'window closed'."""

    __slots__ = ("deadline", "payload")

    def __init__(self, deadline: datetime, payload: dict):
        self.deadline = deadline
        self.payload = payload  # {"instance", "reason", "items"}


class ApprovalBot:
    """Room-facing half of the approval plane (Gate 5).

    Routes the allowlisted approver's reactions and typed replies into
    GrantStore transitions, and renders every outcome back into the
    room. The bot holds NO authorization power of its own: it can only
    call store transitions, which refuse decided/unknown numbers - a
    compromised or buggy bot cannot approve anything without the
    allowlisted sender's input, and cannot double-apply a decision.
    """

    def __init__(
        self,
        store: GrantStore,
        transport,
        room: str,
        approver: str,
        now: Callable[[], datetime],
    ):
        """store: the GrantStore all decisions are routed through.
        transport: thin async send_message/add_reaction interface
        (matrix-nio adapter in production, fake in tests). room: the
        private approval room id. approver: the single allowlisted
        Matrix user id - messages from ANY other sender are ignored
        silently (never acknowledged, so the bot is not an oracle).
        now: injected clock for sweep and remaining-time display.
        """
        self._store = store
        self._transport = transport
        self._room = room
        self._approver = approver
        self._now = now
        self._swept: set[int] = set()  # request ids already noticed expired
        self._undo_windows: dict[int, _UndoWindow] = {}  # D6.2 #7

    # ------------------------------------------------------------- posting

    def render_request(self, req: GrantRecord) -> str:
        """Markdown for a pending request (D6.1): header names the id
        and its state; each item is ONE line — mode, then the path —
        with paths indented under the number so mode/path pairing
        survives phone-width wrapping."""
        lines = [
            f"⏳ **PENDING #{req.id}** — awaiting your approval",
            f"Instance: **{req.instance}**",
            f"Reason: {req.reason}",
        ]
        for i, item in enumerate(req.items, start=1):
            lines.append(
                f"{i}. **{item['mode'].upper()}** `{item['path']}`"
            )
        lines.append("Expiry if approved: 24h (or reply a shorter one, e.g. `approve 3 8h`)")
        # D6.2 context footer (user-corrected): on a pending request,
        # only the commands that act on THIS message.
        lines.append("Decide: `approve|reject <id> [expiry]`")
        return "\n".join(lines)

    async def post_request(self, req: GrantRecord):
        """Post a pending request to the approval room as a numbered,
        itemized message and pre-place the four decision reactions.

        The reactions are placed by the BOT so the approver only ever
        taps an existing control (the Hermes interaction pattern) - the
        bot itself never reacts on the approver's behalf. The
        event-id -> request-id mapping is persisted immediately after
        posting, so reactions resolve even across a restart.
        Returns the posted event id.
        """
        event_id = await self._transport.send_message(
            self._room, self.render_request(req)
        )
        for emoji in (APPROVE_EMOJI, REJECT_EMOJI, REVOKE_EMOJI, STATUS_EMOJI):
            await self._transport.add_reaction(self._room, event_id, emoji)
        # Persist the mapping so ANY process can resolve reactions to
        # this request, including after a restart (defect fixed: the old
        # in-memory dict died with the posting process).
        self._store.record_posted(event_id, req.id)
        return event_id

    # ------------------------------------------------------------ reactions

    async def handle_reaction(self, sender: str, event_id: str, emoji: str):
        """Route a room reaction to a decision, allowlist-first.

        Order matters: the sender allowlist is checked BEFORE the event
        is even looked up, so a non-approver probing event ids gets no
        information (unknown events and forbidden senders are
        indistinguishable - both silently ignored).
        """
        if sender != self._approver:
            # allowlist: everyone else is furniture. Debug level: this is
            # a probe signal worth having under debug, never an oracle at
            # info (unknown events and forbidden senders are
            # indistinguishable by design).
            logger.debug(
                "decision allowlist rejected: sender=%s emoji=%s event=%s",
                sender, emoji, event_id,
            )
            return
        rid = self._store.request_for_event(event_id)
        if rid is None:
            return  # not one of our request messages
        if emoji == APPROVE_EMOJI:
            await self._decide(rid, "approve", None, None, sender)
        elif emoji == REJECT_EMOJI:
            await self._decide(rid, "reject", None, None, sender)
        elif emoji == REVOKE_EMOJI:
            await self._revoke(rid, sender)
        elif emoji == STATUS_EMOJI:
            await self._post_summary()
        # other emojis: deliberately ignored

    async def handle_reply(self, sender: str, text: str):
        """Route a typed reply ('approve 47 1,2 8h', 'reject 47',
        'revoke 47', 'status') to a decision, allowlist-first.

        The existence check distinguishes 'unknown request' from
        'already decided': unknown numbers get a room notice, decided
        numbers fall through to the store, whose ValueError surfaces
        the already-decided state to the approver.
        """
        if sender != self._approver:
            return
        parsed = parse_reply(text)
        if parsed is None:
            # Unknown command: teach, don't dump.: teach, don't dump. A close match gets a
            # one-line suggestion; pure garbage gets the full help.
            first_word = text.strip().split(" ", 1)[0] if text.strip() else ""
            closest = closest_command(first_word)
            if closest:
                await self._transport.send_message(
                    self._room,
                    f"Unknown command '{first_word}' — closest: `{closest}`. "
                    "Type `status` to see the command list.",
                )
            else:
                await self._transport.send_message(self._room, _HELP_TEXT)
            return
        action, rid, item_numbers, expiry = parsed
        if action == "status":
            await self._post_summary()
            return
        if action == "revoke_all":
            await self._revoke_many(None, sender)
            return
        if action == "revoke_instance":
            await self._revoke_many(rid, sender)  # rid carries the instance name here
            return
        assert rid is not None or action in ("revoke_all", "revoke_instance")  # parse_reply guarantees payload
        if action == "undo":
            await self._undo(rid, sender)
            return
        if rid not in {r.id for r in self._all_requests()}:
            await self._transport.send_message(
                self._room, f"No request #{rid} exists."
            )
            return
        if action == "approve":
            await self._decide(rid, "approve", item_numbers, expiry, sender)
        elif action == "reject":
            await self._decide(rid, "reject", None, None, sender)
        else:
            # parse_reply only yields approve/reject/revoke here (status
            # and undo returned earlier), so this branch IS revoke.
            await self._revoke(rid, sender)

    # ------------------------------------------------------------------ undo

    async def _undo(self, rid: int, sender: str):
        """D6.2 #7: undo a JUST-made reject/revoke. Never resurrects
        the decided number — creates a NEW pending request with the
        original instance/reason/items through the ordinary posted
        flow. Fail closed: unknown id, expired window, or consumed
        window all refuse with a 'window closed' reply. The window map
        is in-memory, so a restart inside the grace closes all
        windows (the restart also discards the decision's context)."""
        window = self._undo_windows.get(rid)
        if window is None or self._now() >= window.deadline:
            self._undo_windows.pop(rid, None)
            await self._transport.send_message(
                self._room,
                f"Undo window for #{rid} closed. File a new request if access is still needed.",
            )
            return
        self._undo_windows.pop(rid)  # one shot: consumed on first use
        payload = window.payload
        new_req = self._store.create_request(
            instance=payload["instance"],
            reason=payload["reason"],
            items=payload["items"],
        )
        logger.info(
            "decision: rid=%d action=undo outcome=recreated sender=%s new_rid=%d",
            rid, sender, new_req.id,
        )
        await self.post_request(new_req)

    def _arm_undo(self, rid: int, rec: GrantRecord):
        """Record the undo window after a reject/revoke."""
        self._undo_windows[rid] = _UndoWindow(
            deadline=self._now() + timedelta(seconds=UNDO_GRACE_SECONDS),
            payload={
                "instance": rec.instance,
                "reason": rec.reason,
                "items": rec.items,
            },
        )

    # ------------------------------------------------------------ internals

    def _all_requests(self):
        """All request ids known to the store (any state). The store is
        the source of truth; the bot only routes decisions to it."""
        return self._store.all_records()

    async def _decide(self, rid: int, action: str, item_numbers, expiry, sender: str):
        """Apply an approve/reject and post the outcome + refreshed
        status. Every state change is made visible in the room
        (invariant: no silent decisions). Store ValueError (already
        decided, bad item numbers) is reported, never crash-swallowed
        and never retried. One scrub-safe log line per decision
        (survives container restart, unlike the room).
        """
        try:
            if action == "approve":
                rec = self._store.approve(rid, expiry=expiry, item_numbers=item_numbers)
                logger.info(
                    "decision: rid=%d action=approve outcome=granted sender=%s "
                    "instance=%s items=%d expiry=%s",
                    rid, sender, rec.instance, len(rec.items), expiry or "24h",
                )
                text = self._render_decision(rec, "Approved", expiry or "24h")
            else:
                self._store.reject(rid)
                logger.info(
                    "decision: rid=%d action=reject outcome=rejected sender=%s",
                    rid, sender,
                )
                rec = self._store.get(rid)
                self._arm_undo(rid, rec)
                text = self._render_decision(rec, "Rejected", None, undo=True)
        except ValueError as exc:
            logger.info(
                "decision: rid=%d action=%s outcome=refused sender=%s reason=%s",
                rid, action, sender, exc,
            )
            await self._transport.send_message(self._room, f"Cannot approve #{rid}: {exc}")
            return
        await self._transport.send_message(self._room, text)

    # ------------------------------------------------------ renderers (D6.1)

    def _render_decision(self, rec: GrantRecord, verb: str, expiry: str | None,
                         undo: bool = False) -> str:
        """Verb-first confirmation ("Approved #7 (24h).") then a
        visually separated refreshed status block. Items are one line
        each: mode + path, indented under the verb line. reject/revoke
        confirmations append the 15s undo offer (D6.2 #7)."""
        head = f"**{verb} #{rec.id}**"
        if rec.state == "active" and expiry:
            head += f" ({expiry})."
        else:
            head += "."
        if rec.items:
            item_lines = [f"  **{i['mode'].upper()}** `{i['path']}`" for i in rec.items]
            head += "\n" + "\n".join(item_lines)
        if undo:
            head += f"\n\nMistake? `undo {rec.id}` within {UNDO_GRACE_SECONDS}s re-opens it as a new request."
        return head + "\n\n———\n\n" + self._status_text()

    async def _revoke_many(self, instance: str | None, sender: str):
        """D6h: mass revocation. instance=None means 'revoke all' (every
        active grant, every instance); a name means every active grant
        on that instance. Revokes one at a time through the store (each
        state transition individually valid and logged), then posts ONE
        summary. An unknown instance revokes nothing and says so — the
        approver sees the zero, not silence (no-silent-decisions
        invariant)."""
        active = self._store.active_grants(instance=instance)
        if instance is not None and not active:
            # Distinguish 'no grants' from 'no such instance' using the
            # configured allowlist when available.
            allowed = getattr(self._store, "allowed_instances", None)
            if allowed is not None and instance not in allowed:
                await self._transport.send_message(
                    self._room, f"Unknown instance '{instance}'."
                )
                return
        revoked = []
        for rec in active:
            try:
                self._store.revoke(rec.id)
            except (ValueError, LookupError):
                # Expired between listing and revoking: skip, count the rest.
                continue
            logger.info(
                "decision: rid=%d action=revoke outcome=revoked sender=%s target=%s",
                rec.id, sender, instance or "all",
            )
            revoked.append(rec.id)
        if not revoked:
            await self._transport.send_message(
                self._room,
                f"Nothing to revoke ({'all instances' if instance is None else instance}).",
            )
            return
        ids = ", ".join(f"#{i}" for i in revoked)
        await self._transport.send_message(
            self._room,
            f"**Revoked {len(revoked)} grant(s)** ({ids}).\n\n———\n\n"
            + self._status_text(),
        )

    async def _revoke(self, rid: int, sender: str):
        """Operator kill switch: route revoke to the store (works on
        pending AND active grants) and confirm in the room. One
        scrub-safe log line per revocation."""
        try:
            self._store.revoke(rid)
        except (ValueError, LookupError) as exc:
            logger.info(
                "decision: rid=%d action=revoke outcome=refused sender=%s reason=%s",
                rid, sender, exc,
            )
            await self._transport.send_message(self._room, f"Cannot revoke #{rid}: {exc}")
            return
        logger.info(
            "decision: rid=%d action=revoke outcome=revoked sender=%s", rid, sender
        )
        rec = self._store.get(rid)
        self._arm_undo(rid, rec)
        await self._transport.send_message(
            self._room, self._render_decision(rec, "Revoked", None, undo=True)
        )

    def _status_lines(self) -> list[str]:
        """Room status block (D6.1 vocabulary): Active grants, then
        Awaiting your approval (D6.2 #8 aging markers on pending).

        D6.2 #9 grouping: with multiple active instances, grants group
        under per-instance headers (alphabetical) and the instance name
        drops from the grant line. A single active instance keeps the
        flat layout — no header tax for one group."""
        lines = ["**Active grants**"]
        active = self._store.active_grants()
        if len({rec.instance for rec in active}) > 1:
            by_instance: dict[str, list] = {}
            for rec in active:
                by_instance.setdefault(rec.instance, []).append(rec)
            for instance in sorted(by_instance):
                lines.append(f"{instance}:")
                for rec in by_instance[instance]:
                    lines.extend(self._active_grant_lines(rec, with_instance=False))
        else:
            for rec in active:
                lines.extend(self._active_grant_lines(rec, with_instance=True))
        if len(lines) == 1:
            lines.append("none")
        lines.append("")
        pending = self._store.pending_records()
        if not pending:
            lines.append("Awaiting your approval: none")
        else:
            lines.append(f"**Awaiting your approval** ({len(pending)}):")
            now = self._now()
            for rec in pending:
                age = now - rec.created_at
                age_str = format_remaining(age)
                line = f"⏳ **#{rec.id}** — {rec.instance} — waiting {age_str}"
                # D6.2 #8 aging markers: display only, no state change.
                if age >= timedelta(hours=4):
                    line += f" (since {rec.created_at:%H:%M}) — **stale?**"
                elif age >= timedelta(hours=1):
                    line += f" (since {rec.created_at:%H:%M})"
                lines.append(line)
        # D6.2 context footer (user-corrected): name only the commands
        # that act on the content above. Active grants → revise/kill;
        # pending requests → decide. Both → one line, both segments.
        # Empty room → no footer.
        footer_parts = []
        if pending:
            footer_parts.append("Decide a request: `approve|reject <id> [expiry]`")
        if active:
            footer_parts.append(
                "Revise: `undo <id>` (15s) · Kill: `revoke <id>` "
                "(mass: `revoke <instance>` / `revoke all`)"
            )
        if footer_parts:
            lines.append("")
            lines.append(" · ".join(footer_parts))
        return lines

    def _active_grant_lines(self, rec: GrantRecord, with_instance: bool) -> list[str]:
        """One active grant as display lines: header (✅ id — modes,
        time left[, instance]) then one line per item."""
        assert rec.expires_at is not None  # active grants always have expiry
        remaining = format_remaining(rec.expires_at - self._now())
        line = f"✅ **#{rec.id}** — {self._modes_label(rec)}, {remaining} left"
        if with_instance:
            line += f" — {rec.instance}"
        lines = [line]
        for item in rec.items:
            lines.append(f"   **{item['mode'].upper()}** `{item['path']}`")
        return lines

    @staticmethod
    def _modes_label(rec: GrantRecord) -> str:
        modes = sorted({i["mode"].upper() for i in rec.items})
        return "+".join(modes)

    def _status_text(self) -> str:
        return "\n".join(self._status_lines())

    async def _post_summary(self):
        await self._transport.send_message(self._room, self._status_text())

    async def sweep(self):
        """Periodic housekeeping: post one expiry notice per pending
        request that has timed out. Called by the server loop.

        The _swept set guarantees each expired request is announced at
        most once per process lifetime (the store keeps the request in
        pending rows until restart discards it, so the notice would
        otherwise repeat on every sweep).
        """
        for rec in self._store.pending_records():
            if rec.state == "expired" and rec.id not in self._swept:
                await self._transport.send_message(
                    self._room,
                    f"Request #{rec.id} expired unanswered. Silence grants nothing.",
                )
                self._swept.add(rec.id)