"""MCP server surface (Gate 6). MCP SDK 2.x (MCPServer).

Design document sections 3.6-3.8. Streamable HTTP transport.

Seven-plus-one tools (request_access, check_access, list, read, write,
move, trash, mkdir), no more:
    request_access(instance, reason, items) -> pending request posted to
        the approval plane. Two-phase: returns immediately; the agent
        polls check_access or waits for the human decision.
    check_access(instance) -> current active grants (scope introspection).
    list / read / write / move / trash(instance, path...) -> file
        operations, ALL routed through the WebDAV layer which carries
        the wall. No tool touches a client directly.

Auth: one agent token, constant-time comparison, enforced by the bearer
middleware installed on the Starlette app (see entrypoint run()).

Failure envelope: every tool returns {"status": ok|refused|error|pending,
...}. Refused = the wall (no grant). Error = infrastructure. No
exception text or traceback crosses the tool boundary.
"""

from __future__ import annotations

import base64
import hmac
from collections.abc import Callable
from datetime import datetime

from mcp.server.mcpserver import MCPServer

from broker.audit import LogWriteError
from broker.grants import GrantStore
from broker.matrixbot import ApprovalBot
from broker.nextcloud import AccessRefused, NextcloudLayer, WebDavError


def check_auth(provided: str | None, expected: str) -> bool:
    """Constant-time agent token check (also usable as the middleware
    predicate)."""
    if not provided:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def _validate_bind_host(bind_host: str | None):
    """Refuse wildcard or empty bind targets at construction time.

    Threat: a wildcard bind would expose the broker on every interface
    and silently bypass the deployment's intended single-interface
    exposure. Exposure policy belongs to the host (docker-compose port
    mapping), never to the application, so the app hard-fails here
    rather than defaulting to a wider listener.
    """
    if bind_host in ("0.0.0.0", "::"):
        raise ValueError(
            "refusing wildcard bind_host: exposure is decided by the host "
            "(docker-compose), never by the application"
        )
    if bind_host == "":
        raise ValueError("bind_host must be None or a specific address")


def build_server(settings: dict) -> MCPServer:
    """Factory validating the bind guard before anything is built."""
    _validate_bind_host(settings.get("bind_host"))
    # D6.6 fix: report the real package version. The SDK defaults to an
    # empty string, which made deployed builds indistinguishable from
    # each other during the Sep 7 multi-instance live test.
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    try:
        ver = _pkg_version("nextcloud-access-broker")
    except PackageNotFoundError:
        ver = "0.1.0"
    return MCPServer(name="nextcloud-access-broker", version=ver)


class BrokerServer:
    """Holds the wired components and implements the tool functions."""

    def __init__(
        self,
        layer: NextcloudLayer,
        store: GrantStore,
        bot: ApprovalBot,
        agent_token: str,
        bind_host: str | None,
        port: int,
        now: Callable[[], datetime],
        allowed_instances: set | None = None,
    ):
        """Wire and validate the server's components.

        layer: the NextcloudLayer carrying the wall - every file tool
        goes through it. store: the grant store (instance allowlist is
        pushed into it here, so refusal happens before storage or
        posting). bot: the approval-plane poster. agent_token: the
        single bearer token, checked constant-time by the middleware
        installed at the entrypoint (NOT here). Raises ValueError on a
        wildcard/empty bind_host before anything else is built.
        """
        _validate_bind_host(bind_host)
        self.layer = layer
        self.store = store
        self.bot = bot
        self.agent_token = agent_token
        self.bind_host = bind_host
        self.port = port
        self._now = now
        # The configured instances ARE the allowlist: requests for any
        # other instance are refused before storage or posting. None
        # means unrestricted (tests only).
        self.store.allowed_instances = allowed_instances

    # ------------------------------------------------------------ helpers

    @staticmethod
    def tool_names():
        return ["request_access", "check_access", "list", "read", "write", "move", "trash", "mkdir"]

    def _refusal(self, exc: AccessRefused) -> dict:
        return {"status": "refused", "reason": exc.reason}

    @staticmethod
    def _error(message: str) -> dict:
        # sanitize: no exception internals, no tracebacks, cap length
        return {"status": "error", "message": str(message)[:300]}

    async def _request_access(self, instance: str, reason: str, items: list) -> dict:
        """Two-phase request flow: store the pending request, then post
        it to the approval plane. If posting fails, the request is
        rolled back to rejected so no invisible pending rows accumulate
        (a pending request the approver can never see must not linger
        as if it were actionable).
        """
        try:
            req = self.store.create_request(instance=instance, reason=reason, items=items)
        except ValueError as exc:
            return self._error(str(exc))
        try:
            await self.bot.post_request(req)
        except (ConnectionError, RuntimeError, OSError) as exc:
            # approval plane unreachable: reject the request cleanly so
            # the store does not accumulate invisible pending requests.
            self.store.reject(req.id)
            return self._error(f"approval plane unreachable: {exc}")
        return {"status": "pending", "request_id": req.id}

    async def _check_access(self, instance: str) -> dict:
        grants = [
            {
                "id": rec.id,
                "instance": rec.instance,
                "items": rec.items,
                "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
            }
            for rec in self.store.active_grants(instance=instance)
        ]
        return {"grants": grants}

    def _op(self, fn, *args, **kwargs) -> dict:
        """Run one file operation and map every failure class into the
        tool envelope.

        The exception ladder is ordered most-specific first: AccessRefused
        (the wall's refusal - status 'refused', the agent may retry after
        a grant), WebDavError (upstream HTTP), LogWriteError (audit
        refused - the operation did NOT happen), transport unreachability,
        then the final defensive envelope. Invariant: the agent never
        sees a traceback or an unscrubbed exception.
        """
        try:
            result = fn(*args, **kwargs)
        except AccessRefused as exc:
            return self._refusal(exc)
        except WebDavError as exc:
            return self._error(f"nextcloud error {exc.status}: {exc.message}")
        except LogWriteError as exc:
            return self._error(f"audit failure, operation refused: {exc}")
        except (ConnectionError, OSError) as exc:
            return self._error(f"backend unreachable: {exc}")
        except Exception as exc:  # noqa: BLE001 (final defensive envelope)
            # 5a fix: FINAL defensive envelope. Any other exception type
            # from the transport (or anywhere below) must reach the
            # agent credential-free. Scrub EVERY configured instance's
            # secret value, keyword-independent — an upstream error may
            # echo any of them.
            message = str(exc)
            if hasattr(self.layer, "_clients"):
                for client in self.layer._clients.values():
                    secret = getattr(client, "password", None)
                    if secret:
                        message = message.replace(secret, "[redacted]")
            return self._error(f"unexpected transport failure: {message[:200]}")
        return {"status": "ok", "result": result}

    # --------------------------------------------------- tool implementations

    async def request_access(self, instance: str, reason: str, items: list) -> dict:
        return await self._request_access(instance, reason, items)

    async def check_access(self, instance: str) -> dict:
        return await self._check_access(instance)

    async def list(self, instance: str, path: str) -> dict:
        return self._op(self.layer.list, instance, path)

    async def read(self, instance: str, path: str, principal: str = "agent") -> dict:
        """Read a file; raw bytes are base64-encoded for the JSON tool
        envelope (MCP payload is text-only), replacing the bytes result.
        D5: principal is stamped on the audit record ('agent' default;
        the transfer surface passes 'transfer').
        """
        out = self._op(self.layer.read, instance, path, principal=principal)
        if out["status"] == "ok" and isinstance(out["result"], dict):
            content = out["result"].get("content")
            if isinstance(content, bytes):
                out["result"] = {"content_b64": base64.b64encode(content).decode()}
        return out

    async def write(self, instance: str, path: str, content: str, principal: str = "agent") -> dict:
        """Write a file from strict base64 content (validate=True rejects
        whitespace-tolerant sloppy input before the layer is touched).
        D5: principal is stamped on the audit record."""
        try:
            data = base64.b64decode(content, validate=True)
        except (ValueError, TypeError):  # binascii.Error subclasses ValueError
            return self._error("content must be base64")
        return self._op(self.layer.write, instance, path, data, principal=principal)

    async def move(self, instance: str, src: str, dst: str) -> dict:
        return self._op(self.layer.move, instance, src, dst)

    async def trash(self, instance: str, path: str) -> dict:
        return self._op(self.layer.trash, instance, path)

    async def mkdir(self, instance: str, path: str) -> dict:
        return self._op(self.layer.mkdir, instance, path)

    async def checkout(self, instance: str, path: str, timeout: int = 0, principal: str = "transfer") -> dict:
        """D5 checkout: lock + read. Content is base64 in the envelope
        (MCP is text-only); the lock_token rides alongside it. This
        tool is TRANSFER-surface only."""
        out = self._op(self.layer.checkout, instance, path, timeout=timeout, principal=principal)
        if out["status"] == "ok" and isinstance(out["result"], dict):
            content = out["result"].get("content")
            if isinstance(content, bytes):
                out["result"]["content_b64"] = base64.b64encode(content).decode()
                out["result"]["content"] = None
        return out

    async def checkin(self, instance: str, path: str, content: str, lock_token: str, principal: str = "transfer") -> dict:
        """D5 checkin: write + verify + unlock. Strict base64 like
        write; the lock_token is mandatory (the checkout manifest
        carries it). TRANSFER-surface only."""
        if not lock_token:
            return self._error("lock_token is required for checkin")
        try:
            data = base64.b64decode(content, validate=True)
        except (ValueError, TypeError):
            return self._error("content must be base64")
        return self._op(self.layer.checkin, instance, path, data, lock_token, principal=principal)


AGENT_TOOLS = (
    "request_access", "check_access", "list", "move", "trash", "mkdir",
)
"""The discovery/control surface (/mcp, agent token). File CONTENT tools
(read, write) are deliberately absent: D5 — file content never transits
the LLM context window. Agents that cannot see read/write cannot be
tempted to call them; enforcement is completed by the transfer surface's
separate token in run.py."""

TRANSFER_TOOLS = (
    "check_access", "read", "write", "checkout", "checkin",
)
"""The content surface (/transfer, transfer token). Only the transfer
CLI holds this credential. check_access is included so the CLI can
introspect grants; list is NOT included — the CLI imports the grant
matcher from broker.paths directly (same repo) instead of hand-rolling
containment."""


def build_app(server: BrokerServer, tools: tuple[str, ...] = AGENT_TOOLS) -> MCPServer:
    """Register a tool subset on an MCPServer instance. The bearer
    token middleware is installed by the entrypoint on the Starlette
    app (see run_server in the entrypoint). D5: the tool surface is
    credential-dependent — the agent app registers AGENT_TOOLS (no
    read/write), the transfer app registers TRANSFER_TOOLS. Both
    route through the same BrokerServer methods, so the wall, grants,
    and audit are shared, not forked (hard rule 5 preserved)."""
    mcp = build_server({"bind_host": server.bind_host})
    # D5: the surface's principal, stamped on audit records. The transfer
    # surface (TRANSFER_TOOLS) acts as 'transfer'; every other tool set
    # is an agent-facing surface.
    PRINCIPAL = "transfer" if set(tools) == set(TRANSFER_TOOLS) else "agent"

    async def request_access(instance: str, reason: str, items: list[dict]) -> dict:
        """Request a batch of paths for one instance. Returns a pending
        request id; the owner approves via Matrix. items:
        [{"path": "...", "mode": "read"|"write"}, ...]"""
        return await server.request_access(instance=instance, reason=reason, items=items)

    async def check_access(instance: str) -> dict:
        """Current active grants for this instance (scope introspection)."""
        return await server.check_access(instance=instance)

    async def list(instance: str, path: str) -> dict:
        """List a folder's contents. Requires an active READ grant."""
        return await server.list(instance=instance, path=path)

    async def read(instance: str, path: str) -> dict:
        """Read a file (base64 content). Requires an active READ grant.
        Registered on BOTH surfaces; the principal stamp matches the
        surface this closure was registered on."""
        return await server.read(
            instance=instance, path=path, principal=PRINCIPAL
        )

    async def write(instance: str, path: str, content: str) -> dict:
        """Write a file (base64 content). Requires an active WRITE grant."""
        return await server.write(
            instance=instance, path=path, content=content, principal=PRINCIPAL
        )

    async def move(instance: str, src: str, dst: str) -> dict:
        """Move/rename within the approved area. Requires WRITE on both."""
        return await server.move(instance=instance, src=src, dst=dst)

    async def trash(instance: str, path: str) -> dict:
        """Move an item to Nextcloud trash. Requires WRITE."""
        return await server.trash(instance=instance, path=path)

    async def mkdir(instance: str, path: str) -> dict:
        """Create a folder. Requires WRITE on the path's parent scope."""
        return await server.mkdir(instance=instance, path=path)

    async def checkout(instance: str, path: str, timeout: int = 0) -> dict:
        """Checkout (D5): lock the file (server-wide write refusal via
        files_lock) and return its content + lock_token. Stage the
        token; checkin requires it."""
        return await server.checkout(instance=instance, path=path, timeout=timeout, principal=PRINCIPAL)

    async def checkin(instance: str, path: str, content: str, lock_token: str) -> dict:
        """Checkin (D5): write the worked-on content, then release the
        lock with the checkout's token."""
        return await server.checkin(
            instance=instance, path=path, content=content,
            lock_token=lock_token, principal=PRINCIPAL,
        )

    for fn in (
        request_access, check_access, list, read, write, move, trash,
        mkdir, checkout, checkin,
    ):
        if fn.__name__ not in tools:
            continue
        mcp.add_tool(fn, name=fn.__name__)

    return mcp