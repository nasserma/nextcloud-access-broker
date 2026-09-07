"""Broker entrypoint: wire config -> components -> MCP server -> HTTP.

Run: python -m broker.run (from the project root, config.yaml present)

Startup order (fail-closed at every step):
 1. Load config (validated: room, approver, instances, bind guard).
 2. Open the audit log (refuses to start on a corrupt/unwritable log).
 3. Open the grant store (restart-discards pending requests).
 4. Build the WebDAV layer (wall inside), the bot (approval plane),
    and the BrokerServer (tool implementations).
 5. Register tools on an MCPServer (SDK 2.x).
 6. Wrap the Starlette app with bearer-token middleware (constant time).
 7. Serve on host:port from config. host is from config server.bind_host
    (None = all container interfaces; the HOST decides exposure via
    docker-compose - see design doc 3.7 and config comments).

The order is fail-closed: any step raising aborts startup before the
next dependency is built, and before any network socket is opened.
Config errors and a broken audit log are the two most likely failure
points and both are handled inside steps 1-2, before credentials are
passed to any component.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime

from starlette.requests import Request
from starlette.responses import JSONResponse

from broker.audit import AuditLog
from broker.config import Config, load_config
from broker.grants import GrantStore
from broker.logging_setup import SecretScrubFilter, get_logger
from broker.matrixbot import ApprovalBot
from broker.nextcloud import NextcloudClient, NextcloudLayer
from broker.nio_transport import NioTransport
from broker.server import TRANSFER_TOOLS, BrokerServer, build_app, check_auth
from broker.webdav_adapter import WebDavAdapter


def log_startup_posture(config: Config) -> None:
    """One scrub-safe banner line: the broker's authorization posture
    at startup.

    Non-secret by construction: instance NAMES, the discovery flags,
    the approver id, and the bind address all already appear in the
    approval room / support bundle (which the scrub filter sanitizes
    anyway). No passwords, no tokens. Logging after setup_logging has
    installed the SecretScrubFilter, so the line is safe to share even
    if a secret value ever collided with it.
    """
    log = get_logger()
    has_scrub = any(
        isinstance(f, SecretScrubFilter) for f in log.filters
    )
    if not log.handlers or not has_scrub:
        # Banner must never precede scrubbing: without setup_logging the
        # SecretScrubFilter is not installed. Fail closed on posture
        # logging rather than emit an unscrubbed line.
        raise RuntimeError(
            "startup banner skipped: logging not initialized "
            "(setup_logging must run before log_startup_posture)"
        )
    discovery = sorted(
        name
        for name, block in config.instances.items()
        if block.get("discovery")
    )
    bind = config.server["bind_host"] or "0.0.0.0"
    log.info(
        "posture: instances=%d discovery=%s approver=%s bind=%s:%d",
        len(config.instances),
        ",".join(discovery) if discovery else "off",
        config.matrix["approver"],
        bind,
        config.server["port"],
    )


def wire_components(config: Config):
    """Build all components from validated config. Returns (server, mcp).

    Pure construction — no I/O beyond opening the audit log and the
    grant store; connections to Nextcloud and Matrix are opened
    lazily by the components themselves on first use. Never called
    before load_config has validated the same config object.
    """
    def now():
        return datetime.now(UTC)

    # W2: structured logging with mandatory secret scrubbing. Every log
    # line is safe to share BY CONSTRUCTION: all secret values (app
    # passwords, bot token, agent token) are stripped by the filter.
    # First wiring step so even startup failures log scrubbed.
    from broker.logging_setup import setup_logging

    secrets = [block["password"] for block in config.instances.values()]
    secrets.append(config.matrix["bot_token"])
    secrets.append(config.agent["token"])
    secrets.append(config.agent["transfer_token"])
    log = setup_logging(
        level=getattr(config, "logging_level", "info"),
        secrets=[s for s in secrets if s],
    )
    log.info("broker starting: %d instance(s) configured", len(config.instances))
    log_startup_posture(config)

    # Refuses to construct if the log file is corrupt or unwritable —
    # a broker without an audit trail must not start.
    audit = AuditLog(
        path=config.audit["path"],
        now=lambda: datetime.now(UTC).isoformat(),
    )

    # Grant store location: derived from the audit dir (the one data
    # location the config names). Container convention: /data; dev:
    # ./data. Both survive - the derivation only ever splits the
    # directory of the configured audit path.
    audit_dir = str(config.audit["path"]).rsplit("/", 1)[0] if "/" in str(config.audit["path"]) else "."
    store = GrantStore(
        db_path=audit_dir + "/grants.sqlite3",
        now=now,
        allowed_instances=set(config.instances.keys()),
    )

    # One client per configured instance; the store's
    # allowed_instances is the gate, this dict is the plumbing.
    clients = {}
    for name, block in config.instances.items():
        dav = WebDavAdapter(
            url=block["url"],
            username=block["username"],
            password=block["password"],
        )
        clients[name] = NextcloudClient(
            url=block["url"],
            username=block["username"],
            password=block["password"],
            dav=dav,
        )

    layer = NextcloudLayer(
        store=store,
        clients=clients,
        audit=audit,
        now=now,
        discovery_instances={
            name for name, block in config.instances.items() if block.get("discovery")
        },
        principal="agent",  # D5 default; transfer surface overrides per-call
    )

    bot_transport = NioTransport(
        homeserver=config.matrix["homeserver"],
        user_id=config.matrix["bot_user"],
        access_token=config.matrix["bot_token"],
    )
    bot = ApprovalBot(
        store=store,
        transport=bot_transport,
        room=config.matrix["room_id"],
        approver=config.matrix["approver"],
        now=now,
    )

    srv = BrokerServer(
        layer=layer,
        store=store,
        bot=bot,
        agent_token=config.agent["token"],
        bind_host=config.server["bind_host"],
        port=config.server["port"],
        now=now,
        allowed_instances=set(config.instances.keys()),
    )
    mcp = build_app(srv)
    return srv, mcp, bot, bot_transport


class BearerMiddleware:
    """Starlette middleware: reject every request without the expected
    token. Applied BEFORE the MCP app sees anything.

    Order matters: this wraps the MCP/Starlette app as the outermost
    ASGI layer, so unauthenticated traffic is answered with a 401
    before any MCP protocol parsing, tool dispatch, or session state
    is touched. check_auth is the constant-time comparison in
    server.py; non-HTTP scopes (e.g. lifespan) pass through
    untouched — they carry no tool surface.

    D5: instantiated twice — once per token per surface. The agent
    token never authorizes the transfer surface and vice versa;
    cross-token requests die here, before MCP parsing.
    """

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        header = request.headers.get("authorization", "")
        provided = header[7:] if header.lower().startswith("bearer ") else None
        if not check_auth(provided, self.token):
            response = JSONResponse({"error": "unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class _LifespanDriver:
    """Drive ONE surface's ASGI lifespan with correct channel
    semantics: Starlette's Router.lifespan awaits receive() for the
    startup message, sends startup.complete, then awaits receive()
    AGAIN for shutdown — the receive channel must block between
    messages, not replay or close. A queue-based receive keeps the
    sub-app suspended between phases (exactly how uvicorn drives a
    normal app), which keeps the session-manager task group running
    for the surface's whole lifetime."""

    def __init__(self, app):
        self._app = app
        self._incoming = asyncio.Queue()
        self._outgoing = asyncio.Queue()
        self._task = None

    async def _sub_receive(self):
        return await self._incoming.get()

    async def _sub_send(self, message):
        await self._outgoing.put(message)

    async def _run(self):
        await self._app({"type": "lifespan"}, self._sub_receive, self._sub_send)

    async def startup(self):
        """Start the surface's lifespan and wait for startup.complete.
        The driver task stays alive, suspended on its second receive()
        (the shutdown message)."""
        await self._incoming.put({"type": "lifespan.startup"})
        self._task = asyncio.create_task(self._run())
        reply = await self._outgoing.get()
        if reply["type"] != "lifespan.startup.complete":
            exc = self._task.exception() if self._task.done() else None
            raise RuntimeError(f"surface lifespan startup failed: {reply}") from exc

    async def shutdown(self):
        """Deliver shutdown and await the surface's completion."""
        if self._task is None:
            return
        await self._incoming.put({"type": "lifespan.shutdown"})
        try:
            await self._outgoing.get()
        finally:
            await self._task


class PathDispatch:
    """D5: route two MCP surfaces on ONE port by path prefix.

    /mcp*      -> agent surface (AGENT_TOOLS), agent token
    /transfer* -> transfer surface (TRANSFER_TOOLS), transfer token
    anything else -> 404. Each target is already a fully wrapped
    ASGI app (BearerMiddleware around its MCP app), so cross-token
    requests are refused at the middleware, before MCP parsing.
    Prefix matching, not equality: streamable-HTTP mounts subpaths
    (e.g. /mcp/messages) under the mount point.
    """

    def __init__(self, routes: dict[str, object]):
        # longest prefix first so nested prefixes can never shadow
        self._routes = sorted(routes.items(), key=lambda kv: -len(kv[0]))

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            for prefix, app in self._routes:
                if path == prefix or path.startswith(prefix + "/"):
                    await app(scope, receive, send)
                    return
            response = JSONResponse({"error": "not found"}, status_code=404)
            await response(scope, receive, send)
            return
        # Non-HTTP scopes (lifespan): drive EVERY surface's lifespan,
        # not just the first-sorted one. A StreamableHTTPSessionManager
        # whose lifespan never ran raises 'Task group is not
        # initialized' on its first MCP call (CRIT-3: the agent
        # surface answered 500 while the transfer surface worked,
        # because only the first-sorted route was driven). Fail
        # closed: any surface failing startup forwards
        # lifespan.startup.failed and aborts the whole startup.
        drivers = [_LifespanDriver(app) for _, app in self._routes]
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    for driver in drivers:
                        await driver.startup()
                except Exception as exc:  # noqa: BLE001 — ASGI lifespan contract requires forwarding ANY startup failure
                    await send(
                        {
                            "type": "lifespan.startup.failed",
                            "message": str(exc),
                        }
                    )
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                for driver in drivers:
                    await driver.shutdown()
                await send({"type": "lifespan.shutdown.complete"})
                return


def build_dual_app(agent_server, transfer_server, agent_token: str, transfer_token: str) -> PathDispatch:
    """Compose the two D5 surfaces: agent MCP app at /mcp behind the
    agent token, transfer MCP app at /transfer behind the transfer
    token. Both servers may be the same BrokerServer (shared wall,
    grants, audit) — only the registered tool sets differ."""
    agent_mcp = build_app(agent_server)  # AGENT_TOOLS: no read/write
    transfer_mcp = build_app(transfer_server, tools=TRANSFER_TOOLS)
    host = getattr(agent_server, "bind_host", None) or "0.0.0.0"
    # json_response=True: request/response framing closes each POST
    # with a complete JSON body instead of a held-open SSE stream —
    # scripted clients (the CLI, curl probes) can read a full response
    # without stream parsing. Hermes's MCP client speaks both.
    agent_starlette = agent_mcp.streamable_http_app(
        host=host, streamable_http_path="/mcp", json_response=True,
    )
    transfer_starlette = transfer_mcp.streamable_http_app(
        host=host, streamable_http_path="/transfer", json_response=True,
    )
    return PathDispatch(
        {
            "/mcp": BearerMiddleware(agent_starlette, agent_token),
            "/transfer": BearerMiddleware(transfer_starlette, transfer_token),
        }
    )


async def main():
    """Process entrypoint: wire everything, start the Matrix listener
    as a background task, then block on the HTTP server.

    Lifecycle: the listener task runs concurrently with uvicorn for
    the process's whole lifetime. On any exit path from
    uvicorn.serve() — clean stop, error, cancellation — the finally
    block cancels the listener, awaits its termination (swallowing
    the CancelledError it is guaranteed to raise), and closes the
    Matrix transport's connections. Shutdown therefore never leaves
    a dangling sync task or open homeserver session, and it never
    masks the original uvicorn exception: only the awaited-cleanup
    exceptions are caught here.
    """
    config = load_config("config.yaml")
    _srv, _mcp, bot, bot_transport = wire_components(config)
    app = build_dual_app(
        _srv, _srv, config.agent["token"], config.agent["transfer_token"]
    )

    import uvicorn

    from broker.nio_transport import BotListener

    listener = BotListener(
        transport=bot_transport,
        room=config.matrix["room_id"],
        bot=bot,
    )
    listener_task = asyncio.create_task(listener.run())

    bind = config.server["bind_host"] or "0.0.0.0"
    port = config.server["port"]
    # Scrubbed logger, not bare print (W2: every log line is safe to
    # share by construction). Bind/port/approver are non-secret and
    # already in the posture banner; these lines mark the two planes
    # going live.
    log = get_logger()
    log.info("broker listening on %s:%d (agent surface at /mcp, transfer surface at /transfer, bearer auth on both)", bind, port)
    log.info("approval-plane listener running (reactions and replies active)")
    try:
        await uvicorn.Server(uvicorn.Config(app, host=bind, port=port, log_level="info")).serve()
    finally:
        listener_task.cancel()
        try:
            await listener_task
        except (asyncio.CancelledError, Exception) as exc:  # noqa: BLE001 (shutdown)
            get_logger().info("shutdown: listener stopped (%s)", exc)
        await listener.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)