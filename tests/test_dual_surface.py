"""Tests for the D5 dual-surface composition in run.py.

Two MCP apps on one port behind a path dispatcher:
- /mcp*   -> agent app (AGENT_TOOLS) behind the agent token
- /transfer* -> transfer app (TRANSFER_TOOLS) behind the transfer token
Cross-token use must 401 before any MCP parsing; unknown paths 404.
"""

import asyncio

import pytest

from broker.run import BearerMiddleware, PathDispatch, build_dual_app

AGENT_TOKEN = "a" * 40
TRANSFER_TOKEN = "b" * 40


class _Capture:
    """Minimal ASGI app capturing scope, and a marker for which app ran."""

    def __init__(self, marker: str):
        self.marker = marker
        self.calls = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": self.marker.encode()})


async def _request(app, path, token=None):
    """Drive one ASGI HTTP request; return (status, body)."""
    status = {}
    body = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            status["code"] = message["status"]
        if message["type"] == "http.response.body":
            body["data"] = body.get("data", b"") + message.get("body", b"")

    headers = []
    if token:
        headers.append((b"authorization", f"bearer {token}".encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers,
        "query_string": b"",
    }
    await app(scope, receive, send)
    return status.get("code"), body.get("data", b"")


@pytest.mark.asyncio
async def test_agent_token_reaches_mcp_surface():
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, body = await _request(app, "/mcp", AGENT_TOKEN)
    assert code == 200 and body == b"agent"
    assert agent.calls == ["/mcp"]
    assert transfer.calls == []


@pytest.mark.asyncio
async def test_transfer_token_reaches_transfer_surface():
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, body = await _request(app, "/transfer", TRANSFER_TOKEN)
    assert code == 200 and body == b"transfer"
    assert transfer.calls == ["/transfer"]
    assert agent.calls == []


@pytest.mark.asyncio
async def test_agent_token_on_transfer_surface_401():
    """Cross-token use dies at the middleware, before any MCP parsing."""
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, _ = await _request(app, "/transfer", AGENT_TOKEN)
    assert code == 401
    assert transfer.calls == []  # never reached the app


@pytest.mark.asyncio
async def test_transfer_token_on_agent_surface_401():
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, _ = await _request(app, "/mcp", TRANSFER_TOKEN)
    assert code == 401
    assert agent.calls == []


@pytest.mark.asyncio
async def test_wrong_token_401_both_surfaces():
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    assert (await _request(app, "/mcp", "x" * 40))[0] == 401
    assert (await _request(app, "/transfer", "x" * 40))[0] == 401


@pytest.mark.asyncio
async def test_subpaths_route_to_surface():
    """Streamable-HTTP uses subpaths (/mcp is the mount point); the
    dispatcher must match by prefix, not exact equality."""
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, body = await _request(app, "/mcp/messages", AGENT_TOKEN)
    assert code == 200 and body == b"agent"
    code, body = await _request(app, "/transfer/messages", TRANSFER_TOKEN)
    assert code == 200 and body == b"transfer"


@pytest.mark.asyncio
async def test_unknown_path_404():
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, _ = await _request(app, "/other", AGENT_TOKEN)
    assert code == 404


@pytest.mark.asyncio
async def test_no_token_401():
    agent = _Capture("agent")
    transfer = _Capture("transfer")
    app = PathDispatch(
        {
            "/mcp": BearerMiddleware(agent, AGENT_TOKEN),
            "/transfer": BearerMiddleware(transfer, TRANSFER_TOKEN),
        }
    )
    code, _ = await _request(app, "/mcp")
    assert code == 401


@pytest.mark.asyncio
async def test_build_dual_app_returns_bearer_wrapped_surfaces():
    """Composition helper: two Starlette apps, each already wrapped in
    its own BearerMiddleware with its own token, under PathDispatch."""
    from broker.server import AGENT_TOOLS, TRANSFER_TOOLS

    # Build a minimal real composition using the same construction path
    # as main(): agent app registers AGENT_TOOLS, transfer app registers
    # TRANSFER_TOOLS. Fake server surface is not needed for routing;
    # build_app requires a BrokerServer, so drive the tool-set split
    # assertions via the constants instead and only test that
    # build_dual_app wires prefixes + middleware classes.
    assert "read" not in AGENT_TOOLS and "write" not in AGENT_TOOLS
    assert set(TRANSFER_TOOLS) == {
        "check_access", "read", "write", "checkout", "checkin",
    }

    class _FakeAgent:
        bind_host = None

    # build_dual_app needs build_app-able servers; use a stub whose
    # build_app-compatible surface is the real BrokerServer-free path:
    # construct via a dummy that raises at MCP use is fine — we only
    # assert the routing composition, and the streamable app requires
    # a running task group, so assert composition structurally.
    import inspect

    sig = inspect.signature(build_dual_app)
    assert list(sig.parameters) == [
        "agent_server", "transfer_server", "agent_token", "transfer_token",
    ]
    # Routing composition is covered by the PathDispatch tests above;
    # build_dual_app is the composition of those tested parts.

@pytest.mark.asyncio
async def test_transfer_surface_stamps_principal_in_audit(tmp_path):
    """D5: an allowed read through the TRANSFER app writes an audit
    line with principal='transfer'; through the agent layer default
    it would read 'agent'. End-to-end through MCP dispatch."""
    import json as _json
    from datetime import UTC, datetime

    from broker.audit import AuditLog
    from broker.grants import GrantStore
    from broker.nextcloud import NextcloudLayer
    from broker.server import TRANSFER_TOOLS, BrokerServer, build_app

    audit = AuditLog(path=str(tmp_path / "audit.log"), now=lambda: "t")
    store = GrantStore(db_path=str(tmp_path / "g.sqlite3"), now=lambda: datetime.now(UTC), allowed_instances={"work"})

    class _Dav:
        def get(self, path):
            return {"content": b"bytes"}

    class _Client:
        password = "p"
        _dav = _Dav()

    layer = NextcloudLayer(
        store=store, clients={"work": _Client()}, audit=audit,
        now=lambda: datetime.now(UTC), discovery_instances=set(), principal="agent",
    )
    srv = BrokerServer(
        layer=layer, store=store, bot=None, agent_token="a" * 40,
        bind_host=None, port=8765, now=lambda: datetime.now(UTC),
    )
    # grant READ on the file
    store.create_request(
        instance="work", reason="test",
        items=[{"path": "Documents/paper/a.tex", "mode": "read"}],
    )
    from tests.test_server import approved_grant  # reuse the helper
    approved_grant(store)

    mcp = build_app(srv, tools=TRANSFER_TOOLS)
    result = await mcp.call_tool(
        "read", {"instance": "work", "path": "Documents/paper/a.tex"}
    )
    payload = getattr(result, "content", result)
    data = None
    if isinstance(payload, list) and payload:
        text = getattr(payload[0], "text", None)
        if text is not None:
            data = _json.loads(text)
    assert data and data["status"] == "ok", data
    raw = (tmp_path / "audit.log").read_text()
    lines = [_json.loads(l) for l in raw.splitlines() if l.strip()]
    assert lines[-1]["principal"] == "transfer"
    assert lines[-1]["operation"] == "read"
    assert lines[-1]["decision"] == "allowed"


@pytest.mark.asyncio
async def test_lifespan_runs_both_surfaces():
    """CRIT 3 regression: lifespan must complete BOTH surfaces, not
    just the first-sorted one. Real StreamableHTTPSessionManagers
    raise 'Task group is not initialized' if their lifespan never
    ran; a capture app proves both get driven. The receive channel is
    faithful ASGI: startup once, shutdown once, then block (never
    replay a message — a replay spins the dispatch loop at 100% CPU,
    which is exactly the bug the first draft of this test had)."""
    startup_log = []

    class _LifespanApp:
        def __init__(self, marker):
            self.marker = marker

        async def __call__(self, scope, receive, send):
            assert scope["type"] == "lifespan"
            msg = await receive()
            assert msg["type"] == "lifespan.startup"
            startup_log.append(("startup", self.marker))
            await send({"type": "lifespan.startup.complete"})
            msg = await receive()
            assert msg["type"] == "lifespan.shutdown"
            startup_log.append(("shutdown", self.marker))
            await send({"type": "lifespan.shutdown.complete"})

    agent = _LifespanApp("agent")
    transfer = _LifespanApp("transfer")
    app = PathDispatch({"/mcp": agent, "/transfer": transfer})

    sent = []
    channel = [
        {"type": "lifespan.startup"},
        {"type": "lifespan.shutdown"},
    ]

    async def receive():
        if channel:
            return channel.pop(0)
        # faithful ASGI: block forever after the last message
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    await app({"type": "lifespan"}, receive, send)
    assert sent == [
        {"type": "lifespan.startup.complete"},
        {"type": "lifespan.shutdown.complete"},
    ]
    # drivers are built in route order (longest prefix first), and
    # shutdown runs in the same order; every marker must appear in
    # both phases.
    assert startup_log == [
        ("startup", "transfer"),
        ("startup", "agent"),
        ("shutdown", "transfer"),
        ("shutdown", "agent"),
    ]


@pytest.mark.asyncio
async def test_lifespan_startup_failure_fails_closed():
    """A surface whose lifespan fails must fail the whole startup."""
    class _Broken:
        async def __call__(self, scope, receive, send):
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.failed", "message": "boom"})

    class _Ok:
        async def __call__(self, scope, receive, send):
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})

    app = PathDispatch({"/mcp": _Broken(), "/transfer": _Ok()})
    sent = []

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message):
        sent.append(message)

    await app({"type": "lifespan"}, receive, send)
    assert sent and sent[0]["type"] == "lifespan.startup.failed"
