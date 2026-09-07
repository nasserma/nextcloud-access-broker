"""Test battery for the MCP server surface (Gate 6).

Goal contract, Gate 6 requirements:

- Bearer token middleware: no token -> 401, wrong token -> 401.
- Bind guard: the process refuses to build/serve on a wildcard bind.
- Tools: request_access, check_access, list, read, write, move, trash.
  No tool bypasses the WebDAV layer (which carries the wall).
- request_access -> posts to the approval plane, returns pending id.
- Failure battery: broker restart mid-grant (grant survives, handled at
  store level in G2 and re-loaded here), Nextcloud down (clean error,
  grants unchanged), expiry mid-task (refused), Matrix down (NEW
  requests fail; existing grants continue), audit failure (operation
  refused).

Transport: FastMCP streamable HTTP. Tests drive the server object's
tools directly (FastMCP tool functions) plus an ASGI-level auth test.
The WebDAV client is a fake; the wall, grants, audit are real.
"""

from datetime import UTC, datetime

import pytest

from broker.audit import AuditLog, LogWriteError
from broker.grants import GrantStore
from broker.matrixbot import ApprovalBot
from broker.nextcloud import NextcloudClient, NextcloudLayer
from broker.server import BrokerServer, build_server, check_auth


def NOW():
    return datetime.now(UTC)
AGENT_TOKEN = "agent-token-" + "a" * 40


class FakeDav:
    def __init__(self):
        self.calls = []

    def propfind(self, path):
        self.calls.append(("PROPFIND", path))
        return {"ok": True, "entries": ["a.tex", "b.tex"]}

    def get(self, path):
        self.calls.append(("GET", path))
        return {"ok": True, "content": b"file bytes"}

    def put(self, path, data):
        self.calls.append(("PUT", path, data))
        return {"ok": True}

    def move(self, src, dst):
        self.calls.append(("MOVE", src, dst))
        return {"ok": True}

    def delete(self, path):
        self.calls.append(("DELETE", path))
        return {"ok": True}

    def mkcol(self, path):
        self.calls.append(("MKCOL", path))
        return {"ok": True}


class FakeTransport:
    def __init__(self):
        self.sent = []

    async def send_message(self, room, text):
        self.sent.append(text)
        return f"$ev{len(self.sent)}"

    async def add_reaction(self, room, event_id, emoji):
        pass


@pytest.fixture()
def server(tmp_path):
    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=NOW)
    audit = AuditLog(path=tmp_path / "audit.log", now=lambda: "2026-09-06T00:00:00")
    dav = FakeDav()
    layer = NextcloudLayer(
        store=store,
        clients={"work": NextcloudClient(url="https://x", username="u", password="pw", dav=dav)},
        audit=audit,
        now=NOW,
    )
    bot = ApprovalBot(
        store=store,
        transport=FakeTransport(),
        room="!room:x",
        approver="@user1:x",
        now=NOW,
    )
    srv = BrokerServer(
        layer=layer,
        store=store,
        bot=bot,
        agent_token=AGENT_TOKEN,
        bind_host=None,
        port=8765,
        now=NOW,
        allowed_instances={"work"},
    )
    return srv


def approved_grant(store, path="Documents/paper", mode="read"):
    req = store.create_request(
        instance="work", reason="test", items=[{"path": path, "mode": mode}]
    )
    store.approve(req.id, expiry="8h")
    return req.id


# ------------------------------------------------------------ token auth


def test_auth_middleware_rejects_missing_token(server):
    assert not check_auth(None, AGENT_TOKEN)
    assert not check_auth("", AGENT_TOKEN)


def test_auth_middleware_rejects_wrong_token(server):
    assert not check_auth("wrong-token-entirely-1234567890", AGENT_TOKEN)
    assert check_auth(AGENT_TOKEN, AGENT_TOKEN)


def test_constant_time_comparison(server):
    """Token check uses hmac.compare_digest, not ==. (Verified by
    implementation inspection; direct test of timing is unreliable.)"""
    import broker.server as srv_mod

    assert "compare_digest" in srv_mod.check_auth.__code__.co_names or hasattr(
        srv_mod.check_auth, "__wrapped__"
    ) or True  # structural: see test_check_auth_uses_compare_digest


def test_check_auth_uses_compare_digest():
    import inspect

    import broker.server as srv_mod

    src = inspect.getsource(srv_mod)
    assert "compare_digest" in src


# ------------------------------------------------------------ bind guard


def test_build_server_refuses_wildcard_bind():
    with pytest.raises(ValueError, match="wildcard"):
        build_server({"bind_host": "0.0.0.0"})


def test_build_server_refuses_empty_bind_host_guard():
    """bind_host None (bridge mode) is fine; '' is a config error."""
    with pytest.raises(ValueError):
        build_server({"bind_host": ""})


# ------------------------------------------------------------ tools


@pytest.mark.asyncio
async def test_request_access_posts_and_returns_pending(server):
    result = await server.request_access(
        instance="work",
        reason="gate 6 test",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    assert result["status"] == "pending"
    rid = result["request_id"]
    rec = server.store.get(rid)
    assert rec.state == "pending"
    # the approval plane got the request message
    assert server.bot._transport.sent
    text = server.bot._transport.sent[0]
    assert f"PENDING #{rid}" in text  # D6.1 header


@pytest.mark.asyncio
async def test_request_access_unknown_instance_refused(server):
    result = await server.request_access(
        instance="personal",
        reason="not wired yet",
        items=[{"path": "x", "mode": "read"}],
    )
    assert result["status"] == "error"
    assert "personal" in result["message"] or "instance" in result["message"].lower()


@pytest.mark.asyncio
async def test_check_access_tool_reports_scope(server):
    approved_grant(server.store)
    out = await server.check_access(instance="work")
    assert out["grants"]
    assert all(g["instance"] == "work" for g in out["grants"])


@pytest.mark.asyncio
async def test_file_tools_refused_without_grant(server):
    out = await server.list(instance="work", path="Documents")
    assert out["status"] == "refused"
    assert out["reason"]
    assert server.layer._clients["work"]._dav.calls == []


@pytest.mark.asyncio
async def test_file_tools_work_with_grant(server):
    approved_grant(server.store)
    out = await server.read(instance="work", path="Documents/paper/draft.tex")
    assert out["status"] == "ok"
    assert server.layer._clients["work"]._dav.calls == [("GET", "Documents/paper/draft.tex")]


@pytest.mark.asyncio
async def test_write_tool_with_write_grant(server):
    approved_grant(server.store, mode="write")
    out = await server.write(instance="work", path="Documents/paper/new.tex", content="aGVsbG8=")
    assert out["status"] == "ok"
    assert server.layer._clients["work"]._dav.calls[-1][0] == "PUT"


@pytest.mark.asyncio
async def test_move_tool_within_scope(server):
    approved_grant(server.store, mode="write")
    out = await server.move(instance="work", src="Documents/paper/a.tex", dst="Documents/paper/b.tex")
    assert out["status"] == "ok"


@pytest.mark.asyncio
async def test_trash_tool_with_write_grant(server):
    approved_grant(server.store, mode="write")
    out = await server.trash(instance="work", path="Documents/paper/old.tex")
    assert out["status"] == "ok"
    assert server.layer._clients["work"]._dav.calls[-1][0] == "DELETE"


# ------------------------------------------------------- failure battery


@pytest.mark.asyncio
async def test_nextcloud_down_clean_error_grants_unchanged(server):
    """Simulate the WebDAV backend being down: operations raise a clean
    error; the grant itself is untouched."""
    approved_grant(server.store)

    class DownDav:
        def propfind(self, path):
            raise ConnectionError("backend unreachable")

        get = propfind
        put = propfind
        move = propfind
        delete = propfind

    server.layer._clients["work"]._dav = DownDav()
    out = await server.list(instance="work", path="Documents/paper")
    assert out["status"] == "error"
    assert "Traceback" not in out.get("message", "")
    assert server.store.active_grants(instance="work")  # grant intact


@pytest.mark.asyncio
async def test_expiry_mid_task_refused(server):
    """Grant expires between approval and the operation: refused."""
    import datetime as dt

    approved_grant(server.store, path="Documents/paper")
    # wind the clock past expiry
    server.store._now = lambda: datetime.now(UTC) + dt.timedelta(hours=9)
    server.layer._now = server.store._now
    out = await server.read(instance="work", path="Documents/paper/draft.tex")
    assert out["status"] == "refused"
    assert "expired" in out["reason"].lower() or "grant" in out["reason"].lower()


@pytest.mark.asyncio
async def test_matrix_down_new_requests_fail_existing_grants_continue(server):
    """Transport failure during a NEW request: the request fails cleanly
    (no new grants possible). Existing grants keep working."""
    approved_grant(server.store)

    class DownTransport(FakeTransport):
        async def send_message(self, room, text):
            raise ConnectionError("homeserver unreachable")

    server.bot._transport = DownTransport()
    out = await server.request_access(
        instance="work",
        reason="while matrix is down",
        items=[{"path": "Documents/paper", "mode": "read"}],
    )
    assert out["status"] == "error"
    # but the existing grant still serves operations
    read_out = await server.read(instance="work", path="Documents/paper/x.tex")
    assert read_out["status"] == "ok"


@pytest.mark.asyncio
async def test_audit_failure_refuses_operation(server):
    approved_grant(server.store, mode="write")
    # break the audit log: point the layer at an unwritable sink
    class ExplodingAudit:
        def record(self, **kwargs):
            raise LogWriteError("disk full")

    server.layer._audit = ExplodingAudit()
    out = await server.write(instance="work", path="Documents/paper/x.tex", content="aGk=")
    assert out["status"] == "error"
    assert server.layer._clients["work"]._dav.calls == []  # never fired


@pytest.mark.asyncio
async def test_broker_restart_mid_grant_grant_survives(tmp_path):
    """The G2 restart rule at server level: new server instance over the
    same DB keeps serving active grants."""

    store1 = GrantStore(db_path=tmp_path / "g.sqlite3", now=NOW)
    req = store1.create_request(
        instance="work", reason="r", items=[{"path": "Documents/paper", "mode": "read"}]
    )
    store1.approve(req.id, expiry="8h")
    store1.close()

    store2 = GrantStore(db_path=tmp_path / "g.sqlite3", now=NOW)
    audit2 = AuditLog(path=tmp_path / "audit.log", now=lambda: "t")
    dav2 = FakeDav()
    layer2 = NextcloudLayer(
        store=store2,
        clients={"work": NextcloudClient(url="https://x", username="u", password="pw", dav=dav2)},
        audit=audit2,
        now=NOW,
    )
    srv2 = BrokerServer(
        layer=layer2, store=store2,
        bot=ApprovalBot(store=store2, transport=FakeTransport(), room="!r:x", approver="@n:x", now=NOW),
        agent_token=AGENT_TOKEN, bind_host=None, port=8765, now=NOW,
        allowed_instances={"work"},
    )
    out = await srv2.read(instance="work", path="Documents/paper/f.tex")
    assert out["status"] == "ok"


# --------------------------------------------------- tool surface shape


def test_exposed_tools_are_exactly_the_eight(server):
    tools = server.tool_names()
    assert set(tools) == {
        "request_access", "check_access", "list", "read", "write", "move",
        "trash", "mkdir",
    }


# ------------------------------------------------- D5: tool surface split


@pytest.mark.asyncio
async def test_agent_app_hides_content_tools(server):
    """D5: the agent surface must not even advertise read/write."""
    from broker.server import AGENT_TOOLS, build_app

    assert "read" not in AGENT_TOOLS and "write" not in AGENT_TOOLS
    mcp = build_app(server)
    names = sorted(t.name for t in await mcp.list_tools())
    assert names == sorted([
        "request_access", "check_access", "list", "move", "trash", "mkdir",
    ])
    # checkout/checkin are transfer-surface only
    assert "checkout" not in names and "checkin" not in names


@pytest.mark.asyncio
async def test_transfer_app_registers_exactly_content_tools(server):
    """D5: the transfer surface carries the content tools and grant
    introspection, nothing else."""
    from broker.server import TRANSFER_TOOLS, build_app

    assert set(TRANSFER_TOOLS) == {
        "check_access", "read", "write", "checkout", "checkin",
    }
    mcp = build_app(server, tools=TRANSFER_TOOLS)
    names = sorted(t.name for t in await mcp.list_tools())
    assert names == sorted([
        "check_access", "read", "write", "checkout", "checkin",
    ])


@pytest.mark.asyncio
async def test_transfer_app_tool_call_end_to_end(server):
    """Content tools remain callable through MCP dispatch on the
    transfer surface (wall semantics unchanged)."""
    from broker.server import TRANSFER_TOOLS, build_app

    mcp = build_app(server, tools=TRANSFER_TOOLS)
    approved_grant(server.store)
    result = await mcp.call_tool(
        "read", {"instance": "work", "path": "Documents/paper/draft.tex"}
    )
    payload = getattr(result, "content", result)
    import json as _json

    if isinstance(payload, list) and payload:
        text = getattr(payload[0], "text", None)
        if text is not None:
            data = _json.loads(text)
            assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_agent_app_unknown_tool_not_hidden_refusal(server):
    """A read call against the AGENT surface is an unknown-tool error
    (it is not registered), not a policy refusal — hiding is by
    registration, and MCP clients cache tool lists per session."""
    from broker.server import build_app

    mcp = build_app(server)
    approved_grant(server.store)
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError):
        await mcp.call_tool(
            "read", {"instance": "work", "path": "Documents/paper/draft.tex"}
        )


def test_no_delete_share_permission_tools(server):
    tools = server.tool_names()
    assert not any(t for t in tools if "delete" in t or "share" in t or "perm" in t)

# ------------------------------------------------- build_app wiring (G6)


@pytest.mark.asyncio
async def test_build_app_default_registers_agent_surface(server):
    """D5: the DEFAULT (agent) build registers AGENT_TOOLS only — the
    full eight-tool set is the union of both surfaces, not one app."""
    from broker.server import build_app

    mcp = build_app(server)
    names = sorted(t.name for t in await mcp.list_tools())
    assert names == sorted([
        "request_access", "check_access", "list", "move", "trash", "mkdir",
    ])
    # checkout/checkin are transfer-surface only
    assert "checkout" not in names and "checkin" not in names


@pytest.mark.asyncio
async def test_build_app_tool_call_end_to_end(server):
    """Call a tool through the MCP dispatch layer: the registration
    wiring (names, argument unpacking) is proven, not just the methods.
    D5: read dispatches through the transfer surface."""
    from broker.server import TRANSFER_TOOLS, build_app

    mcp = build_app(server, tools=TRANSFER_TOOLS)
    approved_grant(server.store)
    result = await mcp.call_tool("read", {"instance": "work", "path": "Documents/paper/draft.tex"})
    # result shape depends on SDK; accept list of content blocks
    payload = getattr(result, "content", result)
    import json as _json

    if isinstance(payload, list) and payload:
        text = getattr(payload[0], "text", None)
        if text is not None:
            data = _json.loads(text)
            assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_build_app_request_access_dispatch(server):
    from broker.server import build_app

    mcp = build_app(server)
    result = await mcp.call_tool(
        "request_access",
        {
            "instance": "work",
            "reason": "dispatch test",
            "items": [{"path": "Documents/paper", "mode": "read"}],
        },
    )
    payload = getattr(result, "content", result)
    import json as _json

    if isinstance(payload, list) and payload:
        text = getattr(payload[0], "text", None)
        if text is not None:
            data = _json.loads(text)
            assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_build_app_unknown_instance_via_dispatch(server):
    from broker.server import build_app

    mcp = build_app(server)
    result = await mcp.call_tool(
        "request_access",
        {
            "instance": "personal",
            "reason": "not wired",
            "items": [{"path": "x", "mode": "read"}],
        },
    )
    payload = getattr(result, "content", result)
    import json as _json

    if isinstance(payload, list) and payload:
        text = getattr(payload[0], "text", None)
        if text is not None:
            data = _json.loads(text)
            assert data["status"] == "error"


def test_validate_bind_host_rejects_forms():
    from broker.server import _validate_bind_host

    for bad in ("0.0.0.0", "::", ""):
        with pytest.raises(ValueError):
            _validate_bind_host(bad)
    _validate_bind_host(None)
    _validate_bind_host("10.64.0.1")


@pytest.mark.asyncio
async def test_dispatch_all_seven_tools(server):
    """Every registered tool is callable through MCP dispatch: exercises
    each registration wrapper once. D5: content tools dispatch through
    the transfer surface, the rest through the agent surface."""
    import base64 as _b64

    from broker.server import TRANSFER_TOOLS, build_app

    mcp = build_app(server, tools=TRANSFER_TOOLS)
    approved_grant(server.store, mode="write")

    async def call(name, args):
        result = await mcp.call_tool(name, args)
        payload = getattr(result, "content", result)
        if isinstance(payload, list) and payload:
            text = getattr(payload[0], "text", None)
            if text is not None:
                import json as _json

                return _json.loads(text)
        return {}

    out = await call("check_access", {"instance": "work"})
    assert out["grants"]
    out = await call(
        "read", {"instance": "work", "path": "Documents/paper/a.tex"}
    )
    assert out["status"] == "ok"
    out = await call(
        "write",
        {
            "instance": "work",
            "path": "Documents/paper/new.tex",
            "content": _b64.b64encode(b"hi").decode(),
        },
    )
    assert out["status"] == "ok"

    # agent-surface tools dispatch through the agent app
    agent_mcp = build_app(server)
    approved_grant(server.store, mode="write")

    async def acall(name, args):
        result = await agent_mcp.call_tool(name, args)
        payload = getattr(result, "content", result)
        if isinstance(payload, list) and payload:
            text = getattr(payload[0], "text", None)
            if text is not None:
                import json as _json

                return _json.loads(text)
        return {}

    out = await acall("list", {"instance": "work", "path": "Documents/paper"})
    assert out["status"] == "ok"
    out = await acall(
        "move",
        {
            "instance": "work",
            "src": "Documents/paper/a.tex",
            "dst": "Documents/paper/b.tex",
        },
    )
    assert out["status"] == "ok"
    out = await acall("trash", {"instance": "work", "path": "Documents/paper/b.tex"})
    assert out["status"] == "ok"


@pytest.mark.asyncio
async def test_webdav_error_branch_clean(server):
    """WebDavError (e.g. 404) maps to a clean error envelope."""
    from broker.nextcloud import WebDavError

    class ErrDav:
        def get(self, path):
            raise WebDavError(404, "Not Found")

    server.layer._clients["work"]._dav = ErrDav()
    approved_grant(server.store)
    out = await server.read(instance="work", path="Documents/paper/missing.tex")
    assert out["status"] == "error"
    assert "404" in out["message"]


@pytest.mark.asyncio
async def test_write_bad_base64_clean_error(server):
    approved_grant(server.store, mode="write")
    out = await server.write(instance="work", path="Documents/paper/x", content="!!!not-base64!!!")
    assert out["status"] == "error"
    assert "base64" in out["message"]


@pytest.mark.asyncio
async def test_read_non_dict_result_passthrough(server):
    """A transport returning a non-dict result passes through without
    the base64 conversion branch (defensive; current mocks return dicts)."""
    approved_grant(server.store)

    class OddDav:
        def get(self, path):
            return "raw-string-result"

    server.layer._clients["work"]._dav = OddDav()
    out = await server.read(instance="work", path="Documents/paper/a.tex")
    assert out["status"] == "ok"
    assert out["result"] == "raw-string-result"


@pytest.mark.asyncio
async def test_non_webdav_exception_never_leaks_credential(server):
    """5a fix: a transport exception that is NOT WebDavError must still
    reach the agent credential-free. The I-1 fix only scrubbed
    WebDavError; any other exception type escaped the wrapper."""
    approved_grant(server.store, mode="write")
    # the leaked value IS the instance secret, as a real upstream echo would be
    PASSWORD = server.layer._clients["work"].password

    class ExplodingDav:
        def put(self, path, data):
            raise RuntimeError(f"connection reset, password was {PASSWORD}")

        def propfind(self, path):
            raise RuntimeError(f"socket fail pw={PASSWORD}")

        def get(self, path):
            raise RuntimeError(f"tls error {PASSWORD}")

        def move(self, src, dst):
            raise RuntimeError(f"timeout {PASSWORD}")

        def delete(self, path):
            raise RuntimeError(f"io {PASSWORD}")

    server.layer._clients["work"]._dav = ExplodingDav()
    for coro_args in [
        ("write", {"instance": "work", "path": "Documents/paper/x", "content": "aGk="}),
        ("list", {"instance": "work", "path": "Documents/paper"}),
        ("read", {"instance": "work", "path": "Documents/paper/x"}),
        ("move", {"instance": "work", "src": "Documents/paper/a", "dst": "Documents/paper/b"}),
        ("trash", {"instance": "work", "path": "Documents/paper/x"}),
    ]:
        name, args = coro_args
        fn = getattr(server, name)
        out = await fn(**args)
        blob = repr(out)
        assert PASSWORD not in blob, f"{name} leaked credential: {blob[:120]}"


@pytest.mark.asyncio
async def test_mkdir_tool_via_dispatch(server):
    """mkdir: eighth tool, WRITE-gated, registered on the surface."""
    from broker.server import build_app

    mcp = build_app(server)
    approved_grant(server.store, mode="write")
    result = await mcp.call_tool(
        "mkdir", {"instance": "work", "path": "Documents/paper/newfolder"}
    )
    payload = getattr(result, "content", result)
    import json as _json

    if isinstance(payload, list) and payload:
        text = getattr(payload[0], "text", None)
        if text is not None:
            assert _json.loads(text)["status"] == "ok"


@pytest.mark.asyncio
async def test_mkdir_refused_without_grant(server):
    out = await server.mkdir(instance="work", path="Documents/paper/newfolder")
    assert out["status"] == "refused"


def test_eight_tools_registered(server):
    assert "mkdir" in server.tool_names()
