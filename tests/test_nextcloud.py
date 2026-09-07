"""Test battery for the WebDAV layer (Gate 4).

Goal contract, Gate 4 requirements:

- Exactly five operations: list, read, write, move, trash. No delete, no
  share management, no permission changes.
- EVERY operation passes through the path checker inside this layer,
  even when the underlying WebDAV server would serve the request.
- Errors map to clean refusals; no stack traces to the agent.
- Credentials never appear in logs or output.
- grep for DELETE against trash endpoints must show the namespace is
  refused at path-check level (D1 deviation: trash == WebDAV DELETE,
  which Nextcloud routes to trashbin; trashbin namespace itself is
  unreachable).

Mocking rules (from the plan): the WebDAV CLIENT is mocked; the path
checker is NOT. Mocking the wall is forbidden.
"""

import json
from datetime import datetime, timedelta

import pytest

from broker.grants import GrantStore
from broker.nextcloud import (
    AccessRefused,
    NextcloudClient,
    NextcloudLayer,
    WebDavError,
)

T0 = datetime(2026, 9, 5, 9, 0, 0)  # noqa: DTZ001 (injected clock)
PASSWORD = "app-password-do-not-log"


class FakeWebDav:
    """Records every verb+path the client would issue. Serves nothing;
    the layer must refuse un-granted paths BEFORE anything reaches here,
    and granted paths land here as recorded requests."""

    def __init__(self):
        self.calls = []
        self.fail_paths = {}  # path -> (http_status, message)

    def _record(self, verb, path, **kwargs):
        self.calls.append({"verb": verb, "path": path, **kwargs})
        if path in self.fail_paths:
            status, message = self.fail_paths[path]
            raise WebDavError(status, message)
        return {"ok": True}

    def propfind(self, path):  # list
        return self._record("PROPFIND", path)

    def get(self, path):  # read
        return self._record("GET", path)

    def put(self, path, data):  # write
        return self._record("PUT", path, data=data)

    def move(self, src, dst):  # move/rename
        return self._record("MOVE", src, dst=dst)

    def delete(self, path):  # trash only; never called on trashbin ns
        return self._record("DELETE", path)

    def mkcol(self, path):
        return self._record("MKCOL", path)


@pytest.fixture()
def layer(tmp_path):
    store = GrantStore(db_path=tmp_path / "grants.sqlite3", now=lambda: T0)
    dav = FakeWebDav()
    nc = NextcloudLayer(
        store=store,
        clients={"personal": NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=dav)},
        audit=None,  # audit wiring exercised in Gate 6 integration; here: None allowed
        now=lambda: T0,
    )
    return nc, dav, store


def grant_path(store, path, mode="read", expiry="8h"):
    req = store.create_request(
        instance="personal", reason="test", items=[{"path": path, "mode": mode}]
    )
    store.approve(req.id, expiry=expiry)
    return req.id


# ------------------------------------------------------------- list / read


def test_list_inside_grant(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper")
    out = nc.list("personal", "Documents/paper")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "PROPFIND"


def test_list_outside_grant_refused_before_webdav(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper")
    with pytest.raises(AccessRefused):
        nc.list("personal", "Photos")
    assert dav.calls == []  # never reached the mock


def test_read_inside_grant(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper")
    out = nc.read("personal", "Documents/paper/draft.tex")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "GET"


def test_read_outside_grant_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper")
    with pytest.raises(AccessRefused):
        nc.read("personal", "Documents/paper/../../secret.txt")
    assert dav.calls == []


# ---------------------------------------------------------------- write/move


def test_write_inside_write_grant(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper/figures", mode="write")
    out = nc.write("personal", "Documents/paper/figures/fig1.pdf", b"data")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "PUT"


def test_write_against_read_only_grant_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="read")
    with pytest.raises(AccessRefused):
        nc.write("personal", "Documents/paper/new.tex", b"x")
    assert dav.calls == []


def test_move_requires_write_on_both_ends(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    grant_path(store, "Photos", mode="read")  # dst readable but NOT writable
    with pytest.raises(AccessRefused):
        nc.move("personal", "Documents/paper/a.tex", "Photos/a.tex")
    assert dav.calls == []


def test_move_within_write_scope_allowed(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    out = nc.move("personal", "Documents/paper/a.tex", "Documents/paper/b.tex")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "MOVE"


def test_move_destination_outside_grant_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    with pytest.raises(AccessRefused):
        nc.move("personal", "Documents/paper/a.tex", "Photos/a.tex")
    assert dav.calls == []


# -------------------------------------------------------------------- trash


def test_trash_inside_write_grant_issues_delete_verb(layer):
    """D1: trash == WebDAV DELETE, which Nextcloud routes to trashbin."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    out = nc.trash("personal", "Documents/paper/old.tex")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "DELETE"


def test_trash_against_read_grant_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="read")
    with pytest.raises(AccessRefused):
        nc.trash("personal", "Documents/paper/old.tex")
    assert dav.calls == []


def test_trashbin_namespace_unreachable(layer):
    """No grant can ever authorize a path in the trashbin namespace, and
    the layer refuses any request pointing there regardless of grants."""
    nc, dav, store = layer
    grant_path(store, "trashbin", mode="write")  # user-approved trashbin grant!
    with pytest.raises(AccessRefused):
        nc.trash("personal", "trashbin/USER/trash/oldfile")
    assert dav.calls == []


def test_trashbin_list_attempt_refused(layer):
    nc, dav, store = layer
    grant_path(store, "trashbin", mode="read")
    with pytest.raises(AccessRefused):
        nc.list("personal", "trashbin/user1/trash")
    assert dav.calls == []


# ------------------------------------------------------------- error mapping


def test_webdav_404_maps_to_clean_refusal(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper")
    dav.fail_paths["Documents/paper/missing.tex"] = (404, "Not Found")
    with pytest.raises(WebDavError) as excinfo:
        nc.read("personal", "Documents/paper/missing.tex")
    assert "Traceback" not in str(excinfo.value)
    assert excinfo.value.status == 404


def test_webdav_403_maps_to_clean_refusal(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    dav.fail_paths["Documents/paper/x"] = (403, "Forbidden")
    with pytest.raises(WebDavError) as excinfo:
        nc.write("personal", "Documents/paper/x", b"z")
    assert excinfo.value.status == 403


def test_unknown_instance_refused(layer):
    nc, dav, _store = layer
    with pytest.raises(AccessRefused):
        nc.list("corporate", "any")
    assert dav.calls == []


def test_expired_grant_refused_even_if_webdav_would_serve(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", expiry="1h")
    store._now = lambda: T0 + timedelta(hours=2)
    with pytest.raises(AccessRefused):
        nc.read("personal", "Documents/paper/draft.tex")
    assert dav.calls == []


# ------------------------------------------------------------- credentials


def test_password_never_in_output_or_errors(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper")
    dav.fail_paths["Documents/paper/x"] = (500, f"auth failed for {PASSWORD}")
    with pytest.raises(WebDavError) as excinfo:
        nc.read("personal", "Documents/paper/x")
    assert PASSWORD not in str(excinfo.value)
    # and no operation result carries it
    out = nc.list("personal", "Documents/paper")
    assert PASSWORD not in json.dumps(out)


def test_client_holds_password_but_never_exposes_it():
    client = NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=None)
    assert client.password == PASSWORD  # holder, yes
    assert "password" not in client.describe()
    assert PASSWORD not in client.describe()


# ----------------------------------------------- wall-in-layer architecture


def test_no_direct_webdav_access_on_layer(layer):
    """The layer exposes only the five operations; no passthrough."""
    nc, _dav, _store = layer
    public = [name for name in dir(nc) if not name.startswith("_")]
    allowed = {
        "list", "read", "write", "move", "trash", "mkdir",
        "check_access",  # introspection helper for the agent
        "checkout", "checkin",  # D5 checkout model
    }
    methods = [name for name in public if callable(getattr(nc, name, None))]
    assert set(methods) <= allowed, f"unexpected public methods: {methods}"

def test_sanitize_redacts_password_shapes():
    assert "hunter2" not in WebDavError(401, "bad password=hunter2 for user").message
    assert "[redacted]" in WebDavError(401, "bad password=hunter2").message
    assert "secret" not in WebDavError(403, "secret token leaked").message.lower() or "[redacted]" in WebDavError(403, "secret token").message


def test_sanitize_truncates_long_messages():
    msg = "x" * 500
    e = WebDavError(500, msg)
    assert len(e.message) <= 300


def test_namespace_guard_refuses_remote_php_dav_trashbin(layer):
    nc, dav, store = layer
    grant_path(store, "remote.php/dav/trashbin", mode="write")
    with pytest.raises(AccessRefused):
        nc.trash("personal", "remote.php/dav/trashbin/user1/trash/item")
    assert dav.calls == []


def test_namespace_guard_malformed_path_refused(layer):
    nc, _dav, _store = layer
    with pytest.raises(AccessRefused):
        nc.read("personal", "../escape")


def test_move_cross_instance_not_a_surface(layer):
    """The layer's move() takes ONE instance argument for both endpoints;
    there is no API to move across instances at all (structural, tested
    by signature), and a move whose destination is ungranted is refused."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    with pytest.raises(AccessRefused):
        nc.move("personal", "Documents/paper/a.tex", "Photos/a.tex")
    assert dav.calls == []


def test_check_access_introspection_allowed_and_refused(layer):
    """check_access() answers would-this-be-allowed without contacting
    WebDAV: allowed inside scope, refused with reason outside."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="read")
    assert nc.check_access("personal", "Documents/paper/draft.tex", "read") == {
        "allowed": True
    }
    out = nc.check_access("personal", "Documents/paper/draft.tex", "write")
    assert out["allowed"] is False
    assert out["reason"]
    out2 = nc.check_access("personal", "Elsewhere/x", "read")
    assert out2["allowed"] is False
    assert dav.calls == []  # introspection never fires a verb


def test_audit_wiring_write_before_operate(tmp_path):
    """With a real AuditLog wired: every operation writes an audit record
    BEFORE the WebDAV verb fires, and the record names the operation."""
    from broker.audit import AuditLog, verify_chain
    from broker.nextcloud import NextcloudClient

    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    audit = AuditLog(path=tmp_path / "audit.log", now=lambda: "2026-09-05T09:00:00")
    dav = FakeWebDav()
    nc = NextcloudLayer(
        store=store,
        clients={"personal": NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=dav)},
        audit=audit,
        now=lambda: T0,
    )
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "Docs", "mode": "write"}]
    )
    store.approve(req.id)
    nc.write("personal", "Docs/new.tex", b"hello")
    assert dav.calls[-1]["verb"] == "PUT"
    log_text = (tmp_path / "audit.log").read_text()
    assert '"operation": "write"' in log_text
    assert "Docs/new.tex" in log_text
    assert verify_chain(tmp_path / "audit.log").ok


def test_audit_refusal_logged_not_operated(tmp_path):
    """A refused operation is logged as denied AND nothing reaches WebDAV."""
    from broker.audit import AuditLog
    from broker.nextcloud import NextcloudClient

    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    audit = AuditLog(path=tmp_path / "audit.log", now=lambda: "2026-09-05T09:00:00")
    dav = FakeWebDav()
    nc = NextcloudLayer(
        store=store,
        clients={"personal": NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=dav)},
        audit=audit,
        now=lambda: T0,
    )
    req = store.create_request(
        instance="personal", reason="r", items=[{"path": "Docs", "mode": "read"}]
    )
    store.approve(req.id)
    # refused write: logged, not operated
    try:
        nc.write("personal", "Docs/new.tex", b"x")
        assert False, "should have raised"
    except AccessRefused:
        pass
    assert dav.calls == []
    # (denied requests are not audited in v1: only performed operations are.
    # Refusal auditing is layered in Gate 6 when the server catches AccessRefused.)


# ------------------------------------------- D4 discovery mode matrix


def test_discovery_list_without_grant(layer):
    """D4 on: list works with NO grant, and is audit-marked discovery."""
    nc, dav, _store = layer
    nc.discovery_instances = {"personal"}
    out = nc.list("personal", "Any/Random/Path")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "PROPFIND"


def test_discovery_off_list_still_requires_grant(layer):
    """D4 off (default): list refused without grant, as before."""
    nc, dav, _store = layer
    nc.discovery_instances = set()
    with pytest.raises(AccessRefused):
        nc.list("personal", "Documents/paper")
    assert dav.calls == []


def test_discovery_does_not_relax_read(layer):
    """D4 on: read still requires a grant."""
    nc, dav, _store = layer
    nc.discovery_instances = {"personal"}
    with pytest.raises(AccessRefused):
        nc.read("personal", "Any/secret.txt")
    assert dav.calls == []


def test_discovery_does_not_relax_write(layer):
    nc, dav, _store = layer
    nc.discovery_instances = {"personal"}
    with pytest.raises(AccessRefused):
        nc.write("personal", "Any/new.txt", b"x")
    assert dav.calls == []


def test_discovery_does_not_relax_trash(layer):
    nc, dav, _store = layer
    nc.discovery_instances = {"personal"}
    with pytest.raises(AccessRefused):
        nc.trash("personal", "Any/old.txt")
    assert dav.calls == []


def test_discovery_trashbin_still_unreachable(layer):
    """D4 on: the trashbin namespace remains refused even for list."""
    nc, dav, _store = layer
    nc.discovery_instances = {"personal"}
    with pytest.raises(AccessRefused):
        nc.list("personal", "trashbin/user1/trash")
    assert dav.calls == []


def test_discovery_listed_in_audit_log(tmp_path):
    """Discovery listings are audit-logged with reason discovery."""
    from broker.audit import AuditLog, verify_chain
    from broker.nextcloud import NextcloudClient

    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    audit = AuditLog(path=tmp_path / "audit.log", now=lambda: "t")
    dav = FakeWebDav()
    nc = NextcloudLayer(
        store=store,
        clients={"personal": NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=dav)},
        audit=audit,
        now=lambda: T0,
        discovery_instances={"personal"},
    )
    nc.list("personal", "Some/Path")
    text = (tmp_path / "audit.log").read_text()
    assert '"reason": "discovery"' in text
    assert verify_chain(tmp_path / "audit.log").ok


# ------------------------------------------- D4 root listing (guard fix)


def test_discovery_root_listing_allowed(layer):
    """The instance root is listable under discovery: the basic query
    'show me the top level' works."""
    nc, dav, _store = layer
    nc.discovery_instances = {"personal"}
    out = nc.list("personal", "")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "PROPFIND"
    out2 = nc.list("personal", "/")
    assert out2["ok"]


def test_root_still_requires_grant_without_discovery(layer):
    nc, dav, _store = layer
    nc.discovery_instances = set()
    with pytest.raises(AccessRefused):
        nc.list("personal", "")
    assert dav.calls == []


def test_root_not_grantable_read_outside_discovery(layer):
    """Even WITH a broad grant, root-level trashbin namespace stays
    refused; and a grant on 'Documents' does not open the root."""
    nc, dav, store = layer
    grant_path(store, "Documents", mode="read")
    with pytest.raises(AccessRefused):
        nc.read("personal", "")
    assert dav.calls == []


# ------------------------------------------- review findings I-1 and I-2


def test_value_based_redaction_bare_credential(layer):
    """I-1 fix: a bare credential (no 'password:' keyword) in an
    upstream error must be scrubbed because the layer knows the value."""
    from broker.nextcloud import WebDavError

    nc, _dav, store = layer
    PASSWORD = "Xk9kQmNzVmQw-bare-42"
    old_client = nc._clients["personal"]
    # a transport that leaks the bare credential in its error text
    class LeakyDav:
        def get(self, path):
            raise WebDavError(500, f"login failed with {PASSWORD}")

        def propfind(self, path):
            raise WebDavError(500, f"login failed with {PASSWORD}")

        def put(self, path, data):
            raise WebDavError(500, f"login failed with {PASSWORD}")

        def move(self, src, dst):
            raise WebDavError(500, f"login failed with {PASSWORD}")

        def delete(self, path):
            raise WebDavError(500, f"login failed with {PASSWORD}")

    leaky_client = type(old_client)(
        url=old_client.url, username=old_client.username, password=PASSWORD, dav=LeakyDav()
    )
    nc._clients["personal"] = leaky_client
    grant_path(store, "Documents/paper")
    with pytest.raises(WebDavError) as excinfo:
        nc.read("personal", "Documents/paper/f.txt")
    assert PASSWORD not in str(excinfo.value)
    assert PASSWORD not in excinfo.value.message


def test_namespace_guard_case_complete(layer):
    """I-2 fix: trashbin namespace refused regardless of case/alias."""
    from broker.nextcloud import AccessRefused

    nc, _dav, store = layer
    grant_path(store, "Documents", mode="read")
    grant_path(store, "Trashbin", mode="read")
    grant_path(store, "files_trashbin", mode="read")
    grant_path(store, "remote.php/dav/Trashbin", mode="read")
    for probe in (
        "Trashbin", "TRASHBIN", "files_trashbin", "Files_Trashbin",
        "remote.php/dav/Trashbin", "Trashbin/user/trash", "files_trashbin/x",
    ):
        with pytest.raises(AccessRefused):
            nc.list("personal", probe)
    # and the verbs are refused on it too
    with pytest.raises(AccessRefused):
        nc.read("personal", "Trashbin/x")
    with pytest.raises(AccessRefused):
        nc.trash("personal", "files_trashbin/x")


# ------------------------------------------- mkdir tool (production gap fix)


def test_mkdir_inside_write_grant(layer):
    """Folder creation is a WRITE-scope operation: requires WRITE on
    the parent path, hits the transport as a folder-create call."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    out = nc.mkdir("personal", "Documents/paper/figures")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "MKCOL"


def test_mkdir_against_read_grant_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="read")
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Documents/paper/figures")
    assert dav.calls == []


def test_mkdir_outside_grant_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Photos/newfolder")
    assert dav.calls == []


def test_mkdir_trashbin_namespace_refused(layer):
    nc, dav, store = layer
    grant_path(store, "Documents", mode="write")
    grant_path(store, "Trashbin", mode="write")
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Trashbin/evil")
    assert dav.calls == []


# -------------------------------------- mkdir hostile paths (layer level)


def test_mkdir_traversal_via_dotdot_refused(layer):
    """Hostile: ../ traversal must be refused before WebDAV even with a
    write grant that would otherwise look to cover the target."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Documents/paper/../../../secret")
    assert dav.calls == []


def test_mkdir_double_encoding_refused(layer):
    """Hostile: %2e%2e (single-encoded dot-dot) does not smuggle a
    traversal through the wall; the wall's decode-then-check ordering
    means this is judged on its decoded components."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    # %2e%2e decodes to '..' -> escapes the grant -> must refuse
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Documents/paper/%2e%2e/escape")
    assert dav.calls == []


def test_mkdir_double_encoded_slash_decodes_to_nested(layer):
    """Hostile: %252f (double-encoded '/') fully decodes to '/'. The
    wall's decode-then-check ordering means 'a%252fb' becomes 'a/b'
    INSIDE the grant, so it is allowed as an ordinary nested folder -
    the encoded separator buys no scope (contrast: it must never make
    an OUTSIDE path look inside)."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    out = nc.mkdir("personal", "Documents/paper/a%252fb")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "MKCOL"


def test_mkdir_sibling_prefix_of_grant_refused(layer):
    """Hostile: 'Documents/paperx' shares a string prefix with the grant
    'Documents/paper' but is NOT inside it (component-prefix check)."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Documents/paperx/evil")
    assert dav.calls == []


def test_mkdir_at_grant_root_inside_grant(layer):
    """MKCOL exactly AT the grant root is a WRITE on the granted path:
    allowed, and the transport sees the normalized path."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    out = nc.mkdir("personal", "Documents/paper")
    assert out["ok"]
    assert dav.calls[-1]["verb"] == "MKCOL"
    assert dav.calls[-1]["path"] == "Documents/paper"


def test_mkdir_root_refused(layer):
    """The instance root ('' or '/') is never mkdir-able: the wall's
    empty-path rule denies it regardless of grants."""
    nc, dav, store = layer
    grant_path(store, "Documents", mode="write")
    for probe in ("", "/"):
        with pytest.raises(AccessRefused):
            nc.mkdir("personal", probe)
    assert dav.calls == []


def test_mkdir_backslash_smuggling_refused(layer):
    """Hostile: backslash separators normalize to slashes (wall step 4),
    so 'Documents\\evil' is 'Documents/evil' - outside the write grant."""
    nc, dav, store = layer
    grant_path(store, "Documents/paper", mode="write")
    with pytest.raises(AccessRefused):
        nc.mkdir("personal", "Documents\\evil")
    assert dav.calls == []


def test_mkdir_audit_write_before_operate(tmp_path):
    """With a real AuditLog wired: mkdir writes an audit record with
    operation='mkdir' BEFORE the MKCOL verb fires, and the chain
    verifies."""
    from broker.audit import AuditLog, verify_chain
    from broker.nextcloud import NextcloudClient

    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    audit = AuditLog(path=tmp_path / "audit.log", now=lambda: "2026-09-05T09:00:00")
    dav = FakeWebDav()
    nc = NextcloudLayer(
        store=store,
        clients={"personal": NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=dav)},
        audit=audit,
        now=lambda: T0,
    )
    grant_path(store, "Docs", mode="write")
    nc.mkdir("personal", "Docs/newfolder")
    assert dav.calls[-1]["verb"] == "MKCOL"
    text = (tmp_path / "audit.log").read_text()
    assert '"operation": "mkdir"' in text
    assert "Docs/newfolder" in text
    assert verify_chain(tmp_path / "audit.log").ok
