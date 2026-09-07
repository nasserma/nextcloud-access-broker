"""D6.7 regression tests: multi-item grants must pair EACH item's path
with ITS OWN mode at the wall.

Regression context (live test, Sep 7 2026): the wall built Grant entries
as Grant(path=rec.path, mode=item["mode"]) — rec.path is the FIRST item's
path. A multi-item grant [item0=read A, item1=write B] therefore became
(read A, write A): item1's write widened item0's scope (privilege
escalation) and B was unreachable despite the human approving it.

Mocking rules (from the plan): the WebDAV CLIENT is mocked; the path
checker is NOT.
"""

from datetime import datetime

import pytest

from broker.grants import GrantStore
from broker.nextcloud import AccessRefused, NextcloudClient, NextcloudLayer

T0 = datetime(2026, 9, 7, 12, 0, 0)  # noqa: DTZ001 (injected clock)
PASSWORD = "app-password-do-not-log"


class FakeWebDav:
    def __init__(self):
        self.calls = []

    def propfind(self, path):
        self.calls.append(("PROPFIND", path))
        return {"ok": True}

    def get(self, path):
        self.calls.append(("GET", path))
        return {"ok": True}

    def put(self, path, data):
        self.calls.append(("PUT", path))
        return {"ok": True}

    def move(self, src, dst):
        self.calls.append(("MOVE", src))
        return {"ok": True}

    def delete(self, path):
        self.calls.append(("DELETE", path))
        return {"ok": True}

    def mkcol(self, path):
        self.calls.append(("MKCOL", path))
        return {"ok": True}


@pytest.fixture()
def layer(tmp_path):
    store = GrantStore(db_path=tmp_path / "grants.sqlite3", now=lambda: T0)
    dav = FakeWebDav()
    nc = NextcloudLayer(
        store=store,
        clients={"personal": NextcloudClient(url="https://x", username="u", password=PASSWORD, dav=dav)},
        audit=None,
        now=lambda: T0,
    )
    return nc, dav, store


def grant_items(store, items, expiry="8h"):
    req = store.create_request(instance="personal", reason="test", items=items)
    store.approve(req.id, expiry=expiry)
    return req.id


def test_second_item_path_is_reachable(layer):
    """Item[1+] of a multi-item grant authorizes ITS OWN path (the bug:
    only item[0]'s path was ever grantable)."""
    nc, dav, store = layer
    grant_items(store, [
        {"path": "a/one.txt", "mode": "read"},
        {"path": "b/two.txt", "mode": "read"},
    ])
    nc.read("personal", "b/two.txt")


def test_write_item_does_not_widen_read_item_path(layer):
    """A write item must NOT authorize writes on item[0]'s path: the
    escalation shape from the live test (write-mode paired with item[0]'s
    path allowed writing anywhere under item[0])."""
    nc, dav, store = layer
    grant_items(store, [
        {"path": "readonly/dir", "mode": "read"},
        {"path": "elsewhere/notes.txt", "mode": "write"},
    ])
    with pytest.raises(AccessRefused):
        nc.write("personal", "readonly/dir/injected.txt", b"x")


def test_write_still_lands_on_its_own_item_path(layer):
    nc, dav, store = layer
    grant_items(store, [
        {"path": "readonly/dir", "mode": "read"},
        {"path": "elsewhere/notes.txt", "mode": "write"},
    ])
    nc.write("personal", "elsewhere/notes.txt", b"payload")
    assert ("PUT", "elsewhere/notes.txt") in dav.calls


def test_read_item_does_not_lift_write_mode(layer):
    """Mirror of the escalation: a read item must not become a write grant
    on its own path via a later write item."""
    nc, dav, store = layer
    grant_items(store, [
        {"path": "docs/read.txt", "mode": "read"},
        {"path": "other/write.txt", "mode": "write"},
    ])
    with pytest.raises(AccessRefused):
        nc.write("personal", "docs/read.txt", b"x")


def test_single_item_grants_unchanged(layer):
    """Single-item behavior is byte-identical to pre-fix (no regression)."""
    nc, dav, store = layer
    grant_items(store, [{"path": "solo/file.txt", "mode": "read"}])
    nc.read("personal", "solo/file.txt")
    assert ("GET", "solo/file.txt") in dav.calls
    with pytest.raises(AccessRefused):
        nc.read("personal", "solo/other.txt")


def test_gated_list_uses_each_items_path(layer):
    """The grant-gated list path (discovery=false instances) had the same
    first-item bug with its own null-guard variant."""
    nc, dav, store = layer
    grant_items(store, [
        {"path": "first/dir", "mode": "read"},
        {"path": "second/dir", "mode": "read"},
    ])
    nc.list("personal", "second/dir")
    assert ("PROPFIND", "second/dir") in dav.calls