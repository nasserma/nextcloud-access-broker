"""Tests for the production WebDAV adapter (webdav3 behind layer verbs).

The webdav3.Client is monkeypatched at the method level: the adapter's
translation logic (verb mapping, error mapping, byte semantics, entry
shaping) is real; the network layer is faked. This catches interface
mismatches like the one that slipped through Gate 4's mock-only tests.
"""

import pytest

import broker.webdav_adapter as adapter_mod
from broker.nextcloud import WebDavError
from broker.webdav_adapter import WebDavAdapter


@pytest.fixture()
def dav():
    return WebDavAdapter(url="https://cloud.example.com", username="u", password="p")


def patch_method(monkeypatch, name, fn):
    monkeypatch.setattr(adapter_mod.WebDavClient, name, fn, raising=False)


def test_propfind_maps_list(dav, monkeypatch):
    captured = {}

    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        captured["path"] = remote_path
        return [
            {"name": None, "isdir": True, "size": None, "modified": "t1", "path": "/remote.php/dav/files/u/Documents/"},
            {"name": None, "isdir": False, "size": 12, "modified": "t2", "path": "/remote.php/dav/files/u/readme.md"},
        ]

    patch_method(monkeypatch, "list", fake_list)
    out = dav.propfind("Documents")
    assert captured["path"] == "Documents"
    # D6b: the listed folder's own self-reference entry is filtered;
    # only real children remain.
    names = [e["name"] for e in out["entries"]]
    assert names == ["readme.md"]
    assert out["entries"][0]["type"] == "file"


def test_propfind_root_uses_default(dav, monkeypatch):
    captured = {}

    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        captured["path"] = remote_path
        return []

    patch_method(monkeypatch, "list", fake_list)
    dav.propfind("")
    assert captured["path"] == "/"


def test_propfind_404_maps(dav, monkeypatch):
    from webdav3.exceptions import RemoteResourceNotFound

    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        raise RemoteResourceNotFound(path=remote_path)

    patch_method(monkeypatch, "list", fake_list)
    with pytest.raises(WebDavError) as e:
        dav.propfind("Missing")
    assert e.value.status == 404


def test_get_streams_bytes(dav, monkeypatch):
    def fake_iter(self, remote_path):
        yield b"hel"
        yield b"lo"

    patch_method(monkeypatch, "download_iter", fake_iter)
    out = dav.get("a.txt")
    assert out["content"] == b"hello"


def test_get_404_maps(dav, monkeypatch):
    from webdav3.exceptions import RemoteResourceNotFound

    def fake_iter(self, remote_path):
        raise RemoteResourceNotFound(path=remote_path)

    patch_method(monkeypatch, "download_iter", fake_iter)
    with pytest.raises(WebDavError) as e:
        dav.get("missing.txt")
    assert e.value.status == 404


def test_put_uses_upload_to(dav, monkeypatch):
    captured = {}

    class FakeBytesIO:
        def __init__(self, data):
            captured["data"] = data

    def fake_upload_to(self, buff, remote_path):
        captured["path"] = remote_path


    monkeypatch.setattr(adapter_mod.io, "BytesIO", FakeBytesIO)
    patch_method(monkeypatch, "upload_to", fake_upload_to)
    out = dav.put("new.txt", b"bytes-here")
    assert out["ok"]
    assert captured["data"] == b"bytes-here"
    assert captured["path"] == "new.txt"


def test_move_maps(dav, monkeypatch):
    captured = {}

    def fake_move(self, remote_path_from, remote_path_to, overwrite=False):
        captured["src"], captured["dst"] = remote_path_from, remote_path_to

    patch_method(monkeypatch, "move", fake_move)
    dav.move("a.txt", "b.txt")
    assert captured == {"src": "a.txt", "dst": "b.txt"}


def test_delete_maps_to_clean(dav, monkeypatch):
    """D1: the layer's trash verb maps to webdav3 clean() == WebDAV DELETE,
    which Nextcloud routes to the trashbin."""
    captured = {}

    def fake_clean(self, remote_path):
        captured["path"] = remote_path

    patch_method(monkeypatch, "clean", fake_clean)
    dav.delete("old.txt")
    assert captured["path"] == "old.txt"


def test_error_code_extraction(dav, monkeypatch):
    from webdav3.exceptions import ResponseErrorCode

    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        raise ResponseErrorCode(url="https://x", code=403, message="forbidden")

    patch_method(monkeypatch, "list", fake_list)
    with pytest.raises(WebDavError) as e:
        dav.propfind("x")
    assert e.value.status == 403


def test_error_code_missing_defaults_500(dav, monkeypatch):
    from webdav3.exceptions import ResponseErrorCode

    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        raise ResponseErrorCode(url="https://x", code=None, message="unknown")

    patch_method(monkeypatch, "list", fake_list)
    with pytest.raises(WebDavError) as e:
        dav.propfind("x")
    assert e.value.status == 500

def test_propfind_handles_none_name_entries(dav, monkeypatch):
    """Live-found: webdav3 get_info entries can carry name=None (the
    self-reference). Must be skipped, not crash."""
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return [
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/", "created": "2026-01-01", "modified": "2026-01-01"},
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/Documents/"},
            {"name": None, "isdir": False, "size": 3, "path": "/remote.php/dav/files/u/readme.md"},
        ]

    patch_method(monkeypatch, "list", fake_list)
    out = dav.propfind("")
    names = [e["name"] for e in out["entries"]]
    assert names == ["Documents", "readme.md"]


def test_propfind_handles_non_dict_entries(dav, monkeypatch):
    """Genuinely malformed entries are skipped, not crashed on."""
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return [None, "garbage", {"name": "ok.txt", "isdir": False, "path": "/remote.php/dav/files/u/ok.txt"}]

    patch_method(monkeypatch, "list", fake_list)
    out = dav.propfind("")
    assert [e["name"] for e in out["entries"]] == ["ok.txt"]


# ------------------------------------------------------ mkcol (F2a / F2b)

def test_mkcol_maps_and_captures(dav, monkeypatch):
    """Happy path: MKCOL maps to webdav3 mkdir, path passed through."""
    captured = {}

    def fake_check(self, remote_path):
        return False  # not pre-existing

    def fake_mkdir(self, remote_path):
        captured["path"] = remote_path
        return True

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    out = dav.mkcol("Documents/newdir")
    assert captured["path"] == "Documents/newdir"
    assert out == {"ok": True}


def test_mkcol_remote_parent_not_found_maps_to_404_webdav_error(dav, monkeypatch):
    """F2a: webdav3 raises RemoteParentNotFound (client-side, subclass of
    NotFound but NOT of RemoteResourceNotFound) when the parent folder is
    missing. The adapter must map it to a clean WebDavError(404) - not
    let the raw exception escape into the layer's defensive envelope."""
    from webdav3.exceptions import RemoteParentNotFound

    def fake_check(self, remote_path):
        return False

    def fake_mkdir(self, remote_path):
        raise RemoteParentNotFound("/files/u/Documents/missing/newdir/")

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    with pytest.raises(WebDavError) as e:
        dav.mkcol("Documents/missing/newdir")
    assert e.value.status == 404


def test_mkcol_remote_resource_not_found_maps_to_404_webdav_error(dav, monkeypatch):
    """F2a: RemoteResourceNotFound is also a NotFound; mkcol must catch
    the common base so both variants map cleanly."""
    from webdav3.exceptions import RemoteResourceNotFound

    def fake_check(self, remote_path):
        return False

    def fake_mkdir(self, remote_path):
        raise RemoteResourceNotFound(path="/files/u/Documents/newdir/")

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    with pytest.raises(WebDavError) as e:
        dav.mkcol("Documents/newdir")
    assert e.value.status == 404


def test_mkcol_preexisting_folder_refused_not_silent_ok(dav, monkeypatch):
    """F2b: webdav3's Client.mkdir swallows MethodNotSupported (Yandex's
    405-on-existing) and returns True, so mkdir-on-existing must be
    detected BEFORE the call via an explicit check() call. The adapter
    refuses with WebDavError(405, 'path already exists') instead of
    reporting ok for a folder that was already there."""
    def fake_check(self, remote_path):
        return True  # folder already there

    def fake_mkdir(self, remote_path):
        raise AssertionError("mkdir must not run when pre-existence is detected")

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    with pytest.raises(WebDavError) as e:
        dav.mkcol("Documents/already-there")
    assert e.value.status == 405


def test_mkcol_405_response_maps_to_conflict(dav, monkeypatch):
    """F2b: if the upstream still answers 405 (race: created between the
    exists check and MKCOL), the adapter maps it to the same clean
    'path already exists' refusal, not 'mkdir failed'."""
    from webdav3.exceptions import ResponseErrorCode

    def fake_check(self, remote_path):
        return False

    def fake_mkdir(self, remote_path):
        raise ResponseErrorCode(url="https://x", code=405, message="Method Not Allowed")

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    with pytest.raises(WebDavError) as e:
        dav.mkcol("Documents/raced")
    assert e.value.status == 405


def test_mkcol_response_error_code_maps_with_status(dav, monkeypatch):
    """Other ResponseErrorCode on mkdir keeps the upstream status."""
    from webdav3.exceptions import ResponseErrorCode

    def fake_check(self, remote_path):
        return False

    def fake_mkdir(self, remote_path):
        raise ResponseErrorCode(url="https://x", code=403, message="forbidden")

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    with pytest.raises(WebDavError) as e:
        dav.mkcol("Documents/locked")
    assert e.value.status == 403


def test_mkcol_exists_false_proceeds_to_mkdir(dav, monkeypatch):
    """Happy path passes through the pre-existence gate: check() is
    consulted first, then mkdir runs and ok is returned."""
    calls = []

    def fake_check(self, remote_path):
        calls.append(("check", remote_path))
        return False

    def fake_mkdir(self, remote_path):
        calls.append(("mkdir", remote_path))
        return True

    patch_method(monkeypatch, "check", fake_check)
    patch_method(monkeypatch, "mkdir", fake_mkdir)
    out = dav.mkcol("Documents/newdir")
    assert calls == [("check", "Documents/newdir"), ("mkdir", "Documents/newdir")]
    assert out == {"ok": True}
