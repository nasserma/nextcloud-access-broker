"""D6b regression: non-root listings must not include the listed
folder itself as an entry.

Live evidence (Sep 7 2026): listing '/Projects' returned 'dir Projects'
as its first entry; every non-root listing showed the folder itself.
The old filter compared the entry NAME against the username, which only
matches the root self-reference. The fix filters by full DAV path
equality, which also protects a child that legitimately shares the
folder's name ('a/b' containing a child 'a/b/b').
"""

import pytest

from broker.webdav_adapter import WebDavAdapter, _self_reference_paths


@pytest.fixture()
def dav():
    return WebDavAdapter(url="https://x", username="u", password="p")


def _patch_list(monkeypatch, rows):
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return rows
    monkeypatch.setattr(
        type(dav()._client), "list", fake_list, raising=False
    )


def test_non_root_listing_excludes_self_entry(dav, monkeypatch):
    """The exact live failure: 'Projects' listing began with 'Projects'."""
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return [
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/Projects/"},
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/Projects/1804_RHC/"},
            {"name": None, "isdir": False, "size": 10, "path": "/remote.php/dav/files/u/Projects/notes.txt"},
        ]
    monkeypatch.setattr(type(dav._client), "list", fake_list, raising=False)
    out = dav.propfind("Projects")
    names = [e["name"] for e in out["entries"]]
    assert names == ["1804_RHC", "notes.txt"]


def test_child_sharing_folder_name_is_kept(dav, monkeypatch):
    """Path equality (not name equality): a child 'a/b/b' inside 'a/b'
    must survive the filter."""
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return [
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/a/b/"},
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/a/b/b/"},
        ]
    monkeypatch.setattr(type(dav._client), "list", fake_list, raising=False)
    out = dav.propfind("a/b")
    names = [e["name"] for e in out["entries"]]
    assert names == ["b"]


def test_root_listing_self_reference_still_filtered(dav, monkeypatch):
    """Pre-existing behavior preserved: root listing skips the user's
    own root folder entry."""
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return [
            {"name": None, "isdir": True, "path": "/remote.php/dav/files/u/"},
            {"name": "Documents", "isdir": True, "path": "/remote.php/dav/files/u/Documents/"},
        ]
    monkeypatch.setattr(type(dav._client), "list", fake_list, raising=False)
    out = dav.propfind("")
    assert [e["name"] for e in out["entries"]] == ["Documents"]


def test_root_relative_path_shape_filtered(dav, monkeypatch):
    """webdav3 sometimes returns root-relative paths (/files/u/...)."""
    def fake_list(self, remote_path="/", get_info=False, recursive=False):
        return [
            {"name": None, "isdir": True, "path": "/files/u/Projects/"},
            {"name": "kid", "isdir": False, "size": 1, "path": "/files/u/Projects/kid"},
        ]
    monkeypatch.setattr(type(dav._client), "list", fake_list, raising=False)
    out = dav.propfind("Projects")
    assert [e["name"] for e in out["entries"]] == ["kid"]


def test_self_reference_paths_shapes():
    assert _self_reference_paths("u", "") == {"/files/u", "/remote.php/dav/files/u"}
    assert _self_reference_paths("u", "/Projects") == {
        "/files/u/Projects", "/remote.php/dav/files/u/Projects",
    }
