"""Tests for the D5 checkout model (lock/unlock verbs + CLI checkout).

The adapter gains lock/unlock over webdav3's native LOCK/UNLOCK
(requests map has both; 423 maps to ResourceLocked). The layer gains
checkout/checkin semantics; the CLI folds fetch+lock into checkout
and push+unlock into checkin.

files_lock caveat (documented): LOCK requires the files_lock app on
the instance; 506/405 degrades to a clean refusal, never a crash.
"""


import pytest

from broker.webdav_adapter import WebDavAdapter


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.content = b""


class FakeSession:
    """Records requests; answers LOCK with a token."""

    def __init__(self, lock_status=200, unlock_status=200, token="opaquelocktoken:abc"):
        self.requests = []
        self.lock_status = lock_status
        self.unlock_status = unlock_status
        self.token = token

    auth = None

    def request(self, method, url, auth=None, headers=None, timeout=None,
                cert=None, data=None, stream=None, verify=None):
        self.requests.append({"method": method, "url": url, "headers": headers})
        if method == "LOCK":
            return FakeResponse(self.lock_status, {"Lock-Token": f"<{self.token}>"})
        if method == "UNLOCK":
            return FakeResponse(self.unlock_status)
        return FakeResponse(200)


def _adapter(monkeypatch, session=None):
    adapter = WebDavAdapter("http://nc", "user", "pw")
    session = session or FakeSession()
    adapter._client.session = session
    return adapter, session


def test_adapter_lock_returns_token(monkeypatch):
    adapter, session = _adapter(monkeypatch)
    out = adapter.lock("Documents/paper/a.tex")
    assert out["ok"] is True
    assert out["lock_token"] == "opaquelocktoken:abc"
    assert session.requests[0]["method"] == "LOCK"


def test_adapter_unlock_sends_token(monkeypatch):
    adapter, session = _adapter(monkeypatch)
    out = adapter.unlock("Documents/paper/a.tex", "opaquelocktoken:abc")
    assert out["ok"] is True
    req = session.requests[0]
    assert req["method"] == "UNLOCK"
    assert req["headers"].get("Lock-Token") == "<opaquelocktoken:abc>"


def test_adapter_lock_already_locked_423(monkeypatch):
    from webdav3.exceptions import ResourceLocked

    adapter, _session = _adapter(monkeypatch, FakeSession(lock_status=423))
    with pytest.raises(Exception) as exc_info:
        adapter.lock("a.tex")
        assert isinstance(exc_info.value, ResourceLocked)


def test_adapter_unlock_no_lock_412(monkeypatch):
    adapter, _session = _adapter(monkeypatch, FakeSession(unlock_status=412))
    from broker.nextcloud import WebDavError

    with pytest.raises(WebDavError) as exc_info:
        adapter.unlock("a.tex", "tok")
    assert exc_info.value.status == 412


def test_adapter_lock_timeout_header(monkeypatch):
    adapter, session = _adapter(monkeypatch)
    adapter.lock("a.tex", timeout=3600)
    assert any("Second-3600" in str(r["headers"]) for r in session.requests)


def test_adapter_unlock_requires_token(monkeypatch):
    adapter, _ = _adapter(monkeypatch)
    with pytest.raises(ValueError, match="lock_token"):
        adapter.unlock("a.tex", "")


def test_adapter_put_with_lock_token_carries_if_header(monkeypatch):
    """CRIT regression (found live in 2f): a PUT against a resource
    under our own checkout lock must carry the RFC 4918 If header, or
    the server refuses it with 423 and checkin deadlocks behind its
    own lock. Token-less put keeps the library's normal path."""
    adapter, session = _adapter(monkeypatch)
    out = adapter.put("Documents/paper/a.tex", b"x", lock_token="opaquelocktoken:abc")
    assert out["ok"] is True
    req = session.requests[0]
    assert req["method"] == "PUT"
    ifhdr = req["headers"].get("If")
    assert ifhdr == "(<opaquelocktoken:abc>)"
    # path must be Urn-normalized (leading slash) — same class of bug
    # as the lock 404: hostname+root+path concatenation.
    assert req["url"].endswith("/files/user/Documents/paper/a.tex")


def test_adapter_put_without_lock_token_uses_library_path(monkeypatch):
    adapter, session = _adapter(monkeypatch)
    out = adapter.put("new.txt", b"bytes-here")
    assert out["ok"] is True
    puts = [r for r in session.requests if r["method"] == "PUT"]
    assert len(puts) == 1
    assert "If" not in (puts[0]["headers"] or {})


def test_adapter_lock_405_no_files_lock_app(monkeypatch):
    """files_lock disabled: server answers 405 Method Not Supported —
    must surface as a clean WebDavError, not a crash."""
    adapter, _session = _adapter(monkeypatch, FakeSession(lock_status=405))
    from broker.nextcloud import WebDavError

    with pytest.raises(WebDavError) as exc_info:
        adapter.lock("a.tex")
    assert exc_info.value.status == 405