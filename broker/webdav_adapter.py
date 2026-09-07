"""Production WebDAV adapter: webdav3.Client behind the layer's verbs.

The layer (broker.nextcloud.NextcloudLayer) calls exactly five verbs:
    propfind(path)  -> {"entries": [...]}  (names + type + size + modified)
    get(path)       -> {"content": bytes}
    put(path, data) -> ok
    move(src, dst)  -> ok
    delete(path)    -> ok  (WebDAV DELETE; Nextcloud routes to trash, D1)

webdav3.Client exposes different names and file-oriented semantics
(upload/download take local paths). This adapter translates, keeping
everything in memory (no temp files) and never logging credentials.

Live-verified entry shape (against a real Nextcloud, Sept 6 2026):
    {'created': None, 'name': None, 'size': None, 'modified': None,
     'etag': None, 'content_type': None, 'isdir': True,
     'path': '/remote.php/dav/files/<user>/<name>/'}
Keys: 'isdir' (NOT 'is_dir'), 'name' is None for directories, 'path'
carries the full DAV path. Names are derived from 'path' when 'name'
is absent.
"""

from __future__ import annotations

import io

from webdav3.client import Client as WebDavClient
from webdav3.exceptions import (
    MethodNotSupported,
    NotFound,
    ResponseErrorCode,
)


def _status_from(exc: Exception) -> int:
    """Extract an HTTP status from a webdav3 exception for WebDavError.

    webdav3 does not guarantee a numeric code on every exception type;
    anything without one degrades to 500 rather than guessing, so an
    unmapped upstream error is always surfaced as a server-side failure.
    """
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return code
    return 500


def _self_root_name(username: str) -> str:
    """The user's own root folder name, to skip the self-reference
    entry in listings (webdav3 normalizes the root option to '/', so
    the name must come from the username, not the client)."""
    return username


def _self_reference_paths(username: str, requested: str) -> set[str]:
    """D6b: full DAV paths that denote the LISTED folder itself.

    webdav3 includes the requested folder as the first listing entry.
    The old filter caught only the root case (name == username); a
    non-root listing therefore showed the folder itself as its first
    entry (live evidence Sep 7: listing 'Projects' began with 'dir
    Projects'). The self entry's path is the requested folder's own
    path; path equality distinguishes it from any child, including a
    child that shares the folder's name ('a/b' may legitimately
    contain a child 'a/b/b'). Two prefix shapes cover webdav3
    variants: root-relative (/files/<user>/...) and full DAV path
    (/remote.php/dav/files/<user>/...).
    """
    norm = requested.strip("/")
    base = f"/files/{username}"
    if not norm:
        return {base, f"/remote.php/dav{base}"}
    return {f"{base}/{norm}", f"/remote.php/dav{base}/{norm}"}


def _entry_name(info: dict, username: str) -> str | None:
    """Derive a clean entry name: prefer 'name', fall back to the last
    path segment of 'path' (webdav3 gives name=None for dirs)."""
    name = info.get("name") or ""
    if not name:
        path = info.get("path") or ""
        if path:
            name = path.rstrip("/").split("/")[-1]
    name = str(name).strip("/")
    if not name or name == _self_root_name(username):
        return None
    return name


def _entry_is_dir(info: dict) -> bool:
    """webdav3 uses 'isdir'; tolerate 'is_dir' variants defensively."""
    is_dir = info.get("isdir")
    if isinstance(is_dir, bool):
        return is_dir
    return str(info.get("is_dir", "")).lower() == "true"


class WebDavAdapter:
    """Implements the layer's five verbs over webdav3.Client."""

    def __init__(self, url: str, username: str, password: str):
        """Bind the adapter to one instance's file namespace.

        The root is pinned to files/<username>/: Nextcloud's DAV root
        also hosts principals, calendars, addressbooks, and the trashbin
        namespace, none of which the broker may touch. Pinning here is
        the structural half of the namespace defense (the layer's
        _namespace_guard is the name-based half).
        """
        # Nextcloud file namespace: the DAV root holds principals,
        # calendars, addressbooks; user FILES live under files/<user>/.
        self._client = WebDavClient(
            {
                "webdav_hostname": url.rstrip("/") + "/remote.php/dav",
                "webdav_login": username,
                "webdav_password": password,
                "root": f"/files/{username}",
            }
        )
        self._username = username

    # ------------------------------------------------------------ listing

    def propfind(self, path: str) -> dict:
        """List a folder. The root ('' or '/') lists the top level.
        Returns {"ok": True, "entries": [...]} with name, type, size,
        modified where available. Raises WebDavError (404 / mapped
        status) on upstream failure; upstream messages are never passed
        through raw, so credential leakage from webdav3 cannot occur.
        """
        try:
            if path in ("", "/"):
                infos = self._client.list(get_info=True)
            else:
                infos = self._client.list(path, get_info=True)
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "listing failed") from exc
        entries = []
        # Non-dict info rows and self-reference entries are skipped: a
        # listing must only ever contain real user-visible entries. D6b:
        # the self entry is identified by full PATH equality (the listed
        # folder's own DAV path), not by name — a name-based filter only
        # caught the root case and left every non-root listing showing
        # the folder itself as its first entry.
        self_paths = _self_reference_paths(self._username, path)
        for info in infos or []:
            if not isinstance(info, dict):
                continue
            entry_path = str(info.get("path") or "").rstrip("/")
            if entry_path in self_paths:
                continue
            name = _entry_name(info, self._username)
            if name is None:
                continue
            entries.append(
                {
                    "name": name,
                    "type": "dir" if _entry_is_dir(info) else "file",
                    "size": info.get("size"),
                    "modified": info.get("modified"),
                }
            )
        return {"ok": True, "entries": entries}

    # ------------------------------------------------------------- content

    def get(self, path: str) -> dict:
        """Download a file fully into memory (no temp files) and return
        {"ok": True, "content": bytes}. Raises WebDavError on upstream
        failure with a fixed, credential-free message.
        """
        try:
            chunks = list(self._client.download_iter(path))
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "download failed") from exc
        return {"ok": True, "content": b"".join(chunks)}

    def put(self, path: str, data: bytes, lock_token: str | None = None) -> dict:
        """Upload bytes to a path (in-memory, no temp files) and return
        {"ok": True}. lock_token: when the target is under our own
        checkout lock (D5 checkin), the PUT MUST carry the RFC 4918
        If: (<token>) header — a locked resource refuses token-less
        writes with 423, which would deadlock checkin behind its own
        lock (found live: checkin PUT was rejected by the very lock
        checkout had taken). Without a token the library's normal
        upload path is used. Raises WebDavError; 404 here usually
        means the parent directory does not exist.
        """
        try:
            if lock_token:
                from webdav3.urn import Urn

                self._client.execute_request(
                    action="upload",
                    path=Urn(path).quote(),
                    data=io.BytesIO(data),
                    headers_ext=[f"If: (<{lock_token}>)"],
                )
            else:
                self._client.upload_to(io.BytesIO(data), path)
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found (parent missing?)") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "upload failed") from exc
        return {"ok": True}

    # --------------------------------------------------------------- verbs

    def move(self, src: str, dst: str) -> dict:
        """MOVE src -> dst WITHOUT overwrite (overwrite=False): a move
        can never silently clobber an existing destination file.
        Raises WebDavError on upstream failure.
        """
        try:
            self._client.move(src, dst, overwrite=False)
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "move failed") from exc
        return {"ok": True}

    def mkcol(self, path: str) -> dict:
        """MKCOL a folder (WebDAV folder creation). Requires a WRITE
        grant via the layer's mkdir; the namespace guard applies.

        F2b: webdav3's Client.mkdir swallows MethodNotSupported (the
        405 a server returns for MKCOL-on-existing) and returns True,
        which would report ok for a folder that was already there.
        Pre-existence is therefore detected BEFORE the call via an
        explicit exists() check, and a 405 arriving anyway (race) is
        mapped to the same refusal. F2a: RemoteParentNotFound (raised
        client-side when the parent is missing) and RemoteResource-
        NotFound share the NotFound base, which is what mkcol catches.
        """
        if self._client.check(path):
            from broker.nextcloud import WebDavError

            raise WebDavError(405, "path already exists")
        try:
            self._client.mkdir(path)
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found (parent missing?)") from exc
        except MethodNotSupported as exc:
            # MKCOL-on-existing raced past the exists() check: the
            # server's 405 arrives as MethodNotSupported (only Yandex's
            # Client.mkdir swallows it; other servers raise it here).
            from broker.nextcloud import WebDavError

            raise WebDavError(405, "path already exists") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            if _status_from(exc) == 405:
                raise WebDavError(405, "path already exists") from exc
            raise WebDavError(_status_from(exc), "mkdir failed") from exc
        return {"ok": True}

    def delete(self, path: str) -> dict:
        """WebDAV DELETE. Nextcloud's files_trashbin routes this to the
        user's trash (deviation D1). The trashbin namespace itself is
        unreachable through the layer's namespace guard."""
        try:
            self._client.clean(path)
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "delete failed") from exc
        return {"ok": True}
    # -------------------------------------------------- D5 checkout verbs

    def lock(self, path: str, timeout: int = 0) -> dict:
        """WebDAV LOCK (D5 checkout): create a token-owned lock via
        webdav3's native LOCK (RFC 4918). Nextcloud's files_lock app
        turns this into a server-wide write refusal for every access
        path (WebDAV, sync client, web UI) until UNLOCK.

        timeout: seconds; 0 = server default (files_lock: no expiry
        unless lock_timeout is configured). Returns the lock token —
        callers must persist it; without it the lock cannot be released
        through the broker.

        423 (already locked) surfaces as webdav3's ResourceLocked,
        consistent with the adapter's exception contract. 405 means
        files_lock is not enabled on the instance — a deployment gap,
        not a broker failure.
        """
        try:
            from webdav3.urn import Urn

            response = self._client.execute_request(
                action="lock",
                path=Urn(path).quote(),
                headers_ext=([f"Timeout: Second-{timeout}"] if timeout > 0 else None),
                data=(
                    "<D:lockinfo xmlns:D='DAV:'><D:lockscope><D:exclusive/>"
                    "</D:lockscope><D:locktype><D:write/></D:locktype>"
                    "</D:lockinfo>"
                ),
            )
        except MethodNotSupported as exc:
            from broker.nextcloud import WebDavError

            # files_lock app disabled on the instance: deployment gap
            raise WebDavError(405, "files_lock not enabled on this instance") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "lock failed") from exc
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found") from exc
        token = response.headers.get("Lock-Token", "").strip("<>")
        if not token:
            from broker.nextcloud import WebDavError

            raise WebDavError(500, "lock response carried no token")
        return {"ok": True, "lock_token": token}

    def unlock(self, path: str, lock_token: str) -> dict:
        """WebDAV UNLOCK (D5 checkin): release the token-owned lock.
        The token is mandatory — without it nobody (including the
        broker) can release the lock; only the file owner's UI override
        or an admin force-unlock remains. 412 means not locked; 423
        means the token is wrong or the lock is owned elsewhere.
        """
        if not lock_token:
            raise ValueError("lock_token is required for unlock")
        try:
            from webdav3.urn import Urn

            self._client.execute_request(
                action="unlock",
                path=Urn(path).quote(),
                headers_ext=[
                    f"Lock-Token: <{lock_token}>",
                    f"If: (<{lock_token}>)",
                ],
            )
        except MethodNotSupported as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(405, "files_lock not enabled on this instance") from exc
        except ResponseErrorCode as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(_status_from(exc), "unlock failed") from exc
        except NotFound as exc:
            from broker.nextcloud import WebDavError

            raise WebDavError(404, "Not Found") from exc
        return {"ok": True}
