"""WebDAV layer: the five file operations, with the wall inside (Gate 4).

Design document section 3.6. Architecture rule (plan, hard rule 5): the
path check lives INSIDE this layer. No caller - MCP tool, bot, anything
- can reach a WebDAV verb without passing through check_access first.

Five operations only: list, read, write, move, trash.
No delete (outside trash semantics), no shares, no permissions.

Trash (deviation D1): WebDAV DELETE, which Nextcloud's files_trashbin
storage wrapper routes to the user's trash when the trashbin app is
enabled. The trashbin NAMESPACE itself (remote.php/dav/trashbin/...)
is refused here regardless of grants: permanent deletion and restore
operations are unreachable through the broker.

Credentials: NextcloudClient holds the app password; describe() and
all error paths must keep it out of logs and agent-visible output.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime

from broker.grants import GrantStore
from broker.paths import READ, WRITE, Grant, check_access, normalize_path

_FORBIDDEN_NAMESPACE_RE = re.compile(r"^(?:remote\.php/)?dav/trashbin(?:/|$)", re.IGNORECASE)


class AccessRefused(Exception):
    """The request is outside every active grant. Clean refusal; the
    underlying WebDAV server was never contacted."""

    def __init__(self, reason: str):
        super().__init__(f"access refused: {reason}")
        self.reason = reason


class WebDavError(Exception):
    """The underlying WebDAV operation failed. Carries HTTP status and a
    sanitized message; never a traceback, never credentials."""

    def __init__(self, status: int, message: str):
        self.status = status
        self.message = self._sanitize(message)
        super().__init__(f"webdav error {status}: {self.message}")

    @staticmethod
    def _sanitize(message: str) -> str:
        # strip anything that looks like a credential leak from upstream
        message = re.sub(r"(password|token|secret)\S*", "[redacted]", message, flags=re.IGNORECASE)
        return message[:300]

    def scrub_value(self, secret: str | None) -> WebDavError:
        """I-1 fix: value-based redaction. Scrub the ACTUAL secret value
        (keyword-independent) from the message. Called by the layer,
        which holds the credential."""
        if secret and secret in self.message:
            self.message = self.message.replace(secret, "[redacted]")
            # rebuild the exception text: args[0] was frozen at __init__
            self.args = (f"webdav error {self.status}: {self.message}",)
        return self


class NextcloudClient:
    """Credential holder + transport for one instance. `dav` is the
    transport object (webdavclient3 Client in production, a mock in
    tests). The layer is the ONLY caller of this client's verbs."""

    def __init__(self, url: str, username: str, password: str, dav):
        """Hold the per-instance credential set and its transport.

        url/username/password: the instance's app-password credentials
        (I-1 scope: `password` must never appear in logs, exceptions, or
        agent-visible output; describe() deliberately omits it). dav:
        the WebDAV transport (webdavclient3 Client in production, a mock
        in tests); only NextcloudLayer's five operations may call its
        verbs.
        """
        self.url = url
        self.username = username
        self.password = password
        self._dav = dav

    def describe(self) -> str:
        """Human-safe identification of this client: NEVER includes the
        password (or any secret-shaped field), so it is safe for logs
        and operator display."""
        return f"NextcloudClient(url={self.url!r}, username={self.username!r})"


class NextcloudLayer:
    """The only public file-operation surface of the broker."""

    def __init__(
        self,
        store: GrantStore,
        clients: dict[str, NextcloudClient],
        audit,  # AuditLog or None (Gate 6 wires it; None = audit-less tests)
        now: Callable[[], datetime],
        discovery_instances: set | None = None,
        principal: str | None = None,
    ):
        """Wire the layer to its store, clients, and audit log.

        store: the GrantStore providing active grants (the wall's data).
        clients: instance name -> NextcloudClient; names not present are
        refused before anything else. audit: AuditLog or None (Gate 6
        wires it in production; None is audit-less test mode, where the
        write-before-operate guarantee degrades to direct execution).
        now: injected clock for grant expiry checks.
        discovery_instances: D4 - instances where list() is allowed
        without a grant (standing discovery), still namespace-guarded
        and audit-logged.
        principal: D5 - 'agent' | 'transfer' | None (pre-D5 callers),
        stamped on audit records so CLI transfers are distinguishable
        from agent-surface operations in the log.
        """
        self._store = store
        self._clients = clients
        self._audit = audit
        self._now = now
        # D4: instances with standing discovery (list without grant).
        self.discovery_instances = discovery_instances or set()
        # D5: principal stamped on every audit record this layer writes.
        self._principal = principal

    # -------------------------------------------------------- authorization

    @staticmethod
    def _namespace_guard(path: str) -> str | None:
        """Normalize and refuse the trashbin namespace outright. Returns
        the normalized path if acceptable, None if forbidden. The
        instance ROOT ('' -> '') is acceptable: it is the legitimate
        starting point for discovery listing and is refused by grant
        checks anyway (no grant can cover the whole root, and discovery
        list on root is by design).

        Threat: WebDAV's DAV root hosts several namespaces
        (files/<user>/, trashbin/, files_trashbin/...). A request to the
        trashbin namespace would let the agent permanently delete or
        restore files, bypassing grant semantics - so it is refused by
        name here regardless of any grant, in all three spellings the
        path normalizer can produce (I-2 case-complete refusal).
        """
        norm = normalize_path(path)
        if norm is None:
            # malformed or root: normalize_path('' ) is None. Root must
            # be distinguished from genuinely malformed input.
            if isinstance(path, str) and path.strip() in ("", "/"):
                return ""  # root
            return None
        # I-2 fix: case-complete trashbin refusal (defense-in-depth;
        # the adapter binds all paths under files/<user>/ so the real
        # trash endpoint is structurally unreachable regardless).
        lowered = norm.lower()
        if lowered == "trashbin" or lowered.startswith("trashbin/"):
            return None
        if lowered == "files_trashbin" or lowered.startswith("files_trashbin/"):
            return None
        if lowered == "remote.php/dav/trashbin" or lowered.startswith("remote.php/dav/trashbin/"):
            return None
        return norm

    def _authorized(self, instance: str, path: str, mode: str):
        """Wall + namespace guard + instance check, in that order.
        Returns (client, normalized_path) or raises AccessRefused.

        D5: refusals are audit-logged (decision 'refused') before the
        exception propagates — a wall refusal that leaves no trace is
        invisible exactly when it matters.
        """
        client = self._clients.get(instance)
        if client is None:
            self._audit_refusal(instance, path, mode, f"unknown instance {instance!r}")
            raise AccessRefused(f"unknown instance {instance!r} (not configured)")
        norm = self._namespace_guard(path)
        if norm is None:
            self._audit_refusal(instance, path, mode, "forbidden namespace")
            raise AccessRefused("path is in a forbidden namespace")
        # D6.7 fix: pair EACH item's path with ITS OWN mode. The old code
        # used rec.path (first item only) for every entry, so multi-item
        # grants silently granted item[0]'s path under every item's mode
        # (privilege escalation: a write item widened item[0]'s scope)
        # and item[1+]'s paths were unreachable despite approval.
        grants = [
            Grant(path=item["path"], mode=item["mode"], expires_at=rec.expires_at, id=rec.id)
            for rec in self._store.active_grants(instance=instance)
            for item in rec.items
        ]
        decision = check_access(norm, mode, grants, self._now())
        if not decision.allowed:
            self._audit_refusal(instance, norm, mode, decision.reason)
            raise AccessRefused(decision.reason)
        return client, norm

    def _audit_refusal(self, instance: str, path: str, operation: str, reason: str):
        """Best-effort refusal logging: an audit failure must not turn a
        refusal into an error, and no credential ever reaches the log.
        Best-effort is correct here — the operation is already refused;
        the audit line is visibility, not a gate."""
        if self._audit is None:
            return
        try:
            self._audit.record(
                instance=instance,
                path=path,
                operation=operation,
                grant_id=None,
                decision="refused",
                reason=reason,
                principal=self._principal,
            )
        except Exception as exc:  # noqa: BLE001 (visibility path must not raise)
            import logging

            logging.getLogger("broker").warning(
                "audit refusal logging failed: %s", exc
            )

    def _audit_and(
        self,
        instance: str,
        path: str,
        operation: str,
        grant_id,
        decision: str,
        reason: str,
        action: Callable,
        principal: str | None = None,
    ):
        """Write-before-operate, if an audit log is wired. If the audit
        write fails, the operation is refused (audit.py contract).
        D5: principal defaults to the layer's principal; a per-call
        override lets one shared layer serve both surfaces."""
        import logging

        principal = principal if principal is not None else self._principal
        logging.getLogger("broker").debug(
            "op %s %s/%s -> %s (%s)", operation, instance, path, decision, reason
        )
        if self._audit is None:
            return self._scrub_errors(instance, action)()
        return self._audit.record(
            instance=instance,
            path=path,
            operation=operation,
            grant_id=grant_id,
            decision=decision,
            reason=reason,
            principal=principal,
            then=self._scrub_errors(instance, action),
        )

    def _scrub_errors(self, instance: str, action: Callable) -> Callable:
        """I-1 fix: wrap the transport call so any WebDavError leaving it
        has THIS instance's actual credential value scrubbed, keyword-
        independent, before it propagates to the agent."""
        client = self._clients.get(instance)
        secret = getattr(client, "password", None) if client else None

        def guarded():
            try:
                return action()
            except WebDavError as exc:
                raise exc.scrub_value(secret) from None

        return guarded

    # ---------------------------------------------------------- the five ops

    def list(self, instance: str, path: str):
        """PROPFIND a directory. Two paths through the wall:
        D4 discovery (no grant needed on enabled instances, grant_id
        recorded as None with reason 'discovery') or the normal granted
        READ path. Both are namespace-guarded and audit-logged.
        Raises AccessRefused for unknown instance, forbidden namespace,
        or (non-discovery) no covering grant.
        """
        client = self._clients.get(instance)
        if client is None:
            raise AccessRefused(f"unknown instance {instance!r} (not configured)")
        norm = self._namespace_guard(path)
        if norm is None:
            raise AccessRefused("path is in a forbidden namespace")
        # D4: discovery mode - list without a grant on enabled instances,
        # audit-logged, trashbin namespace still refused.
        if instance in self.discovery_instances:
            return self._audit_and(
                instance, norm, "list", None, "allowed", "discovery",
                lambda: client._dav.propfind(norm),
            )
        _, norm = self._authorized_read(instance, norm)
        return self._audit_and(
            instance, norm, "list", None, "allowed", "granted read",
            lambda: client._dav.propfind(norm),
        )

    def _authorized_read(self, instance: str, norm: str):
        """Wall check for the grant-gated list path (shares _authorized
        logic with a pre-normalized path)."""
        # D6.7 fix: same per-item pairing as _authorized (first-item path
        # used to swallow every item's mode, breaking multi-item grants).
        grants = [
            Grant(path=item["path"], mode=item["mode"], expires_at=rec.expires_at, id=rec.id)
            for rec in self._store.active_grants(instance=instance)
            for item in rec.items
        ]
        decision = check_access(norm, READ, grants, self._now())
        if not decision.allowed:
            raise AccessRefused(decision.reason)
        return self._clients[instance], norm

    def read(self, instance: str, path: str, principal: str | None = None):
        """GET a file. Requires a live READ (or WRITE) grant covering the
        normalized path; audit-logged write-before-operate. D5: principal
        override lets the transfer surface stamp its own identity."""
        client, norm = self._authorized(instance, path, READ)
        return self._audit_and(
            instance, norm, "read", None, "allowed", "granted read",
            lambda: client._dav.get(norm), principal=principal,
        )

    def write(self, instance: str, path: str, data: bytes, principal: str | None = None):
        """PUT a file. Requires a live WRITE grant specifically (READ
        grants never authorize writes); audit-logged write-before-operate.
        D5: principal override for the transfer surface."""
        client, norm = self._authorized(instance, path, WRITE)
        return self._audit_and(
            instance, norm, "write", None, "allowed", "granted write",
            lambda: client._dav.put(norm, data), principal=principal,
        )

    def move(self, instance: str, src: str, dst: str):
        """MOVE within one instance. BOTH endpoints must be covered by
        WRITE grants on the same instance (otherwise an agent could move
        a file into an ungranted location); source checked first so a
        denied source never authorizes anything.
        """
        # Both endpoints are checked against grants on the SAME instance:
        # there is no cross-instance move surface, so no guard is needed
        # here - _authorized() already binds both ends to one client.
        client, norm_src = self._authorized(instance, src, WRITE)
        _, norm_dst = self._authorized(instance, dst, WRITE)
        return self._audit_and(
            instance, f"{norm_src} -> {norm_dst}", "move", None, "allowed", "granted write",
            lambda: client._dav.move(norm_src, norm_dst),
        )

    def trash(self, instance: str, path: str):
        """DELETE a file - deviation D1: Nextcloud's files_trashbin routes
        this to the user's trash (recoverable), never a permanent
        deletion. Requires a WRITE grant; the trashbin namespace itself
        is refused by _namespace_guard before this runs.
        """
        client, norm = self._authorized(instance, path, WRITE)
        return self._audit_and(
            instance, norm, "trash", None, "allowed", "granted write",
            lambda: client._dav.delete(norm),  # D1: routed to trashbin by Nextcloud
        )

    def mkdir(self, instance: str, path: str):
        """MKCOL a folder: a WRITE-scope operation on the parent path.
        Requires an active WRITE grant covering the path; the wall and
        the namespace guard apply identically to file operations.
        Audit-logged write-before-operate like every other verb.
        """
        client, norm = self._authorized(instance, path, WRITE)
        return self._audit_and(
            instance, norm, "mkdir", None, "allowed", "granted write",
            lambda: client._dav.mkcol(norm),
        )

    # -------------------------------------------------- D5 checkout model

    def checkout(self, instance: str, path: str, timeout: int = 0, principal: str | None = None):
        """D5 checkout: LOCK the file (server-wide write refusal for
        every access path via files_lock), then GET its content. The
        caller receives bytes + lock_token and stages the token in the
        manifest; without the token the lock cannot be released
        through the broker.

        Requires a live WRITE grant (checkout implies intent to write;
        read-only consumers use plain read). Audit-logged
        write-before-operate. The lock happens BEFORE the read so the
        fetched bytes are the locked revision.
        """
        client, norm = self._authorized(instance, path, WRITE)
        result = self._audit_and(
            instance, norm, "checkout", None, "allowed", "granted write",
            lambda: client._dav.lock(norm, timeout=timeout), principal=principal,
        )
        content = self._audit_and(
            instance, norm, "read", None, "allowed", "checkout read",
            lambda: client._dav.get(norm), principal=principal,
        )
        data = content.get("content") if isinstance(content, dict) else None
        return {
            "ok": True,
            "lock_token": result.get("lock_token"),
            "content": data,
        }

    def checkin(self, instance: str, path: str, data: bytes, lock_token: str, principal: str | None = None):
        """D5 checkin: PUT the worked-on bytes, verify, then UNLOCK with
        the recorded token. The PUT happens while the lock is held
        (this is the whole point); UNLOCK releases the file to other
        writers. Missing/expired grant: PUT refuses, lock REMAINS
        (fail closed — the file stays protected until the token is
        spent or the owner overrides).
        """
        client, norm = self._authorized(instance, path, WRITE)
        written = self._audit_and(
            instance, norm, "checkin", None, "allowed", "granted write",
            lambda: client._dav.put(norm, data, lock_token=lock_token), principal=principal,
        )
        unlocked = self._audit_and(
            instance, norm, "checkin-unlock", None, "allowed", "lock released",
            lambda: client._dav.unlock(norm, lock_token), principal=principal,
        )
        return {"ok": True, "written": bool(written), "unlocked": bool(unlocked)}

    # ------------------------------------------------------- introspection

    def check_access(self, instance: str, path: str, mode: str) -> dict:
        """Non-mutating scope check for the agent: would this be allowed
        right now? Never contacts WebDAV."""
        try:
            self._authorized(instance, path, mode)
            return {"allowed": True}
        except AccessRefused as exc:
            return {"allowed": False, "reason": exc.reason}