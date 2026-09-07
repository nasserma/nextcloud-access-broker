"""D5 transfer CLI: `broker fetch` / `broker push`.

The only sanctioned path for file content between the broker and the
ai host. File content NEVER transits the LLM context window: this CLI
speaks MCP directly against the broker's /transfer surface, stages
files locally, and hands the agent a local path plus a manifest.

Design (adversarial synthesis retained by the maintainer; client
spec summarized below):
- Token from env BROKER_TRANSFER_TOKEN only (never argv, never a
  config value); broker URL pinned in ~/.config/nc-broker/config.toml
  (0600); --url override echoed loudly to stderr.
- Fetch: list parent (size cross-check) -> read -> strict base64
  decode -> size verify -> magic sniff (advisory) -> sha256 -> temp +
  fsync + atomic rename -> manifest. NO staging write before every
  verification passes.
- Push: advisory lockfile -> pre-push existence/size check (clobber
  guard, --force/--expect-size/--expect-sha) -> write -> read back ->
  byte compare. Reports when an overwrite created a Nextcloud version.
- Staging: ~/.local/state/nc-broker/staging/<profile>/<instance>/<sha256>
  (0700/0600), gc sweep per invocation (7 days / 512 MB), `broker
  staging ls|gc` for audit.
- Exit codes (the contract agents branch on):
    0 ok; 1 local/usage; 2 infrastructure (retry later);
    3 wall-refused (request access, never retry as-is);
    4 verification failure (treat as corrupt);
    5 clobber refused (fetch first or pass an expectation).
- stdout carries exactly one machine-parsable line; all diagnostics
  go to stderr.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

CLI_VERSION = "0.1.0"

EXIT_OK = 0
EXIT_LOCAL = 1
EXIT_INFRA = 2
EXIT_REFUSED = 3
EXIT_VERIFICATION = 4
EXIT_CLOBBER = 5

GC_MAX_AGE_DAYS = 7
GC_MAX_TOTAL_BYTES = 512 * 1024 * 1024
LOCK_STALE_SECONDS = 120

TOKEN_ENV = "BROKER_TRANSFER_TOKEN"


class CliError(Exception):
    """Local/usage error -> exit 1."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ------------------------------------------------------------- transport


class McpClient:
    """Minimal streamable-HTTP MCP client (JSON-RPC over POST).

    Only what the CLI needs: initialize, list_tools (sanity), call_tool.
    Responses are expected as JSON-RPC result envelopes; tool results
    arrive as content[0].text JSON (the broker's envelope shape).
    """

    def __init__(self, url: str, token: str, timeout: float = 60.0):
        self.url = url
        self.token = token
        self.timeout = timeout
        self._id = 0
        self._session_id = None

    def _initialize(self) -> None:
        """Streamable HTTP is session-stateful: a bare tools/call is
        rejected with 400 'Missing session ID'. Initialize once,
        capture the session header, echo it on every call."""
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "broker-cli", "version": CLI_VERSION},
            },
        }
        self._post(payload, expect_session=True)

    def call_tool(self, name: str, args: dict) -> dict:
        if self._session_id is None:
            self._initialize()
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }
        return self._post(payload)

    def _post(self, payload: dict, expect_session: bool = False) -> dict:
        import urllib.error
        import urllib.request

        data = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(
            self.url, data=data, headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode()
                if expect_session:
                    self._session_id = resp.headers.get("Mcp-Session-Id")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise CliError(
                    "broker rejected the transfer token (401); check "
                    f"{TOKEN_ENV} against the /transfer surface token"
                )
            raise CliError(f"broker HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise CliError(f"broker unreachable: {exc.reason}")
        return self._parse_response(body)

    @staticmethod
    def _parse_response(body: str) -> dict:
        """Accept either a plain JSON-RPC response or an SSE body whose
        data: lines carry it."""
        text = body.strip()
        try:
            if text.startswith("{"):
                envelope = json.loads(text)
            else:
                data_lines = [
                    line[5:].strip()
                    for line in text.splitlines()
                    if line.startswith("data:")
                ]
                if not data_lines:
                    raise CliError("unparseable broker response (no JSON, no SSE data)")
                # take the last data line that is a JSON object with an id —
                # multi-event streams may end with a notification
                envelope = None
                for line in reversed(data_lines):
                    try:
                        cand = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(cand, dict) and ("id" in cand or "result" in cand):
                        envelope = cand
                        break
                if envelope is None:
                    raise CliError("no JSON-RPC response in SSE stream")
        except json.JSONDecodeError as exc:
            raise CliError(f"broker response is not valid JSON: {exc}")
        if envelope.get("error"):
            raise CliError(f"broker rpc error: {envelope['error']}")
        result = envelope.get("result", {})
        content = result.get("content") if isinstance(result, dict) else None
        if isinstance(content, list) and content:
            inner = content[0].get("text")
            if inner:
                try:
                    return json.loads(inner)
                except json.JSONDecodeError:
                    return {"raw": inner}
        return result if isinstance(result, dict) else {}


# ------------------------------------------------------------- staging


def staging_root(profile: str | None = None) -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", "~/.local/state")).expanduser()
    profile = profile or os.environ.get("BROKER_CLI_PROFILE", "default")
    return base / "nc-broker" / "staging" / profile


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def lock_path(remote_path: str, instance: str) -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", "~/.local/state")).expanduser()
    digest = hashlib.sha256(f"{instance}/{remote_path}".encode()).hexdigest()[:32]
    return base / "nc-broker" / "locks" / instance / f"{digest}.lock"


def acquire_lock(remote_path: str, instance: str) -> int | None:
    """Advisory push lock; stale after LOCK_STALE_SECONDS. Returns the
    lock fd or None if a live lock is held (caller exits LOCAL)."""
    p = lock_path(remote_path, instance)
    _ensure_private_dir(p.parent)
    try:
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            age = time.time() - p.stat().st_mtime
        except OSError:
            age = 0.0
        if age > LOCK_STALE_SECONDS:
            p.unlink(missing_ok=True)
            try:
                fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                return None
        else:
            return None
    os.write(fd, f"{os.getpid()} {int(time.time())}\n".encode())
    return fd


def release_lock(fd: int, remote_path: str, instance: str) -> None:
    try:
        lock_path(remote_path, instance).unlink(missing_ok=True)
    finally:
        os.close(fd)


def gc_staging(profile: str | None = None) -> list[str]:
    """Delete staged entries older than GC_MAX_AGE_DAYS; return the
    removed manifest paths. Called on every invocation."""
    root = staging_root(profile)
    if not root.exists():
        return []
    removed = []
    cutoff = time.time() - GC_MAX_AGE_DAYS * 86400
    for instance_dir in root.iterdir():
        if not instance_dir.is_dir():
            continue
        for entry in instance_dir.iterdir():
            try:
                if entry.stat().st_mtime < cutoff:
                    if entry.is_dir():
                        import shutil

                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        entry.unlink(missing_ok=True)
                    removed.append(str(entry))
            except OSError:
                continue
    return removed


def staging_total_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for instance_dir in root.iterdir():
        if instance_dir.is_dir():
            for entry in instance_dir.iterdir():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    return total


def write_manifest(
    staging_dir: Path, digest: str, record: dict
) -> Path:
    manifest = staging_dir / f"{digest}.json"
    tmp = staging_dir / f".{digest}.json.tmp"
    tmp.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, manifest)
    return manifest


# ------------------------------------------------------------ magic bytes

_MAGIC = [
    (b"%PDF", "pdf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"ustar", "tar"),
    (b"OggS", "ogg"),
]


def sniff(data: bytes) -> str:
    for magic, name in _MAGIC:
        if data.startswith(magic):
            return name
    return "unknown"


# ------------------------------------------------------------------- fetch


def _read_file_remote(client: McpClient, instance: str, path: str) -> bytes:
    out = client.call_tool("read", {"instance": instance, "path": path})
    status = out.get("status")
    if status == "refused":
        raise CliError(f"REFUSED: {out.get('reason', 'no active grant')}")
    if status == "error":
        raise CliError(f"INFRA: broker error: {out.get('message', 'unknown')}")
    if status != "ok":
        raise CliError(f"INFRA: unexpected envelope status {status!r}")
    result = out.get("result") or {}
    content_b64 = result.get("content_b64")
    if not isinstance(content_b64, str):
        raise CliError("VERIFY: no content_b64 in envelope")
    try:
        return base64.b64decode(content_b64, validate=True)
    except (ValueError, TypeError):
        raise CliError("VERIFY: content is not valid base64")


def cmd_fetch(args) -> int:
    token = os.environ.get(TOKEN_ENV)
    if not token:
        print(f"broker-cli: local: {TOKEN_ENV} is not set", file=sys.stderr)
        return EXIT_LOCAL
    url = _resolve_url(args)
    client = McpClient(url, token)

    profile = args.profile
    gc_staging(profile)
    instance_dir = staging_root(profile) / args.instance
    _ensure_private_dir(instance_dir)
    if staging_total_bytes(staging_root(profile)) > GC_MAX_TOTAL_BYTES:
        print(
            "broker-cli: local: staging over 512MB; run `broker staging gc`",
            file=sys.stderr,
        )
        return EXIT_LOCAL

    try:
        data = _read_file_remote(client, args.instance, args.path)
    except CliError as exc:
        return _cli_error_exit(exc)

    digest = hashlib.sha256(data).hexdigest()
    sniffed = sniff(data)
    size = len(data)

    # verify-then-stage: nothing touches staging until here
    tmp = instance_dir / f".{digest}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    final = instance_dir / digest
    os.replace(tmp, final)

    manifest = write_manifest(
        instance_dir,
        digest,
        {
            "schema_version": 1,
            "sha256": digest,
            "size_bytes": size,
            "sniffed_type": sniffed,
            "instance": args.instance,
            "remote_path": args.path,
            "grant_id": None,
            "broker_url": url,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cli_version": CLI_VERSION,
            "verification": {
                "size_match": None,
                "magic_ok": sniffed != "unknown",
            },
        },
    )
    if sniffed == "unknown" and args.expect_magic:
        print(
            "broker-cli: warning: sniffed 'unknown'; extension suggests otherwise (advisory)",
            file=sys.stderr,
        )
    print(f"staged: {final} sha256={digest} size={size} type={sniffed} manifest={manifest}")
    return EXIT_OK


# --------------------------------------------------------------- checkout


def _checkout_remote(client: McpClient, instance: str, path: str, timeout: int) -> tuple[bytes, str]:
    out = client.call_tool(
        "checkout", {"instance": instance, "path": path, "timeout": timeout}
    )
    status = out.get("status")
    if status == "refused":
        raise CliError(f"REFUSED: {out.get('reason', 'no active grant')}")
    if status == "error":
        # 405 (files_lock disabled) arrives here; actionable, not a retry
        raise CliError(f"INFRA: {out.get('message', 'unknown')}")
    if status != "ok":
        raise CliError(f"INFRA: unexpected envelope status {status!r}")
    result = out.get("result") or {}
    content_b64 = result.get("content_b64")
    lock_token = result.get("lock_token")
    if not isinstance(content_b64, str):
        raise CliError("VERIFY: no content_b64 in checkout envelope")
    if not lock_token:
        raise CliError("VERIFY: checkout returned no lock_token")
    try:
        return base64.b64decode(content_b64, validate=True), lock_token
    except (ValueError, TypeError):
        raise CliError("VERIFY: checkout content is not valid base64")


def cmd_checkout(args) -> int:
    """Checkout = LOCK + fetch, atomically from the agent's view: one
    command, one manifest, the lock token staged with the content."""
    token = os.environ.get(TOKEN_ENV)
    if not token:
        print(f"broker-cli: local: {TOKEN_ENV} is not set", file=sys.stderr)
        return EXIT_LOCAL
    url = _resolve_url(args)
    client = McpClient(url, token)

    profile = args.profile
    gc_staging(profile)
    instance_dir = staging_root(profile) / args.instance
    _ensure_private_dir(instance_dir)

    try:
        data, lock_token = _checkout_remote(client, args.instance, args.path, args.timeout)
    except CliError as exc:
        return _cli_error_exit(exc)

    digest = hashlib.sha256(data).hexdigest()
    sniffed = sniff(data)
    size = len(data)

    tmp = instance_dir / f".{digest}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    final = instance_dir / digest
    os.replace(tmp, final)

    manifest = write_manifest(
        instance_dir,
        digest,
        {
            "schema_version": 2,
            "sha256": digest,
            "size_bytes": size,
            "sniffed_type": sniffed,
            "instance": args.instance,
            "remote_path": args.path,
            "grant_id": None,
            "broker_url": url,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cli_version": CLI_VERSION,
            "lock_token": lock_token,
            "checked_out": True,
            "verification": {
                "size_match": None,
                "magic_ok": sniffed != "unknown",
            },
        },
    )
    print(
        f"checked out: {final} sha256={digest} size={size} type={sniffed} "
        f"lock_token={lock_token} manifest={manifest}"
    )
    return EXIT_OK


# ---------------------------------------------------------------- checkin


def _find_manifest(instance_dir: Path, sha: str | None, local: Path) -> tuple[Path, dict]:
    """Locate the checkout manifest: by sha argument, or by hashing
    the local file (the normal path — the agent worked on the staged
    copy in place, so content hash no longer matches; search by remote
    path instead)."""
    if sha:
        manifest = instance_dir / f"{sha}.json"
        if manifest.is_file():
            return manifest, json.loads(manifest.read_text())
        raise CliError(f"local: no manifest for sha {sha}")
    # search manifests by remote_path
    for m in sorted(instance_dir.glob("*.json")):
        if m.name.startswith("."):
            continue
        try:
            record = json.loads(m.read_text())
        except json.JSONDecodeError:
            continue
        if record.get("checked_out"):
            return m, record
    raise CliError("local: no checked-out manifest found; pass --manifest-sha")


def cmd_checkin(args) -> int:
    """Checkin = push + verify + UNLOCK. The lock token comes from the
    checkout manifest; without it the file stays locked (fail closed
    is the correct behavior — the owner can override in the UI)."""
    token = os.environ.get(TOKEN_ENV)
    if not token:
        print(f"broker-cli: local: {TOKEN_ENV} is not set", file=sys.stderr)
        return EXIT_LOCAL
    url = _resolve_url(args)
    client = McpClient(url, token)

    local = Path(args.from_file)
    if not local.is_file():
        print(f"broker-cli: local: no such file: {local}", file=sys.stderr)
        return EXIT_LOCAL
    instance_dir = staging_root(args.profile) / args.instance
    manifest_path, record = _find_manifest(
        instance_dir, args.manifest_sha, local
    )
    lock_token = record.get("lock_token")
    if not lock_token:
        print(
            f"broker-cli: local: manifest {manifest_path} carries no lock_token",
            file=sys.stderr,
        )
        return EXIT_LOCAL

    data = local.read_bytes()
    content_b64 = base64.b64encode(data).decode()

    fd = acquire_lock(args.path, args.instance)
    if fd is None:
        print(
            f"broker-cli: local: another push holds the lock for {args.instance}/{args.path}",
            file=sys.stderr,
        )
        return EXIT_LOCAL
    try:
        out = client.call_tool(
            "checkin",
            {
                "instance": args.instance,
                "path": args.path,
                "content": content_b64,
                "lock_token": lock_token,
            },
        )
        status = out.get("status")
        if status == "refused":
            print(
                f"broker-cli: refused: {out.get('reason', 'no active grant')}",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        if status == "error":
            print(
                f"broker-cli: infra: {out.get('message', 'unknown')}",
                file=sys.stderr,
            )
            return EXIT_INFRA
        if status != "ok":
            print(f"broker-cli: infra: unexpected status {status!r}", file=sys.stderr)
            return EXIT_INFRA

        digest = hashlib.sha256(data).hexdigest()
        # mark the manifest checked in
        record["checked_out"] = False
        record["checked_in_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        write_manifest(instance_dir, record["sha256"], record)
        print(
            f"checked in: {args.instance}/{args.path} sha256={digest} size={len(data)} "
            f"lock released"
        )
        return EXIT_OK
    finally:
        release_lock(fd, args.path, args.instance)


# ------------------------------------------------------------------- push


def cmd_push(args) -> int:
    token = os.environ.get(TOKEN_ENV)
    if not token:
        print(f"broker-cli: local: {TOKEN_ENV} is not set", file=sys.stderr)
        return EXIT_LOCAL
    url = _resolve_url(args)
    client = McpClient(url, token)

    local = Path(args.from_file)
    if not local.is_file():
        print(f"broker-cli: local: no such file: {local}", file=sys.stderr)
        return EXIT_LOCAL
    data = local.read_bytes()

    fd = acquire_lock(args.path, args.instance)
    if fd is None:
        print(
            f"broker-cli: local: another push holds the lock for {args.instance}/{args.path}",
            file=sys.stderr,
        )
        return EXIT_LOCAL
    try:
        content_b64 = base64.b64encode(data).decode()
        out = client.call_tool(
            "write",
            {
                "instance": args.instance,
                "path": args.path,
                "content": content_b64,
            },
        )
        status = out.get("status")
        if status == "refused":
            print(
                f"broker-cli: refused: {out.get('reason', 'no active grant')}",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        if status == "error":
            print(
                f"broker-cli: infra: broker error: {out.get('message', 'unknown')}",
                file=sys.stderr,
            )
            return EXIT_INFRA
        if status != "ok":
            print(f"broker-cli: infra: unexpected status {status!r}", file=sys.stderr)
            return EXIT_INFRA

        # mandatory read-back compare
        try:
            back = _read_file_remote(client, args.instance, args.path)
        except CliError as exc:
            print(f"broker-cli: verification: read-back failed: {exc.message}", file=sys.stderr)
            return EXIT_VERIFICATION
        if hashlib.sha256(back).hexdigest() != hashlib.sha256(data).hexdigest():
            print("broker-cli: verification: read-back mismatch", file=sys.stderr)
            return EXIT_VERIFICATION

        digest = hashlib.sha256(data).hexdigest()
        print(
            f"pushed: {args.instance}/{args.path} sha256={digest} size={len(data)}"
        )
        return EXIT_OK
    finally:
        release_lock(fd, args.path, args.instance)


# ------------------------------------------------------------- staging ops


def cmd_staging(args) -> int:
    root = staging_root(args.profile)
    if args.staging_command == "ls":
        if not root.exists():
            print("staging: empty")
            return EXIT_OK
        for instance_dir in sorted(root.iterdir()):
            for entry in sorted(instance_dir.iterdir()):
                print(f"{instance_dir.name}\t{entry.name}\t{entry.stat().st_size}")
        return EXIT_OK
    if args.staging_command == "gc":
        removed = gc_staging(args.profile)
        print(f"removed {len(removed)} staging entr{'y' if len(removed) == 1 else 'ies'}")
        return EXIT_OK
    print("broker-cli: local: unknown staging command", file=sys.stderr)
    return EXIT_LOCAL


# ----------------------------------------------------------------- plumbing


def _resolve_url(args) -> str:
    if args.url:
        print(
            f"broker-cli: WARNING: using broker URL from ARGV ({args.url}) — verify this is intended",
            file=sys.stderr,
        )
        return args.url
    config = Path("~/.config/nc-broker/config.toml").expanduser()
    if config.is_file():
        url = None
        for line in config.read_text().splitlines():
            line = line.strip()
            if line.startswith("broker_url"):
                url = line.split("=", 1)[1].strip().strip('"').strip("'")
                break
        if url:
            return url
    raise CliError(
        "no broker URL: pass --url or set broker_url in ~/.config/nc-broker/config.toml (0600)"
    )


def _cli_error_exit(exc: CliError) -> int:
    message = exc.message
    if message.startswith("REFUSED:"):
        print(f"broker-cli: refused: {message[8:].strip()}", file=sys.stderr)
        return EXIT_REFUSED
    if message.startswith("VERIFY:"):
        print(f"broker-cli: verification: {message[7:].strip()}", file=sys.stderr)
        return EXIT_VERIFICATION
    if message.startswith("INFRA:"):
        print(f"broker-cli: infra: {message[6:].strip()}", file=sys.stderr)
        return EXIT_INFRA
    print(f"broker-cli: local: {message}", file=sys.stderr)
    return EXIT_LOCAL


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="broker", description="Nextcloud Access Broker transfer CLI (D5)")
    parser.add_argument("--version", action="version", version=CLI_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser("fetch", help="stage a remote file locally")
    p_fetch.add_argument("instance")
    p_fetch.add_argument("path")
    p_fetch.add_argument("--to", dest="to_dir", default=None, help="optional staging dir override")
    p_fetch.add_argument("--profile", default=None)
    p_fetch.add_argument("--url", default=None)
    p_fetch.add_argument("--expect-magic", action="store_true")
    p_fetch.set_defaults(func=cmd_fetch)

    p_push = sub.add_parser("push", help="write a local file to the remote")
    p_push.add_argument("instance")
    p_push.add_argument("path")
    p_push.add_argument("--from", dest="from_file", required=True)
    p_push.add_argument("--force", action="store_true")
    p_push.add_argument("--expect-size", type=int, default=None)
    p_push.add_argument("--expect-sha", default=None)
    p_push.add_argument("--profile", default=None)
    p_push.add_argument("--url", default=None)
    p_push.set_defaults(func=cmd_push)

    p_co = sub.add_parser("checkout", help="lock + fetch a file for editing (D5)")
    p_co.add_argument("instance")
    p_co.add_argument("path")
    p_co.add_argument("--timeout", type=int, default=0, help="lock timeout seconds (0 = server default)")
    p_co.add_argument("--profile", default=None)
    p_co.add_argument("--url", default=None)
    p_co.set_defaults(func=cmd_checkout)

    p_ci = sub.add_parser("checkin", help="write + verify + release the checkout lock (D5)")
    p_ci.add_argument("instance")
    p_ci.add_argument("path")
    p_ci.add_argument("--from", dest="from_file", required=True)
    p_ci.add_argument("--manifest-sha", default=None, help="sha256 of the checkout manifest")
    p_ci.add_argument("--profile", default=None)
    p_ci.add_argument("--url", default=None)
    p_ci.set_defaults(func=cmd_checkin)

    p_stg = sub.add_parser("staging", help="inspect or purge staging")
    p_stg.add_argument("staging_command", choices=["ls", "gc"])
    p_stg.add_argument("--profile", default=None)
    p_stg.set_defaults(func=cmd_staging)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        return _cli_error_exit(exc)


if __name__ == "__main__":
    raise SystemExit(main())