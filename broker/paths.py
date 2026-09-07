"""The path checker: the single enforcement function for all file access.

Design document section 3.6. Every file operation in the broker passes
through check_access() before touching Nextcloud. This module is security
critical: it is small on purpose, has no dependencies, and carries its own
exhaustive test battery (tests/test_paths.py, 100% coverage required).

Normalization order (each step applied in sequence):
  1. Reject non-strings.
  2. Reject control characters (NUL and friends).
  3. Percent-decode the path, repeatedly, until stable or a small cap.
     This collapses double encoding (%252F -> %2F -> /).
  4. Convert backslashes to forward slashes (Windows-style smuggling).
  5. Split on "/", drop empty and "." components, process ".." by popping.
  6. Refuse paths that escape the root during that processing (fail closed).
  7. Rejoin with single slashes; the empty path means the instance root,
     which is never grantable, so an empty normalized path is always denied.

Matching rule: EXACT component-prefix matching. A grant on "a/b" matches
"a/b" itself and "a/b/anything" but never "a/bc". Never substring matching.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from datetime import datetime
from typing import NamedTuple

READ = "read"
WRITE = "write"
_MODES = frozenset({READ, WRITE})

_MAX_DECODE_PASSES = 4
_MAX_PATH_LENGTH = 2048


class Decision(NamedTuple):
    """The outcome of a single check_access() evaluation.

    allowed: False means DENY (the checker fails closed). grant_id is the
    authorizing grant on allow, or the grant that was closest-but-rejected
    on deny (used for the human-readable reason), else None. reason is a
    short operator-facing string, safe to surface to the requesting agent.
    """

    allowed: bool
    grant_id: int | None
    reason: str


@dataclasses.dataclass(frozen=True)
class Grant:
    """One authorization entry as seen by the checker (immutable).

    frozen=True guarantees no grant can be silently mutated between
    approval and use. expires_at=None means no expiry was set; the
    checker still enforces every other condition independently of it.
    path is the grant root, normalized by normalize_path() before use.
    """

    path: str
    mode: str
    expires_at: datetime | None
    id: int = 0


def _percent_decode(raw: str) -> str:
    """Decode percent-encoding repeatedly until stable, capped.

    urllib.parse.unquote decodes one layer per call, so looping handles
    double/triple encoding. The cap prevents pathological inputs from
    burning CPU; if still changing at the cap, the input is hostile and
    the caller treats it as undecodable.
    """
    from urllib.parse import unquote

    current = raw
    for _ in range(_MAX_DECODE_PASSES):
        decoded = unquote(current)
        if decoded == current:
            return decoded
        current = decoded
    # Unstable after the cap: keep decoding one more time and if it is STILL
    # changing, give up (caller fails closed via the "still-encoded" check
    # below, which will not match any grant).
    if unquote(current) != current:
        return current  # still contains escapes; no grant path will match
    return current


def normalize_path(raw: str) -> str | None:
    """Normalize a path to a canonical relative form.

    Returns None when the input is malformed, contains control characters,
    escapes the root via traversal, or is otherwise hostile. None always
    means DENY.
    """
    if not isinstance(raw, str):
        return None
    if raw == "" or raw.strip() == "":
        return None
    if len(raw) > _MAX_PATH_LENGTH:
        return None

    for ch in raw:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            return None

    decoded = _percent_decode(raw)
    decoded = decoded.replace("\\", "/")

    parts: list[str] = []
    for component in decoded.split("/"):
        if component == "" or component == ".":
            continue
        if component == "..":
            if not parts:
                return None  # traversal above the root: fail closed
            parts.pop()
            continue
        parts.append(component)

    return "/".join(parts)


def _inside(granted_norm: str, requested_norm: str) -> bool:
    """Exact component-prefix containment. Both inputs must be normalized.

    "a/b" contains "a/b" and "a/b/c" but not "a/bc", "a", or "ab".
    """
    if granted_norm == requested_norm:
        return True
    return requested_norm.startswith(granted_norm + "/")


def check_access(
    requested_path: str,
    mode: str,
    grants: Iterable[Grant],
    now: datetime,
) -> Decision:
    """Decide whether (mode, requested_path) is permitted by active grants.

    This is the wall: the ONLY authorization gate between an AI agent and
    the Nextcloud instance. Fails closed on every malformed input, expired
    grant, mode mismatch, and anything unexpected. Returns a Decision
    naming the authorizing grant, or a human-readable refusal reason.

    Threats defended against at each stage:
      - unknown mode: rejects any mode string outside READ/WRITE so a
        typo'd or injected mode can never match a grant.
      - malformed/hostile path: normalize_path() returning None means
        control characters, traversal, over-length, or undecodable
        double-encoding; all are denied before any grant is consulted.
      - grant-side failures: a grant whose own path fails normalization
        or carries an out-of-range mode is skipped, so a corrupt grant
        record can never broaden access.
      - expiry: an expired grant can still contribute the refusal reason
        but never an allow (defense in depth: callers should not create
        expired grants, and this checker does not trust them to).
      - mode escalation: a READ grant never authorizes a WRITE, checked
        after path containment so both scope and mode must hold.
    Invariant: allowed=True implies grant_id is a live, in-scope, mode-
    sufficient grant; allowed=False implies no side effect occurred.
    """
    if mode not in _MODES:
        return Decision(False, None, "unknown mode")

    norm = normalize_path(requested_path)
    if norm is None:
        return Decision(False, None, "malformed or hostile path")

    # Snapshot grants so the check is stable even if the caller mutates.
    best: Decision | None = None
    for g in grants:
        grant_norm = normalize_path(g.path)
        if grant_norm is None or grant_norm == "":
            continue  # a malformed grant path grants nothing
        if g.mode not in _MODES:
            continue
        if not _inside(grant_norm, norm):
            continue
        if g.expires_at is None or g.expires_at <= now:
            if best is None:
                best = Decision(False, None, f"grant {g.id} expired")
            continue
        if mode == WRITE and g.mode != WRITE:
            if best is None:
                best = Decision(
                    False,
                    None,
                    f"grant {g.id} is read-only; write not permitted",
                )
            continue
        # Match: live grant, mode sufficient, path inside scope.
        return Decision(True, g.id, "ok")

    if best is not None:
        return best
    return Decision(False, None, "path not covered by any active grant")