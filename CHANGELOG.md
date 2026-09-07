# Changelog

All notable changes to this project are documented here. The format
follows Keep a Changelog; versions follow semver.

## [0.1.0] — unreleased

First complete implementation: the human-gated access broker.

### Added
- `list_instances` tool (D6.5): configured instance names + discovery
  flags on the agent surface. Instance names were previously
  undiscoverable by agents (probes of unconfigured names are refused,
  so a misspelled name dead-ended with no way forward). Reveals
  names and discovery flags only — never URLs, usernames, or
  credentials.
- Path checker (the wall): normalization + exact component-prefix
  matching; traversal, nested-encoding, and confusable attacks fail
  closed; hypothesis-fuzzed.
- Grant store: pending → active → expired/revoked/rejected state
  machine; one-time request numbers; 24h default grants; restart
  persistence (pending requests are discarded, never widened);
  persisted Matrix event → request mapping.
- Audit log: append-only, hash-chained, checkpointed; write-before-
  operate; a failed log write refuses the operation.
- WebDAV layer: five operations (list, read, write, move, trash) with
  the wall inside the layer; trashbin namespace unreachable; no
  permanent delete.
- Discovery mode (opt-in per instance): standing read-only directory
  listing without a grant, audit-logged. File names visible,
  contents never.
- Matrix approval bot: reactions pre-placed on request messages;
  single-approver allowlist; partial approval and custom expiry via
  typed replies; status summaries; instant revocation.
- MCP server surface (MCP SDK 2.x, streamable HTTP): seven tools,
  bearer-token auth (constant-time), uniform result envelopes.
- Docker deployment: non-root container, healthcheck; exposure is the
  host's decision (compose publishes on the tunnel interface only).
- Adversarial review: attack battery + state-machine probes
  (`review/`); all findings fixed test-first.

### Fixed
- Non-root directory listings no longer include the listed folder
  itself as an entry (D6b). The old name-based filter caught only the
  root self-reference; every non-root listing showed the folder itself
  (live evidence Sep 7: listing 'Projects' began with 'dir Projects').
  The self entry is now filtered by full DAV path equality, which also
  keeps a child that legitimately shares the folder's name.
- Reaction replay after restart (D6g): the first sync no longer
  requests full state, so historical reactions are not re-delivered
  and re-processed after a container restart (live: 7 'already
  decided' errors after the Sep 7 rebuild).

### Security
- Multi-item grants pair each item's path with its own mode at the
  wall (`broker/nextcloud.py`). Earlier builds paired every item's
  mode with the first item's path: items beyond the first were
  unreachable despite human approval, and a write item widened the
  first item's path scope (a write grant on one file silently
  authorized writes anywhere under another item's path). Found during
  the first live multi-instance test (2026-09-07); regression battery
  in `tests/test_d67_multitem_grants.py`, both wall sites covered.
- Credential values (not just keywords) are scrubbed from all error
  paths.
- Instance allowlist enforced before storage or posting: requests for
  unconfigured instances are refused outright.
- Audit chain detects truncation, reordering, edits, and checkpoint
  tampering.

### Known limitations
- Single approver (no quorum).
- File names are visible on discovery-enabled instances.
- A compromised broker host has account-wide access to configured
  instances (see SECURITY.md threat model).