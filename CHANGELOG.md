# Changelog

All notable changes to this project are documented here. The format
follows Keep a Changelog; versions follow semver.

## [0.1.0] — unreleased

First complete implementation: the human-gated access broker.

### Added
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

### Security
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