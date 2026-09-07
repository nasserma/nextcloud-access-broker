# Architecture

## Why this exists

Standard MCP file servers grant an agent standing, account-wide
access at install time. The broker's premise is that this is the wrong
default for file storage you care about: the agent should start from
zero capability, and every access should be an explicit, scoped,
expiring grant that a human approved. No off-the-shelf MCP server
does this, which is why the broker exists.

## Components

```
                    ┌────────────────────────────────────────┐
                    │              broker host               │
                    │                                        │
  AI agent ────────▶│ MCP server (streamable HTTP, bearer)   │
  (agent token)     │   ┌────────────────────────────────┐   │
                    │   │ NextcloudLayer                 │   │
                    │   │  list / read / write /        │   │
                    │   │  move / trash                 │   │
                    │   │      │ the wall (paths.py)   │   │
                    │   │      ▼                       │   │
                    │   │ GrantStore ──── AuditLog ◀────│   │
                    │   │ (SQLite/WAL)   (hash chain)   │   │
                    │   └──────────┬────────────────────┘   │
                    │              │ WebDAV                  │
                    │      ┌───────┴────────┐               │
                    │      ▼                ▼               │
                    │  Nextcloud(s)    Matrix bot ──────────┼──▶ approver
                    │  (app pw)        (sync loop)         │  (chat client)
                    └────────────────────────────────────────┘
```

The approval plane (Matrix today; one configurable gateway by
design) is deliberately severed from the execution plane (the MCP
server the agent talks to): the agent can request capability and
exercise granted capability, but the grant decision happens on
infrastructure the agent cannot reach.

## The wall

One function (`broker/paths.py: check_access`) decides every
operation: normalize (percent-decode to a cap, backslash-fold, resolve
dot segments, refuse root escapes), then exact component-prefix
match against active grants. `Documents/paper` matches itself and
its contents, never `Documents/papers`. WRITE implies READ within
scope. Every failure mode fails closed. This function has 100%
statement and branch coverage, a 500-case hypothesis fuzz, and an
independent attack battery (`review/attack_battery.py`).

The wall lives inside the WebDAV layer, not in the MCP tools: no
caller can reach a transport verb without passing through it, and no
test may mock it.

The layer flattens each grant record into per-item `Grant` entries
before calling `check_access`: every item's PATH pairs with that
item's OWN mode. A multi-item grant therefore grants exactly the
union of its approved (path, mode) pairs — nothing wider. (Builds
before 0.1.0 paired every item's mode with the first item's path,
which both hid later items and widened the first item's scope under
later write modes; fixed and regression-tested, see CHANGELOG.)

## Grant lifecycle

pending --approve--> active --expiry--> expired
pending --12h silence--> expired      active --revoke--> revoked
pending --reject--> rejected          pending --restart--> discarded

Request numbers are one-time. Grants persist across restarts; pending
requests do not (silence grants nothing). No auto-renewal.

## Audit

One JSON record per line, chained: each record carries the SHA256 of
the previous record's canonical form, plus a checkpoint sidecar
(head hash + line count) so truncation is detectable; a chain alone
cannot see its own missing tail. Write-before-operate is literal:
the record is written, flushed, and fsynced before the operation's
transport call, and a failed write refuses the operation.

## Discovery mode

Opt-in per instance (`discovery: true`): `list` operates without a
grant, audit-logged as discovery. Names and structure are visible;
contents never. This exists because gating discovery behind approval
makes such a tool too tedious to use, and users who bypass safeguards
have no safeguards. It is off by default.

## Failure modes (all fail closed)

- Broker down: no access; state preserved.
- Nextcloud down: clean errors; grants unchanged.
- Approval plane down: no new grants; existing grants continue.
- Audit failure: the operation is refused.

## Credentials

App passwords and the bot token live in the broker's config.yaml on
the broker host (chmod 600). The agent holds only its MCP endpoint
and the agent token. Error messages are scrubbed of credential
values: the layer knows each instance's secret and removes it,
without relying on keywords.