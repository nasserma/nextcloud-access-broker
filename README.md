# Nextcloud Access Broker

A human-gated MCP server between AI agents and Nextcloud instances.
(MCP is the tool-calling interface AI agents use.) The agent holds no
standing file-content access: every read and write requires a scoped,
time-limited grant that the owner approves through the configured
approval gateway, currently a Matrix room. On instances that opt
in, the agent can browse file names without a grant. Every
operation is audit-logged before it runs.

## What it enforces

- **Grants:** per-task batches of paths with read/write modes,
  approved by the owner in a private Matrix room (emoji reactions;
  typed replies for partial approval, custom expiry, revoke, and
  mass revoke: `revoke <instance>` / `revoke all`).
  Grants expire after 24h by default, request numbers work once,
  revocation is instant, nothing renews itself, and the agent holds
  no standing access of any kind.
- **The wall:** one path-checking function decides every operation
  (exact component-prefix matching after normalization; traversal,
  encoding, and confusable attacks fail closed). The trashbin
  namespace is unreachable, and no permanent delete exists.
- **Audit:** an append-only, hash-chained log is written before
  every operation; a failed log write refuses the operation.
- **Credentials:** Nextcloud app passwords and the Matrix bot token
  live in `config.yaml` on the storage host. The agent sees only the
  MCP endpoint and the agent token. Error messages are scrubbed of
  credential values, not just keywords.

## Prerequisites

Development: Python 3.11+ (uv venv). Production: Docker and Docker
Compose. On Debian/Ubuntu: `sudo apt install docker.io
docker-compose-v2`, then `sudo usermod -aG docker $USER` (see the
[user guide](docs/userGuide.md) for details). You also need one app
password per Nextcloud instance you wire, and a Matrix bot account
in a private room with you.

## Running (development)

```bash
uv venv && uv pip install -e ".[dev]"
cp config.yaml.example config.yaml   # fill in room, tokens, instances
.venv/bin/python -m broker.run       # localhost:8765/mcp, bearer auth
```

## Running (production, Docker)

The host decides exposure. `docker-compose.yml` publishes the broker
on one specific interface address of your choosing: a VPN/tunnel
interface (recommended when the agent connects over one), a LAN
interface, or `127.0.0.1` behind your own reverse proxy with TLS.
Change that address on the host at any time; the app never needs
rebuilding for it. Do not publish wider than you intend.

```bash
# on the Nextcloud host (the storage host):
docker compose up -d --build
# data/ holds the grant store, audit log, and checkpoint; back it up.
```

Deployment checklist (Gate 7):
1. Verify the trashbin app is enabled on every wired instance
   (deviation D1 condition: trash routing depends on it), and the
   `files_lock` app is enabled where checkout is intended (D5:
   LOCK returns an actionable 405 without it).
2. Confirm the compose ports address is the interface you intend,
   and not one you do not: `curl` to the intended address must
   return 401 (the auth gate working as intended), and addresses
   you did not choose must refuse the connection. A timeout means
   a host firewall (ufw and the like) is dropping the port; allow
   it scoped to the chosen interface and the agent's address,
   never as a blanket rule.
3. Mount `data/` on persistent storage; the audit log is the record.
4. Fill `config.yaml` per instance block; personal/work/org blocks
   are commented out until deliberately wired (they stay absent from
   the running config until the owner adds them on the host).

## Hermes (agent) configuration

On the AI server, add to the profile's `mcp_servers` (config.yaml via
`hermes config set`, never hand-edit):

```yaml
mcp_servers:
  nc-broker:
    url: "http://<broker-address>:8765/mcp"
    headers:
      Authorization: "Bearer ${BROKER_AGENT_TOKEN}"
    timeout: 120
    connect_timeout: 60
```

`BROKER_AGENT_TOKEN` goes in the Hermes `.env`; it is the same agent
token configured in the broker's `config.yaml` on the host.

## Tools

**Agent surface (`/mcp`, agent token):** `request_access` (batch:
instance, reason, items[{path, mode}]), `check_access`,
`list_instances` (configured instance names + discovery flags; no
URLs or credentials — D6.5), `list` (free under discovery), `move`,
`trash`, `mkdir`. The content tools (`read`, `write`) are not
registered on this surface, so an agent can neither see nor call
them (D5: file content never transits the LLM context window).

**Transfer surface (`/transfer`, transfer token, CLI only):**
`check_access`, `read`, `write`, `checkout`, `checkin`. These are
spoken by the `broker` CLI (`broker fetch/push/checkout/checkin`),
which stages files on the client host and hands the agent a local
path plus a manifest (sha256, size, lock token). The agent then
works on the local copy with normal file tools.

**Sync model (D5):** read-only work uses on-demand fetch with a
manifest freshness check. Read-write work uses checkout/checkin over
Nextcloud `files_lock`: a checked-out file is write-refused on every
access path (web UI, sync clients, other agents) until checkin
spends the lock token. An abandoned checkout is hard to miss: it
shows in the file list and the owner can override it, where an
abandoned sync would sit unnoticed.

Result envelope: `ok` / `refused` (the wall; do not retry) / `error`
(infrastructure; report it) / `pending` (wait for the human
decision). CLI exit codes: 0 ok, 1 local/usage, 2 infrastructure
(retry later), 3 wall-refused (request access, never retry as-is),
4 verification failure (treat as corrupt), 5 clobber refused.

## Failure modes (all fail closed)

- Broker down: no access, state preserved (grants resume on restart;
  pending requests are discarded; silence grants nothing).
- Nextcloud down: clean errors; grants unchanged.
- Approval plane down: no NEW requests; existing grants continue.
- Audit write failure: operation refused.

## Testing

```bash
.venv/bin/pytest              # 362 tests
.venv/bin/ruff check broker tests review
.venv/bin/python review/attack_battery.py   # fresh wall attacks
.venv/bin/python review/r2_state_probes.py  # store-state probes
```

## Documentation

- [Architecture](docs/architecture.md): components, the wall, the
  grant lifecycle, the audit chain, and the threat model in brief.
- [User guide](docs/userGuide.md): setup, the approval protocol,
  running, and troubleshooting.
- [Cutover runbook](docs/cutoverRunbook.md): step-by-step first
  deployment, with a verification command at every step.
- [Security policy](SECURITY.md): what this defends against, and
  what it explicitly does not.
- [Contributing](CONTRIBUTING.md): the development discipline.

License: GPL-3.0 (see LICENSE).

## AI usage disclosure

This software was developed with AI assistance under human direction;
the maintainer reviewed, tested, and is accountable for all code
(`ai-assisted` in the emerging W3C/OCaml disclosure vocabulary). The
primary implementation model was GLM (glm-5.3), with
glm-5.3-flash as the delegated sub-agent model for parallel review and
auxiliary tasks. Portions of the implementation, tests, and
documentation are AI-generated; every contribution passed through the
verification pipeline before release: a 405-test suite with
injected-clock determinism, adversarial review with runnable attack
scripts (`review/`), and a secret-scrubbing publish audit.

This is security-sensitive infrastructure for human-gated file access.
If you deploy it, do so on the same terms the maintainer does: read
the threat model (`SECURITY.md`), run the attack battery yourself, and
treat the approval room, tokens, and audit log as part of your own
trust boundary. Provided under GPL-3.0 without warranty; see LICENSE.

## Project status

Deployed and operating on the maintainer's infrastructure, including
a dual-surface content-transfer model (agent surface carries no
content tools; file content moves only through a separate
token-gated CLI surface). The wall, grant store, and audit chain are
production-tested; the development discipline is adversarial review
with runnable attack scripts in `review/`.