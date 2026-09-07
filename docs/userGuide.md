# User Guide

## Prerequisites

- **Python 3.11+** (development), **Docker + Docker Compose**
  (production deployment).
- A Nextcloud instance you administer, with an app password per
  instance you wire (Settings → Security).
- An account on an approval gateway the broker can reach, currently
  a Matrix homeserver, plus a private room with exactly you and the
  bot in it.

### Installing Docker (production host)

Debian/Ubuntu — the distribution package is sufficient for this
project:

```bash
sudo apt update
sudo apt install docker.io docker-compose-v2
```

Then let your own user manage Docker without sudo (the standard
post-install step; re-login or run `newgrp docker` afterward):

```bash
sudo usermod -aG docker $USER
```

Verify both work before continuing:

```bash
docker --version
docker compose version
```

Other distributions: use your package manager's docker and
docker-compose equivalents, or follow the official install docs at
docs.docker.com. The project needs only `docker run` and `docker
compose`; it uses no swarm mode and no registry logins.

## Installation

```bash
git clone <repo> && cd nextcloud-access-broker
uv venv && uv pip install -e ".[dev]"
cp config.yaml.example config.yaml
```

## First-run setup

1. **Matrix bot account.** Create a dedicated account on your
   homeserver for the bot (e.g. `@broker:your-homeserver`). Create a
   private room containing only you and the bot. Fill `matrix:` in
   `config.yaml`: homeserver, bot user, bot access token, the room
   ID, and your own user ID as `approver`. The approver and bot must
   be different accounts.

2. **Agent token.** Generate one:
   `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
   Put it in `agent.token` in the config. This is what your MCP
   client presents.

3. **Nextcloud instances.** For each instance: an app password
   (Nextcloud → Settings → Security), the URL, the username. Set
   `discovery: true` on instances where you accept that the agent can
   browse file names freely (recommended for usability; contents stay
   gated). Leave instances absent entirely if the agent should have
   no path to them.

4. **Data location.** Set `audit.path`. The grant store is created
   next to it. Back up that directory: it is your audit trail.

## The approval protocol

When the agent requests access, your room receives one message:

```
Access request #47
Instance: personal
Reason: revise the paper's figures
1. WRITE - Documents/paper/figures

Expires: 24h or task end (or reply with a shorter one)
```

The message carries four reactions, pre-placed: 👍 👎 🛇 📋.

- **👍** approve the whole batch.
- **👎** reject the whole batch.
- **🛇** revoke an active grant at any time (works on any of the
  bot's request messages).
- **📋** status: reposts all open approvals with time remaining.

Typed replies (uncommon cases): `approve 47 1,2` (partial approval
by item), `approve 47 8h` (shorter expiry), `revoke 47`, `status`.

After every decision the bot posts a confirmation with the open-
approvals summary. Revocation is immediate and announced.

## Running

Development:

```bash
.venv/bin/python -m broker.run        # localhost:8765/mcp
```

Production (Docker): the host decides network exposure. The included
compose file publishes on one address of your choosing: a VPN/tunnel
interface if your agent connects over one, a LAN interface, or
127.0.0.1 behind your own reverse proxy with TLS. The application
owns the port; exposure policy belongs to the host, not the app.

```bash
mkdir data && chown 1000:1000 data    # container runs as uid 1000
docker compose up -d --build
```

Verify: `curl -s http://<chosen-address>:8765/mcp` → 401 (the auth
gate works). From any address you did not choose it must be
connection-refused. If probes time out, the host firewall is
dropping the port; on ufw, allow it scoped to the chosen interface
and the agent's source address (`sudo ufw allow in on <iface> from
<agent-ip> to any port 8765 proto tcp`), never as a blanket allow.

## Connecting an MCP client

```yaml
mcp_servers:
  nc-broker:
    url: "http://<broker-address>:8765/mcp"
    headers:
      Authorization: "Bearer <agent-token>"
```

## Troubleshooting

- **"path is in a forbidden namespace"** on a normal folder: the
  folder is named like the trashbin namespace (`trashbin`,
  `files_trashbin` in any case). Rename it, or accept that it stays
  blocked; the block is deliberate.
- **Refusals with no request posted**: check the bot's homeserver
  connectivity; the approval plane being down means no new grants
  (existing ones keep working).
- **Broker exits at startup**: audit path's directory missing or not
  writable by the runtime user; the broker fails closed instead of
  running unobserved.
- **Verify the audit log** after any incident:
  `python -c "from broker.audit import verify_chain; \
  print(verify_chain('<data>/audit.log'))"`

## When something misbehaves (remote debugging)

The single command that produces everything the maintainer needs:

```bash
docker exec nc-access-broker python /app/scripts/supportBundle.py
```

One JSON file comes out: configuration (redacted), grant states, the
audit chain verification, recent container logs, platform info. The
script self-checks that no secret survived scrubbing before telling
you it is safe to send.

For verbose logs while diagnosing: set `logging.level: debug` in
config.yaml and restart the container. Every log line is scrubbed of
secret values by construction, so logs are safe to share at any level.
Grant state survives restarts; pending requests are discarded (by
design; silence grants nothing).

## Operational rules of thumb

- Approve the smallest scope that the task needs; the request format
  shows you exactly what you are approving.
- Discovery mode is the usability valve: if you find yourself
  approving many `list` requests, turn discovery on for that
  instance instead of training yourself to approve everything.
- The audit log is your incident record: hash-verified, append-only.

## Keeping the broker running across reboots

For how the stack survives host reboots and failures (restart policies,
lingering, systemd supervision units, and verification drills), see
[serviceSupervision.md](serviceSupervision.md).