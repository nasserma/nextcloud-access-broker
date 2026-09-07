# Cutover Runbook: Deploying the Broker to the Storage Host

Every step has a command and its expected output. If any step's output
does not match, stop and note the actual output before continuing;
the support bundle (step 9) is the debug channel.

## 0. What travels

- The git repo (code, tests, Dockerfile, compose). Not config.yaml
  (it holds secrets; copy it by hand or re-create it on the host).
- Your working config.yaml (re-made on the host in step 3).

## 1. Get the code onto the host

    # from the AI server (or wherever the repo lives):
    rsync -av --exclude .venv --exclude data/ \
      <REPO-PATH-ON-AGENT-HOST>/ \
      <user>@<storage-host>:~/nc-access-broker/

Expected: transfer completes; `ls ~/nc-access-broker` shows broker/,
Dockerfile, docker-compose.yml, scripts/, tests/.

## 2. Data directory

    cd ~/nc-access-broker
    sudo mkdir -p data
    # the container runs as uid 1000; the owner name does not matter,
    # the numeric uid does:
    sudo chown 1000:1000 data
    # verify with numeric uids (-n); names are misleading:
    ls -ldn data

Expected: `drwxr-xr-x ... 1000 1000 ... data`. If it shows a name or
any other number, the broker's SQLite store will fail to open at
startup (verified live in Gate 7 prep) - fix before continuing. On
ZFS/LXC hosts where your own uid differs from 1000, use sudo for
both commands; the container only ever sees the number.

## 3. Create config.yaml on the host

    cp config.yaml.example config.yaml
    nano config.yaml

Fill in (this is the one file that holds secrets; chmod 600):
- matrix: homeserver, bot_user, bot_token, room_id, approver
- agent.token (generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`)
- audit.path: /data/audit.log   (container convention; absolute path)
- instances: the ones to wire now. Note: wire the production
  instances (personal/work) here, on this host, out of agent reach.
- logging.level: info (switch to debug when diagnosing)

    chmod 600 config.yaml

Hand-merge config traps (all hit live in the first deployment; each
is one line):

- `password:` vs `password_env:`: the secret goes under `password:`;
  `password_env:` names an environment variable. Pasting the app
  password under `password_env:` produces
  `ConfigError: environment variable <the-password> is not set` at
  startup. If the error names what looks like your password, you
  pasted it one key too far left.
- `audit.path` must be exactly `/data/audit.log`; the example's
  other value (`data/audit.log`, relative) and the old default
  (`/data/audit/audit.log`, a missing subdirectory) both produce
  `sqlite3.OperationalError: unable to open database file` at
  startup. The parent directory must already exist in the container;
  `/data` does, `/data/audit` does not.
- Paste artifacts: a stray character at column 1 (e.g. a line number
  copied out of a listing) produces
  `ScannerError: could not find expected ':'` naming the line;
  go to that line and check for a lost `#` or an orphaned fragment.
- Validate before restarting, cheaply:
  `python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"`

## 4. Edit compose exposure (the host decides this)

    nano docker-compose.yml

Set the ports address to the host's VPN interface IP:

    ports:
      - "<VPN-IP>:8765:8765"

## 5. Build and start

Precheck (avoid the two first-run traps): the compose plugin present,
and your shell actually in the docker group (group membership applies
at login, so if usermod was just run, log out and back in first):

    docker compose version || sudo apt install docker-compose-v2
    groups | grep -q docker || { sudo usermod -aG docker $USER; \
      echo "added to docker group - log out and back in, then re-run"; }

Then:

    docker compose up -d --build

## 5b. Firewall (most hosts run one; check before probing)

If the host runs ufw (Ubuntu default) or any firewall, the compose
ports mapping is not enough: the firewall drops tunnel traffic to
the new port before Docker ever sees it. The symptom is a port that
`docker ps` shows as published while probes to it time out (not
refused).

Check and allow, scoped to the tunnel interface and, tighter still,
to the agent machine's tunnel address:

    sudo ufw status
    # allow only the agent machine, only over the tunnel:
    sudo ufw allow in on tun0 from <AGENT-TUNNEL-IP> to any port 8765 proto tcp
    # (substitute your tunnel interface name and agent's tunnel IP;
    #  verify the interface with: ip addr show | grep tun)

For other firewalls (nftables/iptables), the equivalent rule: allow
TCP/8765 in on the tunnel interface from the agent's tunnel address.
Do not add a blanket 'anywhere' rule; the point of the one-address
compose line is that the host decides who connects.

Verify from the agent machine (not the host):

    curl -s -o /dev/null -w "%{http_code}\n" http://<broker-address>:8765/mcp
    # expected: 401 (the auth gate; success)

A timeout means firewall; a refusal means the compose line binds a
different address than you are probing; 401 means you are through.

Expected: `docker ps` shows nc-access-broker Up (health: starting →
healthy within a minute). `docker logs nc-access-broker` shows
`broker starting: N instance(s) configured` and `Uvicorn running`.

## 6. Trashbin check (deviation D1 condition, per wired instance)

For each wired Nextcloud instance, in its web UI: Settings → Apps →
confirm "Deleted files" (trashbin) is enabled. If it is disabled, the
broker's trash verb would delete permanently. This is a condition
of D1 closure; do not skip.

## 6b. files_lock check (D5 condition, per wired instance)

Confirm the "Temporary files lock" app (ID files_lock; the store
name is not "Collaborative File Locking", which will not match a
search) is enabled on every instance where checkout is intended:

    sudo -u www-data php occ app:enable files_lock

Without it the checkout verb returns a clean 405 error naming the
app. Locks are visible in the web UI next to the file; the file
owner can override them; `occ files:lock --unlock <fileId>`
force-unlocks as admin. Configure a lock timeout on the instance if
indefinite locks are unwanted:
`occ config:app:set --value '240' files_lock lock_timeout`.

## 7. Reachability probes (from the AI server, not the host)

    # from the tunnel (should reach; 401 is success, the auth gate):
    curl -s -o /dev/null -w "%{http_code}\n" http://<VPN-IP>:8765/mcp
    # expected: 401

    # from the LAN address (must be refused; connection error, not 401):
    curl -s -o /dev/null -w "%{http_code}\n" http://<LAN-IP>:8765/mcp
    # expected: 000 / "connection refused"

If the LAN probe connects: the compose ports line is wrong. Fix it
before proceeding.

## 8. Token check (from the AI server)

    curl -s -X POST -H "Authorization: Bearer <agent-token>" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}' \
      http://<VPN-IP>:8765/mcp
    # expected: 200 with session id header

## 9. First request cycle (the real thing)

Ask the agent (from the AI server, MCP wired per step 10) to submit
any request, or do it with curl:
- The request appears in your approval room with 4 reactions.
- Approve (👍), see the confirmation + summary.
- Revoke (🛇), see the refusal on the next operation.
This is the witnessed production cycle for Gate 7.

## 10. Wire the agent (Hermes, on the AI server)

    hermes config set mcp_servers.nc-broker.url "http://<VPN-IP>:8765/mcp"
    hermes config set mcp_servers.nc-broker.headers.Authorization "Bearer \${BROKER_AGENT_TOKEN}"
    hermes config set mcp_servers.nc-broker.timeout 120

BROKER_AGENT_TOKEN (the same agent token as config.yaml) goes into the
Hermes .env. Then /reset the session. Verify with /tools: the listed
tools must not include read or write (D5: the agent surface never
registers content tools).

## 10b. Install the transfer CLI (D5, on the AI server)

The CLI is the only sanctioned content path. It ships in the same
package; install it on the AI server from the rsync'd repo:

    cd <REPO-PATH-ON-AGENT-HOST>
    uv venv .venv-cli && uv pip install --python .venv-cli/bin/python .
    # or into an existing venv: pip install -U .

Credentials (choose the env path; nothing token-shaped in a file):
- BROKER_TRANSFER_TOKEN in the environment that invokes the CLI
  (shell profile or per-command env). Never on the command line.
- Broker URL pinned once:

      mkdir -p ~/.config/nc-broker && chmod 700 ~/.config/nc-broker
      printf 'broker_url = "http://<VPN-IP>:8765/transfer"\n' \
        > ~/.config/nc-broker/config.toml
      chmod 600 ~/.config/nc-broker/config.toml

Cross-token verification (both directions, from the AI server):

    # agent token on /transfer: must 401
    curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer ${BROKER_AGENT_TOKEN}" http://<VPN-IP>:8765/transfer
    # expected: 401
    # transfer token on /mcp: must 401
    curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer ${BROKER_TRANSFER_TOKEN}" http://<VPN-IP>:8765/mcp
    # expected: 401

Then one full CLI round-trip: fetch a granted file, verify the
manifest, push it back (or checkout/checkin if the app-lock cycle is
being verified). Upgrades: the broker container and the AI-host CLI
must stay in lockstep (server tool envelopes ↔ CLI parsing); rsync
the repo, rebuild the container, and pip-install the CLI in the same
change.

## 11. If anything goes wrong

    docker exec nc-access-broker python /app/scripts/supportBundle.py

Produces one sanitized file; send it to the agent. It contains
config (redacted), grant states, audit chain verification, and
recent container logs, all credential-free by construction. For
verbose logs, set logging.level: debug in config.yaml and
`docker compose restart` (restart discards nothing; grants persist,
pending requests are discarded by design).

## Rollback

    docker compose down        # stops the broker; grants/audit persist in ./data
    # to restore dev operation on the AI server: nothing was removed there.

## Post-cutover (not tonight)

- Two-week observation window starts.
- Audit review at the end (the agent reads the chain).
- Final review (Gate 8), then public release.