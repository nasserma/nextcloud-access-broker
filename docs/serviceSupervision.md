# Service supervision: keeping the broker up across reboots and failures

This document describes how the MCP broker container stays running across
host reboots and crashes, honestly stating which layer provides which
guarantee — and which guarantees no current layer provides. Three layers
are involved:

1. **Docker's restart policy** (`restart: unless-stopped` in
   `docker-compose.yml`) — restarts the *container*.
2. **The Docker daemon** (`docker.service` / `docker.socket`) — must be
   running for layer 1 to do anything at all.
3. **systemd supervision of the compose stack itself** — the part that
   does *not* exist by default, documented in sections 2 and 3 below.

---

## 1. What the current setup already provides — and what it does not

### What `restart: unless-stopped` gives you

The compose file sets `restart: unless-stopped` on the `broker` service
(container name `nc-access-broker`). With it in place, Docker's embedded
restart manager will:

- Restart the container automatically if the broker process crashes
  (non-zero exit) at any time while the daemon is running.
- Restart the container when the Docker daemon starts **if** the
  container was running when the daemon last stopped — this is what
  carries you across a host reboot, and what happens when you bounce
  the daemon with `sudo systemctl restart docker`.

Two **preconditions** make the reboot case actually work:

- **The Docker daemon must be enabled at boot.** Check with
  `systemctl is-enabled docker docker.socket`. `docker.socket`
  (socket activation) is normally enabled by default on Debian/Ubuntu;
  if only the socket unit is enabled, the daemon starts on first use
  rather than at boot, which delays but does not prevent the restart.
  If both are disabled, nothing starts the container at boot.
- **The container must have been started at least once with the
  restart policy applied** — i.e. someone ran
  `docker compose -f ~/nc-access-broker/docker-compose.yml up -d`.
  The policy is recorded on the container at `up` time. A container
  that only ever ran with `docker run` (no `--restart`), or a compose
  project that was never brought up, is invisible to this mechanism.

Note also: `unless-stopped` deliberately does **not** restart a
container that was stopped with an explicit `docker stop` /
`docker compose stop` before the daemon stopped. That is by design —
a manual stop survives reboots. If you stopped it manually and want it
back after reboot, run `docker compose up -d` again.

### What is NOT covered

Be clear-eyed about these gaps; none of the layers above handles them:

- **Docker daemon disabled at boot** — no reboot recovery at all.
  The container sits dead until a human logs in and starts Docker.
- **Compose project never started** — `restart: unless-stopped` is a
  property of an existing container, not a promise to create one.
  Nothing will ever start a project that was never `up -d`'d.
- **Stuck-but-running container.** The healthcheck (defined in the
  `Dockerfile`, probing `http://127.0.0.1:8765/mcp` from inside the
  container every 60s, 3 retries, 10s timeout, 15s start period) only
  flips the container's health status to `unhealthy`. **Plain Docker
  has no orchestration layer that replaces unhealthy containers** —
  unlike Docker Swarm or Kubernetes, `docker compose up -d` and the
  restart policy both ignore health status. A wedged broker (process
  alive, MCP endpoint dead) stays wedged forever while reporting
  `unhealthy` in `docker ps`. This is the single most important gap.
- **Host-level sleep/hibernate (laptop/desktop storage hosts).** On
  suspend, timers and wall-clock health intervals freeze; on resume,
  Docker does not proactively restart or probe containers. If the
  broker's connections time out during sleep, it shows up only as
  failed requests until something restarts it. On a server that never
  suspends this is moot; if this host suspends, treat resume as a
  manual `docker compose up -d` checkpoint (or don't suspend it).
- **Compose file / config changes** — `up -d` once does not notice
  later edits to `docker-compose.yml` or the image; a recreate is a
  deliberate act (see the cutover runbook), not something supervision
  provides.

Sections 2–3 close the first two gaps (boot ordering, ensure-running)
and partially close the third (detect-and-restart on unhealthiness)
by adding a supervisor *above* Docker.

---

## 2. Recommended: a systemd **user** unit supervising the compose stack

Because the deployer is a member of the `docker` group and runs Docker
without root, the natural supervisor runs in the user's own systemd
instance (`systemctl --user`). It is a thin watchdog: it exists to make
sure the compose stack is up and healthy, not to manage the container
lifecycle (Docker already does that).

### Unit file: `~/.config/systemd/user/nc-access-broker.service`

```ini
[Unit]
Description=Nextcloud Access Broker - ensure Docker Compose stack is up and healthy
# NOTE: user units cannot order against system units. There is no
# docker.service or docker.socket in the user manager, so
# Wants=docker.service / Requires=docker.socket do NOTHING here (the
# user systemd silently ignores unknown unit names in dependencies —
# they do not fail, they just never provide ordering). Do not bother.
# Instead, ExecStartPre below waits for the daemon to be reachable.

[Service]
Type=oneshot
RemainAfterExit=yes
# Wait up to ~90s for the Docker daemon to answer. On boot this is what
# provides ordering against docker.service without any cross-manager
# dependency: we simply poll until "docker info" succeeds.
ExecStartPre=/bin/sh -c 'for i in $(seq 1 30); do docker info >/dev/null 2>&1 && exit 0; sleep 3; done; echo "docker daemon unreachable after 90s" >&2; exit 1'
# Idempotent: "up -d" creates the stack if missing, reconciles it if
# changed, and does nothing if it is already correct.
ExecStart=/usr/bin/docker compose -f %h/nc-access-broker/docker-compose.yml up -d
# Health gate: wait for the container to report healthy (start period is
# 15s, interval 60s, retries 3 - allow up to ~5 minutes), then fail the
# unit if it never got healthy. The unit is oneshot, so a failure here is
# visible in status and can be retried by the timer below.
ExecStartPost=/bin/sh -c 'for i in $(seq 1 30); do [ "$(docker inspect --format "{{.State.Health.Status}}" nc-access-broker 2>/dev/null)" = healthy ] && exit 0; sleep 10; done; echo "container not healthy after 5 min - restarting stack" >&2; docker compose -f %h/nc-access-broker/docker-compose.yml restart; exit 1'
# Reconcile on every (re)activation, including after the timer's restart.
ExecStop=/usr/bin/docker compose -f %h/nc-access-broker/docker-compose.yml stop

[Install]
WantedBy=default.target
```

Notes on the unit:

- `%h` expands to the user's home directory, so the unit works without
  hardcoding `/home/<user>`. Adjust the path if the repo lives elsewhere
  (production convention in this repo's docs is `~/nc-access-broker`).
- `Type=oneshot` + `RemainAfterExit=yes` means the unit shows `active`
  after a successful run and costs nothing while idle. The unit's job is
  "the stack was verified up and healthy at activation time"; the timer
  in the next subsection re-runs that verification periodically.
- The `ExecStartPost` health loop is the closest userspace analogue to
  orchestration auto-replace: if the container never reaches `healthy`,
  the stack is restarted once and the unit fails loudly.

### Optional companion timer (periodic health reconcile)

`~/.config/systemd/user/nc-access-broker-health.timer`:

```ini
[Unit]
Description=Periodically verify nc-access-broker is up and healthy

[Timer]
OnBootSec=10min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
```

This triggers the same service every 15 minutes (the service is
idempotent and cheap when everything is healthy: one `docker info`, one
`up -d` no-op, one health inspect). This is the watchdog leg that
catches a stack that was stopped out from under systemd, or a container
that went unhealthy between activations. If you prefer the timer to
only *detect* rather than restart, drop the `restart` from the
`ExecStartPost` failure path — but then a failure only pages you, it
does not heal.

### Enable-linger: the critical step for boot-time start

A user systemd instance starts at login and **exits at logout** — unless
lingering is enabled. Without linger, your unit never runs at boot at
all (and dies when you log out). Enable it once:

```bash
sudo loginctl enable-linger $USER
# verify:
loginctl show-user $USER | grep Linger   # expect: Linger=yes
```

Linger makes the user manager start at boot, so `WantedBy=default.target`
behaves like a system unit's `multi-user.target`.

### Install and activate

```bash
mkdir -p ~/.config/systemd/user
# (create the two files above, then)
systemctl --user daemon-reload
systemctl --user enable --now nc-access-broker.service
systemctl --user enable --now nc-access-broker-health.timer
```

### Status and journal

```bash
systemctl --user status nc-access-broker.service
systemctl --user list-timers nc-access-broker-health.timer
journalctl --user -u nc-access-broker.service -f
journalctl --user -u nc-access-broker.service --since "last boot"
```

---

## 3. Alternative: a **system-level** unit (requires sudo)

If you hold sudo on the storage host, a system unit gives you real
ordering and does not depend on linger:

`/etc/systemd/system/nc-access-broker.service`:

```ini
[Unit]
Description=Nextcloud Access Broker - Docker Compose stack
# Real cross-unit ordering IS available at system level:
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=<deployer-user>          # the docker-group user; no root container needed
ExecStart=/usr/bin/docker compose -f /home/<deployer-user>/nc-access-broker/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f /home/<deployer-user>/nc-access-broker/docker-compose.yml stop

[Install]
WantedBy=multi-user.target
```

(Add the same `ExecStartPre` poll and `ExecStartPost` health loop from
the user unit if you want the health gate; they work identically here,
and `Requires=docker.service` replaces the need for the `ExecStartPre`
daemon-wait loop, though keeping it is harmless.)

Activate:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nc-access-broker.service
```

### Tradeoffs: user unit vs system unit

| | `--user` unit (§2) | system unit (§3) |
|---|---|---|
| Requires sudo to install | No | Yes |
| Boots without login | Only with `loginctl enable-linger` | Always |
| Orders against `docker.service` | No (poll `docker info` instead) | Yes (`Requires`/`After`) |
| Survives `dockerd` restarts of its own supervisor | N/A | N/A |
| Scope creep | Isolated to user session | Part of system boot |
| Right when | Deployer has no sudo; single-admin host; principle-of-least-privilege deployment | Multi-user host; broker treated as core infrastructure; you want boot-order guarantees enforced by PID 1 |

For this deployment — a single-purpose storage host where the deployer
is in the `docker` group — the **user unit is the recommended default**:
it achieves the same practical outcome (stack verified up at every boot,
restarted on failure) without ever touching root-owned unit files. Reach
for the system unit only if linger is unacceptable or you need hard
ordering against the daemon rather than a poll.

Either way, remember what the supervisor adds on top of `restart:
unless-stopped`: (a) the stack gets created even if it was never
`up -d`'d, and (b) an unhealthy container gets restarted (§2's
`ExecStartPost`) rather than being left wedged. It does not add
in-container crash restarts — Docker's policy still owns that, and it is
faster anyway (immediate vs. the unit's poll granularity).

---

## 4. Verification

### After (re)boot — full supervision test

```bash
sudo reboot
# ... after reboot, without logging in on the console if possible:
systemctl --user status nc-access-broker.service   # active (exited), RemainAfterExit
systemctl --user list-timers nc-access-broker-health.timer  # next run scheduled
docker ps --filter name=nc-access-broker           # Up (healthy)
```

If you test by SSH, note that without linger the `--user` manager dies
when your last session closes — `loginctl show-user $USER | grep Linger`
must print `Linger=yes` for the boot-time test to be meaningful.

### Health status, both directions

```bash
# expected: healthy (within ~1-2 min of container start)
docker inspect --format '{{.State.Health.Status}}' nc-access-broker
# full health log (per-probe results, exit codes, output):
docker inspect --format '{{json .State.Health}}' nc-access-broker | python3 -m json.tool
```

The healthcheck itself (Dockerfile) considers HTTP 200, 401, and 405 on
`http://127.0.0.1:8765/mcp` healthy — 401 is the auth gate answering,
which is the expected steady state.

### End-to-end reachability (from the agent machine, not the host)

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<broker-address>:8765/mcp
# expected: 401 (see userGuide.md and cutoverRunbook.md for the full probe matrix)
```

### Journals

```bash
journalctl --user -u nc-access-broker.service --since "last boot"
# system-wide Docker view (daemon start, container events):
sudo journalctl -u docker.service --since "last boot"
# container application logs (broker startup lines, Uvicorn bind):
docker logs nc-access-broker --since 10m
```

### Failure-injection drills (recommended once, then after any change)

- **Crash restart (Docker layer):**
  `docker exec nc-access-broker kill 1` → container should be
  `Restarting` → `Up` within seconds, health `starting` → `healthy`.
- **Never-started stack (supervisor layer):**
  `docker compose -f ~/nc-access-broker/docker-compose.yml down` →
  wait for the health timer's next tick (≤15 min) → stack is back up.
  (Immediate test: `systemctl --user start nc-access-broker.service`.)
- **Unhealthy container (watchdog layer):** simulate by temporarily
  pointing the healthcheck's probe at a closed port, rebuild, and
  observe the `ExecStartPost` failure + stack restart in
  `journalctl --user -u nc-access-broker.service`.

---

## Cross-references

- Deployment and first bring-up: `docs/cutoverRunbook.md`
- Day-to-day operation, config, and reachability probes: `docs/userGuide.md`
- Why the host decides exposure / design of the ports line:
  `docs/architecture.md` and the design PDF (§3.7)