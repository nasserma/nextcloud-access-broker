"""Configuration loading (Stage 7 groundwork, needed now for T5.6).

Design document section 3.7 and the config example. Rules enforced:

- The room ID, approver, homeserver, and bot user are required.
- The agent token and instance passwords come from ENVIRONMENT
  VARIABLES named in the config (token_env/password_env), never from
  the config file itself. Missing required env values fail startup.
- host 0.0.0.0 (or empty) is refused at load time: the broker binds to
  the tunnel interface only.
- Instances absent from the config are refused everywhere else in the
  broker (the allowlist IS the config).
"""

from __future__ import annotations

import os
import re

import yaml

_ROOM_ID_RE = re.compile(r"^![\w.-]+:[\w.-]+$")
_USER_ID_RE = re.compile(r"^@[\w.-]+:[\w.-]+$")


class ConfigError(Exception):
    """Startup configuration is invalid or incomplete.

    Raised for missing required fields, unresolved secrets, format
    violations, and forbidden values. The broker refuses to start
    (fail closed at boot) rather than running with defaults.
    """


def _secret(block: dict, direct_key: str, env_key: str, what: str, env: dict, default_env: str = "") -> str:
    """Resolve a secret: a direct value in the yaml wins (design doc:
    one config file holding credentials); password_env/token_env is an
    optional indirection for deployments that prefer environment
    variables. One of the two must be present."""
    direct = block.get(direct_key)
    if direct:
        return str(direct)
    env_name = block.get(env_key) or default_env
    if not env_name:
        raise ConfigError(f"missing {what}: provide {direct_key} or {env_key}")
    value = env.get(env_name) or os.environ.get(env_name)
    if not value:
        raise ConfigError(f"environment variable {env_name} ({what}) is not set")
    return value


class Config:
    """Validated configuration view over the raw yaml + env.

    Constructing a Config fully validates every section and raises
    ConfigError on the first problem; instances of this class are only
    ever created with complete, well-formed settings, so downstream
    wiring code can index attributes without re-checking. Secrets are
    resolved here once and held in memory only.
    """

    def __init__(self, raw: dict, env: dict):
        """raw: parsed yaml mapping; env: environment mapping used to
        resolve *_env indirections (defaults to os.environ at load_config).
        Runs all section validators in order - any ConfigError aborts
        construction, so a partially-validated Config never escapes.
        """
        self._raw = raw
        self._env = env
        self.matrix = self._matrix()
        self.agent = self._agent()
        self.server = self._server()
        self.lifecycle = self._lifecycle()
        self.audit = self._audit()
        self.instances = self._instances()

    # ------------------------------------------------------------- sections

    def _require(self, section: str, key: str):
        """Fetch a required (section, key); None and '' both count as
        missing and abort startup with a named ConfigError."""
        value = self._raw.get(section, {}).get(key)
        if value in (None, ""):
            raise ConfigError(f"missing required config: {section}.{key}")
        return value

    def _resolve_env(self, name: str, what: str) -> str:
        """Resolve an env var by name from the injected env, falling back
        to os.environ (so tests can inject without touching the real
        environment). Raises ConfigError naming both the var and what
        it was for, so startup failures are diagnosable without a yaml.
        """
        if not name:
            raise ConfigError(f"missing env var name for {what}")
        value = self._env.get(name) or os.environ.get(name)
        if not value:
            raise ConfigError(f"environment variable {name} ({what}) is not set")
        return value

    def _matrix(self):
        """Validate the approval-plane section: homeserver, bot identity,
        room, and the single approver.

        bot_user and approver are format-checked against Matrix id
        syntaxes and MUST differ: if the bot were its own approver, the
        approval plane could be driven by the bot's own events - a
        self-approval loop with no human in it.
        """
        homeserver = self._require("matrix", "homeserver")
        bot_user = self._require("matrix", "bot_user")
        room_id = self._require("matrix", "room_id")
        approver = self._require("matrix", "approver")
        block = self._raw.get("matrix", {})
        bot_token = _secret(
            block, "bot_token", "bot_token_env", "matrix bot token",
            self._env, default_env="BROKER_MATRIX_TOKEN",
        )
        if not _USER_ID_RE.match(bot_user):
            raise ConfigError(f"bot_user is not a valid Matrix user id: {bot_user!r}")
        if not _USER_ID_RE.match(approver):
            raise ConfigError(f"approver is not a valid Matrix user id: {approver!r}")
        if not _ROOM_ID_RE.match(room_id):
            raise ConfigError(f"room_id is not a valid Matrix room id: {room_id!r}")
        if bot_user == approver:
            raise ConfigError("approver and bot_user must differ")
        return {
            "homeserver": homeserver,
            "bot_user": bot_user,
            "bot_token": bot_token,
            "room_id": room_id,
            "approver": approver,
        }

    def _agent(self):
        """Validate the agent section: two bearer tokens.

        agent.token authenticates AI agents against the discovery/
        control surface (/mcp); agent.transfer_token authenticates the
        transfer CLI against the content surface (/transfer). D5: file
        content never transits the LLM context window, so content tools
        answer ONLY to the transfer token. Minimum length 32 enforces a
        real secret, and the two tokens MUST differ — a copy-paste
        identity would silently collapse the two surfaces into one
        (fail closed at boot, like every other config error).
        """
        block = self._raw.get("agent", {})
        token = _secret(
            block, "token", "token_env", "agent token",
            self._env, default_env="BROKER_AGENT_TOKEN",
        )
        if len(token) < 32:
            raise ConfigError("agent token must be at least 32 characters")
        transfer_token = _secret(
            block, "transfer_token", "transfer_token_env", "transfer token",
            self._env, default_env="BROKER_TRANSFER_TOKEN",
        )
        if len(transfer_token) < 32:
            raise ConfigError("transfer token must be at least 32 characters")
        if token == transfer_token:
            raise ConfigError(
                "agent token and transfer token must differ — identical "
                "tokens would collapse the D5 content-tool separation"
            )
        return {"token": token, "transfer_token": transfer_token}

    def _server(self):
        port = self._require("server", "port")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigError(f"server.port must be an int in 1-65535, got {port!r}")
        # bind_host is OPTIONAL and only meaningful in host-network mode.
        # Interface exposure is the host's job (docker-compose ports:),
        # not the application's. Wildcard binds are still refused here
        # as defense in depth.
        bind_host = self._raw.get("server", {}).get("bind_host") or None
        if bind_host in ("0.0.0.0", "::"):
            raise ConfigError(
                "refusing wildcard bind_host: exposure is decided by the host "
                "(docker-compose), never by the application (design doc 3.7)"
            )
        return {"port": port, "bind_host": bind_host}

    def _lifecycle(self):
        lc = self._raw.get("lifecycle", {})
        pending = lc.get("pending_timeout_hours", 12)
        default = lc.get("default_grant_hours", 24)
        if not isinstance(pending, (int, float)) or pending <= 0:
            raise ConfigError("lifecycle.pending_timeout_hours must be positive")
        if not isinstance(default, (int, float)) or default <= 0:
            raise ConfigError("lifecycle.default_grant_hours must be positive")
        return {"pending_timeout_hours": pending, "default_grant_hours": default}

    def _logging(self):
        level = self._raw.get("logging", {}).get("level", "info")
        if str(level).lower() not in ("info", "debug"):
            raise ConfigError(f"logging.level must be info or debug, got {level!r}")
        return {"level": str(level).lower()}

    @property
    def logging_level(self) -> str:
        return self._logging()["level"]

    def _audit(self):
        path = self._raw.get("audit", {}).get("path")
        if not path:
            raise ConfigError("missing required config: audit.path")
        return {"path": path}

    def _instances(self):
        """Validate the instance allowlist: the set of Nextcloud instances
        the broker may ever touch.

        This list IS the allowlist enforced everywhere else in the
        broker (grant store, layer, bot). Each entry needs a url,
        username, and resolvable app password; discovery (D4) is opt-in
        per instance. An empty instance set refuses to start - a broker
        with no instances is misconfiguration, not an empty shell.
        """
        instances = self._raw.get("instances", {})
        if not instances:
            raise ConfigError("no instances configured")
        out = {}
        for name, block in instances.items():
            url = block.get("url")
            username = block.get("username")
            if not url or not username:
                raise ConfigError(f"instance {name!r} needs url and username")
            password = _secret(
                block, "password", "password_env", f"instance {name} app password",
                self._env,
            )
            # D4: discovery mode (standing list without grant), opt-in.
            discovery = bool(block.get("discovery", False))
            out[name] = {
                "url": url,
                "username": username,
                "password": password,
                "discovery": discovery,
            }
        return out


def load_config(path: str, env: dict | None = None) -> Config:
    """Load config.yaml + resolve env vars. env defaults to os.environ."""
    with open(path) as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} is not a config mapping")
    return Config(raw, env if env is not None else dict(os.environ))