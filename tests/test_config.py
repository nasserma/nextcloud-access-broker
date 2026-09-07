"""Tests for configuration loading (config.py).

Covers the validation rules: required fields, env resolution, 0.0.0.0
refusal, room/user id shapes, approver != bot, agent token length,
instance completeness, corporate-absent-by-default.
"""

import pytest

from broker.config import Config, ConfigError, load_config

ENV = {
    "BROKER_MATRIX_TOKEN": "x" * 40,
    "BROKER_AGENT_TOKEN": "y" * 40,
    "BROKER_TRANSFER_TOKEN": "t" * 40,
    "NC_TOKEN_PERSONAL": "z" * 20,
}


def base_raw():
    return {
        "matrix": {
            "homeserver": "https://matrix.example.com",
            "bot_user": "@broker:matrix.example.com",
            "room_id": "!abc123:matrix.example.com",
            "approver": "@owner:matrix.example.com",
        },
        "agent": {"token_env": "BROKER_AGENT_TOKEN"},
        "server": {"port": 8765},
        "audit": {"path": "/data/audit/audit.log"},
        "instances": {
            "personal": {
                "url": "https://cloud.example.com",
                "username": "user1",
                "password_env": "NC_TOKEN_PERSONAL",
            }
        },
    }


def make(raw=None, env=None):
    return Config(raw or base_raw(), env if env is not None else ENV)


def test_valid_config_loads():
    c = make()
    assert c.matrix["room_id"] == "!abc123:matrix.example.com"
    assert c.matrix["approver"] == "@owner:matrix.example.com"
    assert c.agent["token"] == "y" * 40
    assert c.instances["personal"]["password"] == "z" * 20
    assert "corporate" not in c.instances


def test_missing_matrix_field_rejected():
    raw = base_raw()
    del raw["matrix"]["room_id"]
    with pytest.raises(ConfigError, match="room_id"):
        make(raw)


def test_wildcard_bind_host_refused():
    raw = base_raw()
    raw["server"]["bind_host"] = "0.0.0.0"
    with pytest.raises(ConfigError, match="wildcard"):
        make(raw)


def test_explicit_bind_host_allowed():
    raw = base_raw()
    raw["server"]["bind_host"] = "10.64.0.1"
    c = make(raw)
    assert c.server["bind_host"] == "10.64.0.1"


def test_bind_host_absent_means_localhost_default():
    c = make()
    assert c.server["bind_host"] is None


def test_bad_room_id_rejected():
    raw = base_raw()
    raw["matrix"]["room_id"] = "not-a-room-id"
    with pytest.raises(ConfigError, match="room"):
        make(raw)


def test_bad_user_id_rejected():
    raw = base_raw()
    raw["matrix"]["approver"] = "user1"
    with pytest.raises(ConfigError, match="approver"):
        make(raw)


def test_approver_same_as_bot_rejected():
    raw = base_raw()
    raw["matrix"]["approver"] = "@broker:matrix.example.com"
    with pytest.raises(ConfigError, match="differ"):
        make(raw)


def test_missing_env_token_rejected(monkeypatch):
    """Test isolation: _secret falls back to os.environ, so the live
    process env (which HAS BROKER_AGENT_TOKEN on this machine) must be
    scrubbed for the absent-env case to be tested at all."""
    monkeypatch.delenv("BROKER_AGENT_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="BROKER_AGENT_TOKEN"):
        make(env={k: v for k, v in ENV.items() if k != "BROKER_AGENT_TOKEN"})


def test_short_agent_token_rejected():
    env = dict(ENV)
    env["BROKER_AGENT_TOKEN"] = "short"
    with pytest.raises(ConfigError, match="32"):
        make(env=env)


def test_missing_instance_password_env_rejected():
    with pytest.raises(ConfigError, match="NC_TOKEN_PERSONAL"):
        make(env={k: v for k, v in ENV.items() if k != "NC_TOKEN_PERSONAL"})


def test_incomplete_instance_block_rejected():
    raw = base_raw()
    raw["instances"]["broken"] = {"url": "https://x"}
    with pytest.raises(ConfigError, match="broken"):
        make(raw)


def test_no_instances_rejected():
    raw = base_raw()
    raw["instances"] = {}
    with pytest.raises(ConfigError, match="no instances"):
        make(raw)


def test_bad_port_rejected():
    raw = base_raw()
    raw["server"]["port"] = "notaport"
    with pytest.raises(ConfigError, match="port"):
        make(raw)


def test_env_resolution_prefers_explicit_env_over_os_environ(monkeypatch):
    monkeypatch.setenv("BROKER_AGENT_TOKEN", "from-os-environ" + "0" * 20)
    c = make(env=ENV)  # explicit env wins
    assert c.agent["token"] == "y" * 40


def test_missing_audit_path_rejected():
    raw = base_raw()
    del raw["audit"]["path"]
    with pytest.raises(ConfigError, match="audit.path"):
        make(raw)


def test_lifecycle_defaults_applied():
    c = make()
    assert c.lifecycle["pending_timeout_hours"] == 12
    assert c.lifecycle["default_grant_hours"] == 24


def test_lifecycle_bad_values_rejected():
    raw = base_raw()
    raw["lifecycle"] = {"pending_timeout_hours": -1}
    with pytest.raises(ConfigError, match="positive"):
        make(raw)


def test_load_config_from_file(tmp_path):
    import yaml as _yaml

    raw = base_raw()
    p = tmp_path / "config.yaml"
    p.write_text(_yaml.dump(raw))
    c = load_config(str(p), env=ENV)
    assert c.server["port"] == 8765


def test_load_config_non_mapping_rejected(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(str(p), env=ENV)

def test_empty_env_name_rejected(monkeypatch):
    """No direct token, no named env, and the default env var absent:
    rejected with a clear message."""
    raw = base_raw()
    raw["agent"]["token_env"] = ""
    env = {k: v for k, v in ENV.items() if k != "BROKER_AGENT_TOKEN"}
    monkeypatch.delenv("BROKER_AGENT_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="agent token"):
        make(raw, env=env)


def test_bad_bot_user_rejected():
    raw = base_raw()
    raw["matrix"]["bot_user"] = "broker"
    with pytest.raises(ConfigError, match="bot_user"):
        make(raw)


def test_bad_default_grant_hours_rejected():
    raw = base_raw()
    raw["lifecycle"] = {"default_grant_hours": 0}
    with pytest.raises(ConfigError, match="default_grant_hours"):
        make(raw)


# ------------------------------------------------- D5: transfer token (Phase 1)

def _env_with_transfer(transfer="t" * 40, agent="y" * 40):
    env = dict(ENV)
    env["BROKER_AGENT_TOKEN"] = agent
    if transfer is not None:
        env["BROKER_TRANSFER_TOKEN"] = transfer
    else:
        env.pop("BROKER_TRANSFER_TOKEN", None)
    return env


def test_transfer_token_resolved_from_env():
    c = make(env=_env_with_transfer(transfer="t" * 40))
    assert c.agent["transfer_token"] == "t" * 40


def test_transfer_token_direct_value_wins():
    raw = base_raw()
    raw["agent"]["transfer_token"] = "d" * 40
    c = make(raw, env=_env_with_transfer(transfer="t" * 40))
    assert c.agent["transfer_token"] == "d" * 40


def test_missing_transfer_token_rejected(monkeypatch):
    monkeypatch.delenv("BROKER_TRANSFER_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="transfer"):
        make(env=_env_with_transfer(transfer=None))


def test_short_transfer_token_rejected():
    with pytest.raises(ConfigError, match="32"):
        make(env=_env_with_transfer(transfer="short"))


def test_transfer_token_equal_to_agent_token_rejected():
    same = "y" * 40
    with pytest.raises(ConfigError, match="differ|equal|distinct"):
        make(env=_env_with_transfer(transfer=same, agent=same))


def test_transfer_token_env_indirection():
    raw = base_raw()
    raw["agent"]["transfer_token_env"] = "MY_TRANSFER"
    env = _env_with_transfer(transfer=None)
    env["MY_TRANSFER"] = "q" * 40
    c = make(raw, env=env)
    assert c.agent["transfer_token"] == "q" * 40
