"""Tests for the startup posture banner (broker.run.log_startup_posture).

Contract (W2, scrub-safe posture): one log.info banner line at startup
naming instance count, per-instance discovery on/off, the single
approver id, and the bind address — all non-secret (instance names and
the approver already appear in the approval room and the support
bundle). The banner must run through the scrubbed 'broker' logger and
must never precede logging initialization (fail closed if setup_logging
has not run).

Capture uses a handler attached directly to the 'broker' logger — the
same technique as test_logging_setup.py — because setup_logging sets
propagate=False, which makes caplog (root handler) blind to these
records.
"""

import logging

import pytest

from broker.config import Config
from broker.run import log_startup_posture

APPROVER = "@owner:matrix.example.com"
BOT = "@brokerbot:matrix.example.com"


@pytest.fixture()
def capture():
    """Attach a capture handler to the 'broker' logger (propagate is
    False after setup_logging, so caplog at root sees nothing) and
    initialize scrubbed logging — the banner refuses to run before
    setup_logging, by design. Restores prior state afterwards."""

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    from broker.logging_setup import setup_logging

    cap = Capture()
    logger = logging.getLogger("broker")
    saved_handlers = list(logger.handlers)
    saved_filters = list(logger.filters)
    saved_level = logger.level
    logger.removeHandler(cap) if False else None
    setup_logging(level="info", secrets=[])
    logger.addHandler(cap)
    yield cap
    logger.removeHandler(cap)
    logger.handlers = saved_handlers
    logger.filters = saved_filters
    logger.setLevel(saved_level)


def _config(audit_dir, instances=None, bind_host="198.51.100.99"):
    raw = {
        "matrix": {
            "homeserver": "https://matrix.example.com",
            "bot_user": BOT,
            "bot_token": "x" * 40,
            "room_id": "!room:matrix.example.com",
            "approver": APPROVER,
        },
        "agent": {"token": "a" * 40, "transfer_token": "b" * 40},
        "server": {"port": 8765, "bind_host": bind_host},
        "audit": {"path": f"{audit_dir}/audit.log"},
        "instances": instances
        or {
            "personal": {
                "url": "https://nc1.example.com",
                "username": "u1",
                "password": "p" * 30,
                "discovery": False,
            },
            "work": {
                "url": "https://nc2.example.com",
                "username": "u2",
                "password": "q" * 30,
                "discovery": True,
            },
        },
    }
    return Config(raw, env={})


def _banner(capture):
    lines = [
        r.getMessage() for r in capture.records if r.getMessage().startswith("posture:")
    ]
    assert lines, "no posture banner captured"
    return lines


def test_banner_names_count_discovery_approver_bind(capture):
    cfg = _config("/tmp")
    log_startup_posture(cfg)
    banners = _banner(capture)
    assert len(banners) == 1  # ONE banner line
    line = banners[0]
    assert "instances=2" in line
    assert "discovery=work" in line  # only the discovery-on instance
    assert f"approver={APPROVER}" in line
    assert "bind=198.51.100.99:8765" in line
    assert [r.levelname for r in capture.records if r.getMessage().startswith("posture:")] == ["INFO"]


def test_banner_discovery_off_when_no_instance_has_it(capture):
    cfg = _config(
        "/tmp",
        instances={
            "solo": {
                "url": "https://nc1.example.com",
                "username": "u1",
                "password": "p" * 30,
            },
        },
    )
    log_startup_posture(cfg)
    line = _banner(capture)[0]
    assert "instances=1" in line
    assert "discovery=off" in line


def test_banner_bind_falls_back_to_wildcard_string(capture):
    """bind_host None (container default: all interfaces, exposure is
    the host's decision) shows as 0.0.0.0 in the banner."""
    cfg = _config("/tmp", bind_host=None)
    log_startup_posture(cfg)
    assert "bind=0.0.0.0:8765" in _banner(capture)[0]


def test_banner_refuses_to_log_before_logging_setup(capture):
    """Fail closed: without setup_logging there is no scrub filter, so
    the banner must raise rather than log unscrubbed. The capture
    handler attached above is NOT a SecretScrubFilter — the guard
    specifically requires logging to have been initialized."""
    logger = logging.getLogger("broker")
    saved_handlers = list(logger.handlers)
    saved_filters = list(logger.filters)
    logger.handlers = []
    logger.filters = []
    try:
        with pytest.raises(RuntimeError, match="logging not initialized"):
            log_startup_posture(_config("/tmp"))
        assert capture.records == []  # nothing was logged unscrubbed
    finally:
        logger.handlers = saved_handlers
        logger.filters = saved_filters


def test_banner_goes_through_scrub_filter(tmp_path, capture):
    """End-to-end W2 contract: with setup_logging configured, a secret
    value colliding with the banner is scrubbed from the rendered line
    (the filter is value-based)."""
    from broker.logging_setup import setup_logging

    secret = "s3cret-app-password-value"
    cfg = _config(tmp_path)
    # collide: put the secret value into the banner's own output (absurd
    # on purpose — proves the filter covers the rendered banner line)
    # banner prints bind=<bind_host>; point it at the secret (absurd on
    # purpose — proves the filter covers the rendered banner line)
    cfg.server = dict(cfg.server, bind_host=secret)
    setup_logging(level="info", secrets=[secret])  # replaces the filter
    log_startup_posture(cfg)
    line = _banner(capture)[0]
    assert secret not in line
    assert "[redacted]" in line


def test_banner_wire_components_calls_it(monkeypatch, tmp_path):
    """wire_components emits the banner right after setup_logging, so
    a production start always logs posture before anything else runs."""
    import broker.run as run_mod

    called = []
    monkeypatch.setattr(run_mod, "log_startup_posture", lambda c: called.append(c))

    cfg = _config(tmp_path)

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("wiring continued past the banner")

    for name in (
        "AuditLog",
        "GrantStore",
        "WebDavAdapter",
        "NextcloudClient",
        "NextcloudLayer",
        "NioTransport",
        "ApprovalBot",
        "BrokerServer",
    ):
        monkeypatch.setattr(run_mod, name, _Boom)
    with pytest.raises(AssertionError, match="wiring continued"):
        run_mod.wire_components(cfg)
    assert called == [cfg]  # banner logged first, with the config
