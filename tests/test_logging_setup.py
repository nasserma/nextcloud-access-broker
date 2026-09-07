"""Tests for the logging facility (W2): level gating and secret scrubbing."""

import logging

import pytest

from broker.logging_setup import setup_logging


@pytest.fixture()
def capture_handler():
    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    cap = Capture()
    logger = logging.getLogger("broker")
    logger.addHandler(cap)
    yield cap
    logger.removeHandler(cap)


def test_secret_scrubbed_from_message(capture_handler):
    SECRET = "sup3r-app-password-99"
    setup_logging(level="info", secrets=[SECRET])
    log = logging.getLogger("broker")
    log.warning("login failed with %s", SECRET)
    text = capture_handler.records[-1].getMessage()
    assert SECRET not in text
    assert "[redacted]" in text


def test_bare_secret_scrubbed_without_keyword(capture_handler):
    SECRET = "Xk9kQmNzVmQw-42"
    setup_logging(secrets=[SECRET])
    log = logging.getLogger("broker")
    log.error(f"upstream echo: {SECRET}")
    assert SECRET not in capture_handler.records[-1].getMessage()


def test_exception_text_scrubbed(capture_handler):
    SECRET = "pw-leak-77"
    setup_logging(secrets=[SECRET])
    log = logging.getLogger("broker")
    try:
        raise RuntimeError(f"boom with {SECRET} inside")
    except RuntimeError:
        log.exception("operation failed")
    record = capture_handler.records[-1]
    blob = record.getMessage()
    assert SECRET not in blob


def test_debug_level_gates_detail(capture_handler):
    setup_logging(level="info", secrets=[])
    log = logging.getLogger("broker")
    log.debug("this is debug detail")
    log.info("this is info")
    levels = [r.levelname for r in capture_handler.records]
    assert "DEBUG" not in levels
    assert "INFO" in levels


def test_debug_mode_shows_debug(capture_handler):
    setup_logging(level="debug", secrets=[])
    log = logging.getLogger("broker")
    log.debug("debug detail visible")
    assert any(r.levelname == "DEBUG" for r in capture_handler.records)


def test_multiple_secrets_all_scrubbed(capture_handler):
    secrets = ["alpha-secret", "beta-secret", "gamma-bot-token"]
    setup_logging(secrets=secrets)
    log = logging.getLogger("broker")
    log.info("mixed alpha-secret and gamma-bot-token and beta-secret")
    text = capture_handler.records[-1].getMessage()
    for s in secrets:
        assert s not in text
    assert text.count("[redacted]") == 3


def test_filter_reconfiguration(capture_handler):
    setup_logging(secrets=["old-secret"])
    setup_logging(secrets=["new-secret"])
    log = logging.getLogger("broker")
    log.warning("old-secret new-secret")
    text = capture_handler.records[-1].getMessage()
    # only the CURRENT secrets are scrubbed; old config cleared
    assert "new-secret" not in text


def test_clean_messages_pass_untouched(capture_handler):
    setup_logging(secrets=["zzz"])
    log = logging.getLogger("broker")
    log.info("normal operational message with paths /a/b/c")
    assert capture_handler.records[-1].getMessage() == (
        "normal operational message with paths /a/b/c"
    )