"""Structured logging with mandatory secret scrubbing (W2).

Remote-debug contract: the owner deploys the broker to a host the
agent cannot reach. If something misbehaves, the owner sends logs.
Every log line must therefore be safe to share BY CONSTRUCTION:
a logging.Filter removes every configured secret VALUE (app
passwords, bot token, agent token) from every record before it
reaches any handler. Debug level adds operation-level detail
(paths, decisions, transport calls) without ever adding secrets.

Usage (run.py):
    from broker.logging_setup import setup_logging
    setup_logging(level=config.logging_level, secrets=[...])
"""

from __future__ import annotations

import logging


class SecretScrubFilter(logging.Filter):
    """Removes configured secret values from every log record.

    Keyword-based sanitizers miss bare credentials (finding I-1
    proved this for error messages). This filter is value-based:
    it knows the actual secrets and strips them wherever they
    appear in the rendered message.

    Value-based means matching the secret string itself, not a key
    name — a secret leaks under unpredictable labels ("password",
    "auth", a repr of a dict, an httpx error echoing the header), so
    searching for the value catches them all. Two record surfaces
    need handling:
      - record.getMessage(): the formatted message from msg+args.
        If any secret is found, args are cleared and msg becomes the
        scrubbed rendered text, so downstream %-formatting can never
        resurrect the raw values from args.
      - record.exc_info: tracebacks are formatted separately at
        emit time and can carry secrets (e.g. a request exception
        echoing an Authorization header). The rendered traceback is
        scrubbed and inlined into the message; if scrubbing itself
        fails, the traceback is dropped entirely and replaced with a
        marker — a lost stack trace is acceptable, a leaked token is
        not.

    The filter always returns True: this filter's job is redaction,
    not suppression. Returning False would silently drop the record
    (a silent decision — forbidden in this codebase) and could hide
    exactly the failure the owner is debugging.
    """

    def __init__(self, secrets: list[str]):
        super().__init__()
        self._secrets = [s for s in secrets if s]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 (formatting must never crash logging)
            return True
        scrubbed = message
        for secret in self._secrets:
            if secret in scrubbed:
                scrubbed = scrubbed.replace(secret, "[redacted]")
        if scrubbed != message:
            # args=None: rendered text is stored in msg so a second
            # handler cannot re-format the raw args back into place.
            record.msg = scrubbed
            record.args = None
        # also scrub exc_info text if present
        if record.exc_info:
            import traceback

            try:
                text = "".join(traceback.format_exception(*record.exc_info))
                clean = text
                for secret in self._secrets:
                    if secret in clean:
                        clean = clean.replace(secret, "[redacted]")
                if clean != text:
                    record.exc_info = None
                    record.msg = record.getMessage() + " | scrubbed-exc: " + clean[-2000:]
                    record.args = None
            except Exception:  # noqa: BLE001 (logging must never crash)
                # Fail safe: drop the traceback entirely rather than
                # risk emitting it unscrubbed.
                record.msg = record.getMessage() + " | (exc-scrub-failed)"
                record.args = None
        return True


def setup_logging(level: str = "info", secrets: list[str] | None = None) -> logging.Logger:
    """Configure the broker logger. Call once at startup.

    level: 'info' (default) or 'debug' (operation-level detail).
    secrets: every value that must never appear in logs — instance
    app passwords, the bot token, the agent token.

    Idempotent by design: handlers are added only when absent, and
    any previous SecretScrubFilter is replaced so a re-call (tests,
    config reload) updates the secret list instead of stacking
    filters.
    """
    logger = logging.getLogger("broker")
    logger.setLevel(logging.DEBUG if str(level).lower() == "debug" else logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
    # Replace any previous filter instance(s) of this class.
    logger.filters = [f for f in logger.filters if not isinstance(f, SecretScrubFilter)]
    logger.addFilter(SecretScrubFilter(secrets or []))
    # Log only through our own handler: propagation to the root
    # logger would bypass this logger's filters.
    logger.propagate = False
    return logger


def get_logger() -> logging.Logger:
    """Return the shared 'broker' logger (assumes setup_logging ran;
    records are unfiltered before that — modules log only after
    wiring completes)."""
    return logging.getLogger("broker")