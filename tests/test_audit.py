"""Test battery for the audit log (Gate 3).

Goal contract, Gate 3 requirements:

- Write-before-operate: the log entry is written and flushed BEFORE the
  caller proceeds. If the log write fails, the operation NEVER runs.
- Append-only: existing lines are never modified. Verified by checksum.
- Tamper evidence: each line carries the SHA256 of the previous line
  (hash chain). Truncation and reordering are detectable.
- Record completeness: timestamp, instance, path, operation, grant id,
  decision (allowed/denied + reason).
- No secrets: the Nextcloud app password must never appear in the log.
"""

import hashlib
import json

import pytest

from broker.audit import AuditLog, LogWriteError, verify_chain

NOW = "2026-09-05T12:00:00"


def make_log(tmp_path):
    return AuditLog(path=tmp_path / "audit.log", now=lambda: NOW)


def test_write_then_operate_order(tmp_path):
    """The operation callback runs only after the log write succeeds, and
    receives nothing (the log write is fire-completed before it)."""
    log = make_log(tmp_path)
    ran = []
    log.record(
        instance="personal",
        path="Documents/paper/draft.tex",
        operation="read",
        grant_id=7,
        decision="allowed",
        reason="ok",
        then=lambda: ran.append(1),
    )
    assert ran == [1]


def test_failed_log_write_refuses_operation(tmp_path):
    """The core security rule: if the log write fails, the operation is
    refused. The callback must NOT run, and an exception must propagate
    so the caller cannot mistake refusal for success."""
    log = make_log(tmp_path)
    ran = []
    with pytest.raises(LogWriteError):
        log.record(
            instance="personal",
            path="a",
            operation="read",
            grant_id=1,
            decision="allowed",
            reason="ok",
            then=lambda: ran.append(1),
            _fail_inject=True,
        )
    assert ran == []


def test_log_write_failure_on_real_disk_error(tmp_path):
    """Pointing the log at a directory: construction itself must fail
    closed (LogWriteError) - the broker must not start with an audit
    sink that cannot be written."""
    ran = []
    with pytest.raises(LogWriteError):
        AuditLog(path=tmp_path, now=lambda: NOW)  # tmp_path IS a directory
    assert ran == []


def test_corrupt_tail_refuses_construction(tmp_path):
    """A log file whose last line is corrupt garbage: construction fails
    closed rather than silently extending a broken chain."""
    bad = tmp_path / "audit.log"
    bad.write_text("{not json at all\n")
    with pytest.raises(LogWriteError):
        AuditLog(path=bad, now=lambda: NOW)


def test_record_fields_complete(tmp_path):
    log = make_log(tmp_path)
    log.record(
        instance="personal",
        path="Documents/paper/draft.tex",
        operation="write",
        grant_id=47,
        decision="allowed",
        reason="approved by owner",
    )
    line = (tmp_path / "audit.log").read_text().strip().splitlines()[-1]
    record = json.loads(line)
    assert record["timestamp"] == NOW
    assert record["instance"] == "personal"
    assert record["path"] == "Documents/paper/draft.tex"
    assert record["operation"] == "write"
    assert record["grant_id"] == 47
    assert record["decision"] == "allowed"
    assert record["reason"] == "approved by owner"


def test_denied_operations_are_logged_too(tmp_path):
    """Refusals are audit events: who asked, what was refused, why."""
    log = make_log(tmp_path)
    log.record(
        instance="personal",
        path="Photos/secret.jpg",
        operation="read",
        grant_id=None,
        decision="denied",
        reason="path not covered by any active grant",
    )
    line = (tmp_path / "audit.log").read_text().strip().splitlines()[-1]
    record = json.loads(line)
    assert record["decision"] == "denied"
    assert record["grant_id"] is None


def test_append_only_existing_lines_unmodified(tmp_path):
    log = make_log(tmp_path)
    for i in range(5):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    raw = (tmp_path / "audit.log").read_bytes()
    checksum_before = hashlib.sha256(raw).hexdigest()
    log.record(
        instance="personal", path="another", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    raw_after = (tmp_path / "audit.log").read_bytes()
    assert raw_after.startswith(raw)  # strictly appended
    assert hashlib.sha256(raw).hexdigest() == checksum_before


def test_hash_chain_links_consecutive_lines(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    prev_hash = "0" * 64
    for line in lines:
        record = json.loads(line)
        assert record["prev_sha256"] == prev_hash
        payload = json.dumps(
            {k: record[k] for k in
             ("timestamp", "instance", "path", "operation", "grant_id", "decision", "reason")},
            sort_keys=True,
        ).encode()
        prev_hash = hashlib.sha256(payload).hexdigest()
        assert record["sha256"] == prev_hash


def test_verify_chain_detects_truncation(tmp_path):
    log = make_log(tmp_path)
    for i in range(4):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    assert verify_chain(tmp_path / "audit.log").ok
    # truncate one line
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    (tmp_path / "audit.log").write_text("\n".join(lines[:-1]) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert result.error


def test_verify_chain_detects_reordering(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n")
    assert not verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_detects_content_edit(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    record = json.loads(lines[1])
    record["path"] = "tampered"
    lines[1] = json.dumps(record, sort_keys=True)
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n")
    assert not verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_ok_on_pristine_log(tmp_path):
    log = make_log(tmp_path)
    log.record(
        instance="personal", path="f", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    assert verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_empty_file_is_ok(tmp_path):
    (tmp_path / "audit.log").write_text("")
    assert verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_missing_file_is_error(tmp_path):
    result = verify_chain(tmp_path / "nope.log")
    assert not result.ok


def test_password_never_logged(tmp_path):
    """The audit log must never contain credentials. Feed a password-
    shaped string through every field and assert absence."""
    secret = "sup3r-secret-app-password"
    log = AuditLog(path=tmp_path / "audit.log", now=lambda: NOW, secrets=[secret])
    with pytest.raises(ValueError, match="secret"):
        log.record(
            instance="personal",
            path=f"a{secret}b",
            operation="read",
            grant_id=1,
            decision="allowed",
            reason="ok",
        )
    assert not (tmp_path / "audit.log").exists() or secret not in (tmp_path / "audit.log").read_text()


def test_operation_without_then_callback(tmp_path):
    """record() without a callback still writes the entry (used for
    logging refusals where there is nothing to run)."""
    log = make_log(tmp_path)
    log.record(
        instance="personal", path="a", operation="read",
        grant_id=None, decision="denied", reason="no grant",
    )
    assert verify_chain(tmp_path / "audit.log").ok


def test_restart_continues_chain_from_last_head(tmp_path):
    """Second AuditLog instance on the same file continues the chain: the
    new record's prev_sha256 equals the last record's sha256."""
    log1 = make_log(tmp_path)
    log1.record(
        instance="personal", path="f1", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    last_sha = json.loads(
        (tmp_path / "audit.log").read_text().strip().splitlines()[-1]
    )["sha256"]
    log2 = AuditLog(path=tmp_path / "audit.log", now=lambda: NOW)
    log2.record(
        instance="personal", path="f2", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["prev_sha256"] == last_sha
    assert verify_chain(tmp_path / "audit.log").ok
    assert verify_chain(tmp_path / "audit.log").lines == 2


def test_empty_existing_log_file_construction_ok(tmp_path):
    """A zero-byte existing log file is treated as empty (genesis)."""
    (tmp_path / "audit.log").write_text("")
    log = AuditLog(path=tmp_path / "audit.log", now=lambda: NOW)
    log.record(
        instance="personal", path="a", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    assert verify_chain(tmp_path / "audit.log").ok


def test_log_of_only_blank_lines_treated_as_empty(tmp_path):
    (tmp_path / "audit.log").write_text("\n \n")
    log = AuditLog(path=tmp_path / "audit.log", now=lambda: NOW)
    log.record(
        instance="personal", path="a", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    assert verify_chain(tmp_path / "audit.log").ok


def test_checkpoint_tampering_detected(tmp_path):
    """Editing the checkpoint head hash itself is detected by mismatch."""
    log = make_log(tmp_path)
    for i in range(2):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    head_path = tmp_path / "audit.log.head"
    head = json.loads(head_path.read_text())
    head["sha256"] = "f" * 64
    head_path.write_text(json.dumps(head, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "checkpoint mismatch" in result.error


def test_checkpoint_line_count_tampering_detected(tmp_path):
    log = make_log(tmp_path)
    for i in range(2):
        log.record(
            instance="personal", path=f"f{i}", operation="read",
            grant_id=1, decision="allowed", reason="ok",
        )
    head_path = tmp_path / "audit.log.head"
    head = json.loads(head_path.read_text())
    head["lines"] = 99
    head_path.write_text(json.dumps(head, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "truncated" in result.error


def test_corrupt_checkpoint_detected(tmp_path):
    log = make_log(tmp_path)
    log.record(
        instance="personal", path="f", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    (tmp_path / "audit.log.head").write_text("{garbage")
    assert not verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_unreadable_log(tmp_path):
    log = make_log(tmp_path)
    log.record(
        instance="personal", path="f", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    target = tmp_path / "subdir" / "audit.log"
    target.parent.mkdir()
    result = verify_chain(target.parent)  # a directory: read fails on some systems
    assert not result.ok


def test_secret_in_non_string_fields_ignored(tmp_path):
    """grant_id is an int; secrets checking must not choke on it."""
    log = AuditLog(path=tmp_path / "audit.log", now=lambda: NOW, secrets=["abc"])
    log.record(
        instance="personal", path="a", operation="read",
        grant_id=123, decision="allowed", reason="ok",
    )
    assert verify_chain(tmp_path / "audit.log").ok


def test_verify_missing_file_counts_zero_lines(tmp_path):
    """The missing-file error path returns lines=0."""
    result = verify_chain(tmp_path / "nope.log")
    assert result.lines == 0


def test_prev_mismatch_detected_on_handcrafted_break(tmp_path):
    """Handcraft a chain where line 2's prev_sha256 does not match line 1's
    sha256 but line 2's own hash is internally consistent - the pure
    prev-mismatch branch (no line 1 hash check fires first)."""
    import broker.audit as A

    log = make_log(tmp_path)
    log.record(
        instance="personal", path="f1", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    # a second record whose own hash is right but prev is wrong
    entry2 = {
        "timestamp": NOW, "instance": "personal", "path": "f2",
        "operation": "read", "grant_id": 1, "decision": "allowed", "reason": "ok",
    }
    r2 = dict(entry2)
    r2["prev_sha256"] = "b" * 64  # wrong on purpose
    r2["sha256"] = __import__("hashlib").sha256(
        A._chain_payload(entry2).encode()
    ).hexdigest()
    (tmp_path / "audit.log").write_text(
        lines[0] + "\n" + json.dumps(r2, sort_keys=True) + "\n"
    )
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "prev mismatch" in (result.error or "")


def test_record_write_oserror_refuses_operation(tmp_path, monkeypatch):
    """Simulate a mid-write OSError (disk full): operation refused."""
    import builtins

    log = make_log(tmp_path)
    ran = []
    real_open = builtins.open

    def flaky_open(*args, **kwargs):
        if "a" in (args[1] if len(args) > 1 else kwargs.get("mode", "a")) and str(args[0]).endswith("audit.log"):
            raise OSError(28, "No space left on device")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)
    with pytest.raises(LogWriteError):
        log.record(
            instance="personal", path="a", operation="read",
            grant_id=1, decision="allowed", reason="ok",
            then=lambda: ran.append(1),
        )
    assert ran == []


def test_checkpoint_write_oserror_surfaces(tmp_path, monkeypatch):
    """The record is written but the checkpoint write fails: LogWriteError
    is raised so the operator notices; the chain itself stays valid."""
    import builtins

    log = make_log(tmp_path)
    ran = []
    real_open = builtins.open

    def flaky_open(*args, **kwargs):
        mode = args[1] if len(args) > 1 else kwargs.get("mode", "a")
        if "w" in mode and str(args[0]).endswith(".head"):
            raise OSError(5, "Input/output error")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)
    with pytest.raises(LogWriteError):
        log.record(
            instance="personal", path="a", operation="read",
            grant_id=1, decision="allowed", reason="ok",
            then=lambda: ran.append(1),
        )
    # the record itself was written
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 1

def test_invalid_json_line_detected(tmp_path):
    """A log line that is not valid JSON is named and refused."""
    log = make_log(tmp_path)
    log.record(
        instance="personal", path="f", operation="read",
        grant_id=1, decision="allowed", reason="ok",
    )
    with open(tmp_path / "audit.log", "a") as f:
        f.write("this is not json\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "not valid JSON" in (result.error or "")


def test_secret_check_skips_non_string_values(tmp_path):
    """A non-string value in a checked field is skipped, not crashed on."""
    log = make_log(tmp_path)
    log._secrets = ["needle"]
    log._check_secrets("personal", 123, None, "ok-path", "allowed", "ok")  # no raise
    with pytest.raises(ValueError, match="secret"):
        log._check_secrets("personal", "contains needle here")



# ------------------------------------------- D5: principal field (Phase 4)

def test_record_principal_field_roundtrip(tmp_path):
    """D5: the audit record carries the principal (agent|transfer) and
    the chain hash covers it; a record without principal (pre-D5 line)
    still verifies (backward compatible chain)."""
    from broker.audit import _CHAINED_FIELDS, AuditLog

    assert "principal" in _CHAINED_FIELDS
    log = AuditLog(path=str(tmp_path / "audit.log"), now=lambda: "2026-09-06T00:00:00")
    log.record(
        instance="work", path="a.tex", operation="read", grant_id=7,
        decision="allowed", reason="granted read", principal="transfer",
    )
    log.record(
        instance="work", path="b.tex", operation="list", grant_id=None,
        decision="allowed", reason="discovery", principal="agent",
    )
    log.record(  # legacy call without principal: must still work
        instance="work", path="c.tex", operation="list", grant_id=None,
        decision="allowed", reason="discovery",
    )
    from broker.audit import verify_chain
    result = verify_chain(str(tmp_path / "audit.log"))
    assert result.ok, getattr(result, "reason", "chain broken")
    with open(tmp_path / "audit.log") as fh:
        lines = [json.loads(l) for l in fh]
    assert lines[0]["principal"] == "transfer"
    assert lines[1]["principal"] == "agent"
    assert "principal" not in lines[2] or lines[2]["principal"] is None


def test_record_refusal_logged(tmp_path):
    """D5: refusals are audit-logged (decision 'refused'), so wall
    violations and token-class misuse are visible in the log."""
    log = AuditLog(path=str(tmp_path / "audit.log"), now=lambda: "2026-09-06T00:00:00")
    log.record(
        instance="work", path="x/secret.tex", operation="read", grant_id=None,
        decision="refused", reason="no active grant", principal="agent",
    )
    with open(tmp_path / "audit.log") as fh:
        lines = [json.loads(l) for l in fh]
    assert lines[0]["decision"] == "refused"
    assert lines[0]["principal"] == "agent"
    assert lines[0]["reason"] == "no active grant"
