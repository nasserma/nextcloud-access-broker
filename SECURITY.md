# Security Policy

## What this software is

The Nextcloud Access Broker is a security component. It gates AI-agent
file access to Nextcloud behind per-task, human-approved, time-limited,
path-scoped grants. Approval arrives through one configurable approval
gateway; the current implementation is Matrix. The enforcement core is
a single path-checking function, and the accountability core is an
append-only, hash-chained audit log written before every operation.

## Threat model

**Defends against:**
- An agent (or an agent's compromised process) reading or writing
  files it was never granted, including via path manipulation
  (traversal, encoding tricks, prefix collisions, unicode
  confusables; all fail closed).
- Standing access creep: there is no configuration in which the agent
  holds file-content access without a live, human-approved grant.
- Silent operation: every file operation is audit-logged before it
  executes; a failed log write refuses the operation.
- Credential exposure to the agent: app passwords never leave the
  broker host; error messages are scrubbed of credential values, not
  just keywords.
- Accidental destruction: no permanent-delete capability exists; the
  Nextcloud trashbin namespace is unreachable through the broker.

**Does not defend against (explicit non-goals):**
- A compromised broker host. The broker holds account-wide app
  passwords, so a compromised host exposes everything within those
  accounts. Run it on a storage host you trust, and nothing else.
- A malicious approver. The single allowlisted approver is trusted by
  definition; there is no quorum mode.
- Side channels (file names are visible under discovery mode; timing,
  size, and existence of files are observable within granted scope).
- A compromised Matrix homeserver: forged approvals require the
  approver's account on the homeserver. Self-host your homeserver and
  treat its compromise as broker compromise.

## Verifying your installation

```bash
# the audit log's hash chain (tamper evidence):
.venv/bin/python -c "from broker.audit import verify_chain; \
    print(verify_chain('/path/to/data/audit.log'))"

# the wall's own attack battery (fresh adversarial cases):
.venv/bin/python review/attack_battery.py
```

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the
maintainer directly. Please include a reproduction command; reports
that demonstrate execution are triaged first. The project's own
review convention applies in reverse: every claimed defect needs a
repro, and so does every claimed fix.

Do not open public issues for exploitable findings before
coordination.