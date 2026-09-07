# Contributing

This project is a security component, and its development discipline
reflects that. The rules below are not bureaucracy; each one exists
because something went wrong without it.

## Ground rules

1. **Test-first, always.** Failing test, minimal fix, green suite.
   The suite is the gate: `.venv/bin/pytest` (264 tests) and
   `.venv/bin/ruff check` must pass before any commit.
2. **The wall is sacred.** `broker/paths.py` is the single enforcement
   function. Changes to it require a new attack battery in
   `review/attack_battery.py` proving the change holds, plus coverage
   at 100% statements and branches. No exceptions, no "small fix".
3. **Never mock the wall.** Tests may fake transports (WebDAV, Matrix)
   but never the path checker or the grant store semantics. A mocked
   wall has historically hidden real bugs (see the adapter's history).
   The approval gateway is a transport like any other; only its
   interface is fixed, not its implementation.
4. **Deviations are logged, not argued.** Design changes are recorded
   in the maintainer's deviation log with rationale and status, and
   are approved by the maintainer before implementation. Approved
   deviations are not findings; unapproved deviations are reverts.
5. **Evidence over claims.** Every gate report quotes tool output:
   test counts, audit-log entries, transcripts. "It works" is not
   evidence; the command and its output are.

## The review convention

Security-relevant PRs get an adversarial review: the reviewer's job is
to construct inputs the tests miss, not to confirm what the tests
cover. Fresh attacks belong in `review/` as runnable scripts, so the
next reviewer inherits them.

## Commit style

`area: what changed` — e.g. `grants: fix restart-discard order`.
Reference the finding or deviation when one exists.

## Reporting security issues

See SECURITY.md. Do not open public issues for exploitable findings.