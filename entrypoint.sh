#!/bin/sh
# Container entrypoint: fail fast on the ONE data-dir failure mode the
# runbook documents (cutoverRunbook.md step 2), then exec the broker.
#
# The image creates /data owned by uid 1000 (user 'broker'), but a host
# bind-mount (./data) silently overrides that ownership. If the mount
# is not writable by uid 1000, the broker's first write (audit log /
# grants.sqlite3) dies with a raw PermissionError traceback that names
# neither the uid mismatch nor the fix. This check turns that crash
# into an operator-facing message instead.
#
# Stat-based, no sudo, runs as whatever USER the image sets (uid 1000).

set -eu

DATA_DIR="${BROKER_DATA_DIR:-/data}"

# Refuse to guess: the dir must exist (the image creates it; a missing
# dir means the bind-mount replaced /data's parent — abort, don't mkdir).
if [ ! -d "$DATA_DIR" ]; then
    echo "entrypoint: $DATA_DIR does not exist in the container." >&2
    echo "A bind-mount or volume replaced it; the broker needs /data to exist and be writable by uid 1000." >&2
    exit 1
fi

# Writability check AS THE CURRENT USER (uid 1000 in production) —
# no sudo inside the container; the number is what matters.
if [ ! -w "$DATA_DIR" ]; then
    mounted_uid="$(stat -c '%u' "$DATA_DIR" 2>/dev/null || echo '?')"
    my_uid="$(id -u)"
    echo "entrypoint: $DATA_DIR is NOT writable by uid $my_uid." >&2
    echo "The host bind-mount owns it as uid $mounted_uid; the broker runs as uid $my_uid (container user 'broker')." >&2
    echo "Fix on the HOST (runbook: docs/cutoverRunbook.md step 2):" >&2
    echo "    sudo chown 1000:1000 data" >&2
    echo "Refusing to start without a writable data dir (fail closed: the audit trail must be writable)." >&2
    exit 1
fi

exec python -m broker.run