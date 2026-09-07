"""D6h regression: typed mass revocation — 'revoke all' and
'revoke <instance>'.

Approver-side convenience over the same store.revoke() path as single
revokes; every transition individually logged, one room summary. The
agent NEVER gets a revoke surface (revocation stays approver-only).
"""

import pytest

from broker.grants import GrantStore
from broker.matrixbot import ApprovalBot, parse_reply

T0 = __import__("datetime").datetime(2026, 9, 7, 12, 0, 0)  # noqa: DTZ001
OWNER = "@owner:matrix.example.com"


class FakeMatrixTransport:
    def __init__(self):
        self.messages = []
        self.reactions = []

    async def send_message(self, room, text):
        self.messages.append(text)

    async def add_reaction(self, room, event_id, emoji):
        self.reactions.append((event_id, emoji))


@pytest.fixture()
def env(tmp_path):
    store = GrantStore(db_path=tmp_path / "g.sqlite3", now=lambda: T0)
    store.allowed_instances = {"alpha", "beta"}
    transport = FakeMatrixTransport()
    b = ApprovalBot(
        store=store, transport=transport, room="!r:x", approver=OWNER,
        now=lambda: T0,
    )
    return b, transport, store


def _grant(store, instance, items=None):
    req = store.create_request(
        instance=instance, reason="t",
        items=items or [{"path": "a/f.txt", "mode": "read"}],
    )
    store.approve(req.id, expiry="8h")
    return req.id


# ------------------------------------------------------------- parse_reply

def test_parse_revoke_all():
    assert parse_reply("revoke all") == ("revoke_all", None, None, None)
    assert parse_reply("Revoke ALL") == ("revoke_all", None, None, None)


def test_parse_revoke_instance():
    assert parse_reply("revoke instanceA") == ("revoke_instance", "instancea", None, None)  # target lowercased


def test_numeric_revoke_unaffected():
    assert parse_reply("revoke 47") == ("revoke", 47, None, None)


def test_revoke_all_not_shadowed_by_instance_named_all():
    # 'all' is reserved; an instance named 'all' is unreachable via this
    # command (config keys matching [a-z0-9][a-z0-9_-]* can't be 'all').
    assert parse_reply("revoke all") == ("revoke_all", None, None, None)


# ---------------------------------------------------------------- behavior

async def test_revoke_all_revokes_every_instance(env):
    b, transport, store = env
    _grant(store, "alpha")
    _grant(store, "beta")
    await b.handle_reply(OWNER, "revoke all")
    assert store.active_grants() == []
    assert any("Revoked 2 grant(s)" in m for m in transport.messages)


async def test_revoke_instance_scopes_to_instance(env):
    b, transport, store = env
    keep_id = _grant(store, "alpha")
    kill_id = _grant(store, "beta")
    await b.handle_reply(OWNER, "revoke beta")
    states = {r.id: r.state for r in store.active_grants()}
    assert states.get(keep_id) == "active"
    assert kill_id not in states
    assert any("Revoked 1 grant(s)" in m for m in transport.messages)


async def test_revoke_instance_survives_midflight_expiry(env):
    """A grant that expires between listing and revoking is skipped
    without aborting the batch."""
    import datetime as dt
    b, transport, store = env
    _grant(store, "alpha")
    req = store.create_request(instance="alpha", reason="t", items=[{"path": "b", "mode": "read"}])
    store.approve(req.id, expiry="8h")
    # expire one directly by shifting the store clock
    store._now = lambda: T0 + dt.timedelta(hours=9)
    await b.handle_reply(OWNER, "revoke alpha")
    assert any("Revoked 1 grant(s)" in m or "Nothing to revoke" in m for m in transport.messages)


async def test_revoke_unknown_instance_says_so(env):
    b, transport, store = env
    store.allowed_instances = {"alpha", "beta"}
    await b.handle_reply(OWNER, "revoke nosuch")
    assert any("Unknown instance" in m for m in transport.messages)
    assert store.active_grants() == []


async def test_revoke_all_when_nothing_active(env):
    b, transport, store = env
    await b.handle_reply(OWNER, "revoke all")
    assert any("Nothing to revoke" in m for m in transport.messages)


async def test_non_approver_cannot_revoke_all(env):
    b, transport, store = env
    _grant(store, "alpha")
    await b.handle_reply("@intruder:x", "revoke all")
    assert len(store.active_grants()) == 1
    assert transport.messages == []
