"""Test battery for the path checker (the wall).

Every behavior in the design document section 3.6 plus the traversal,
encoding, and sibling-prefix attack battery. The path checker is the
single enforcement function for all file operations; mocking it in any
test, here or elsewhere, is forbidden.

The contract under test (broker.paths):

    check_access(requested_path, mode, grants, now) -> Decision

- requested_path: string path relative to the Nextcloud instance root,
  e.g. "Documents/paper/draft.tex"
- mode: "read" or "write"
- grants: iterable of broker.paths.Grant(path, mode, expires_at)
- now: datetime for expiry checks (injected, never real time)

Decision is a NamedTuple with fields: allowed (bool), grant_id (or None),
reason (str, human-readable, populated on denial).
"""

from datetime import datetime, timedelta

import pytest

from broker.paths import Grant, check_access

NOW = datetime(2026, 9, 4, 12, 0, 0, tzinfo=None)  # noqa: DTZ001 (naive on purpose: injected clock)


def grant(path, mode, hours=24, gid=1):
    return Grant(path=path, mode=mode, expires_at=NOW + timedelta(hours=hours), id=gid)


# ---------------------------------------------------------------- basics


def test_plain_file_inside_granted_folder_allowed():
    d = check_access("Documents/paper/draft.tex", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed
    assert d.grant_id == 1


def test_granted_file_directly():
    d = check_access("Documents/paper/draft.tex", "read", [grant("Documents/paper/draft.tex", "read")], NOW)
    assert d.allowed


def test_file_outside_all_grants_denied():
    d = check_access("Photos/secret.jpg", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed
    assert d.grant_id is None
    assert d.reason


def test_empty_grant_list_denies_everything():
    d = check_access("anything", "read", [], NOW)
    assert not d.allowed


def test_no_grants_at_all_is_the_default_closed_state():
    """The broker starts from zero capability: nothing is allowed by default."""
    for mode in ("read", "write"):
        d = check_access("Documents", mode, [], NOW)
        assert not d.allowed


# ------------------------------------------------- sibling prefix attacks


def test_sibling_folder_with_shared_prefix_denied():
    d = check_access("Documents/papers/notes.md", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_prefix_is_componentwise_not_substring():
    """/paper must not match /papers, /paperwork, or /paper.zip."""
    for victim in ("Documents/papers/notes.md", "Documents/paperwork/x", "Documents/paper.zip"):
        d = check_access(victim, "read", [grant("Documents/paper", "read")], NOW)
        assert not d.allowed, victim


def test_exact_folder_path_itself_is_allowed():
    d = check_access("Documents/paper", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


# ------------------------------------------------------- traversal battery


@pytest.mark.parametrize(
    "attack",
    [
        "Documents/paper/../paper/draft.tex",  # traversal resolving INSIDE the grant
        "Documents/./../Documents/paper/draft.tex",
    ],
)
def test_dotdot_traversal_resolving_inside_grant_allowed(attack):
    """Traversal that fully resolves inside the grant is the same path."""
    g = grant("Documents/paper", "read")
    d = check_access(attack, "read", [g], NOW)
    assert d.allowed, attack


@pytest.mark.parametrize(
    "attack",
    [
        "Documents/paper/../../paper/draft.tex",  # pops past Documents -> root-relative
        "../Documents/paper/draft.tex",  # leading .. escapes the root
        "a/../../Documents/paper/draft.tex",  # pops past root
        "Documents/paper/../../../etc/passwd",
        "Documents/../../secret.txt",
    ],
)
def test_dotdot_traversal_escaping_root_denied(attack):
    """Any .. that pops past the instance root fails closed, even when the
    remaining components would spell a path inside a grant. Root escapes
    are never reinterpreted as instance-relative paths."""
    g = grant("Documents/paper", "read")
    d = check_access(attack, "read", [g], NOW)
    assert not d.allowed, attack


def test_traversal_escape_to_root_denied():
    d = check_access("../../../etc/passwd", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_absolute_path_injection_denied_outside_scope():
    """A path claiming to be absolute is treated as instance-relative and must
    still be scope-checked; '/etc/passwd' resolves nowhere near any grant."""
    d = check_access("/etc/passwd", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_doubled_slashes_normalized():
    d = check_access("Documents//paper///draft.tex", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


def test_dot_segments_normalized():
    d = check_access("Documents/./paper/./draft.tex", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


def test_trailing_slash_on_folder_grant_and_request():
    d = check_access("Documents/paper/", "read", [grant("Documents/paper/", "read")], NOW)
    assert d.allowed
    d2 = check_access("Documents/paper/", "read", [grant("Documents/paper", "read")], NOW)
    assert d2.allowed


# ----------------------------------------------------- encoding attacks


def test_percent_encoded_separator_is_decoded_before_matching():
    """%2F is a path separator once decoded; a grant on Documents/paper must
    allow Documents%2Fpaper%2Fdraft.tex (it is the same path), and an
    encoded escape must not smuggle past the checker."""
    d = check_access("Documents%2Fpaper%2Fdraft.tex", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


def test_percent_encoded_traversal_escape_denied():
    d = check_access("Documents/paper%2F..%2F..%2Fsecret.txt", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_double_percent_encoding_is_not_a_bypass():
    """%252F decodes once to %2F; the checker must not allow it to bypass
    normalization, and must still resolve the path correctly after decoding."""
    d = check_access("Documents%252F..%252Fsecret.txt", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_plus_is_not_a_separator():
    d = check_access("Documents+paper", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_unicode_fullwidth_solidus_is_not_a_bypass():
    """U+FF0F FULLWIDTH SOLIDUS looks like / but is a distinct character;
    it must not be treated as a separator that somehow escapes matching,
    and it must not be silently normalized into allowing something else."""
    d = check_access("Documents\uff0fpaper", "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_decode_cap_on_deep_encoding_chain_denies():
    """A recursively percent-encoded '/' at depth 6 needs 6 passes to settle;
    at the 4-pass cap it is still changing, treated as still-encoded,
    matches no grant, denied."""
    deep = "/"
    for _ in range(6):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    path = "Documents" + deep + "paper" + deep + "draft.tex"
    d = check_access(path, "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_decode_of_depth_three_chain_allowed():
    """Depth-3 recursive encoding settles within the cap and resolves to a
    real path inside the grant: encoding depth is not itself a refusal."""
    deep = "/"
    for _ in range(3):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    path = "Documents" + deep + "paper" + deep + "draft.tex"
    d = check_access(path, "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


def test_decode_settling_exactly_at_cap_allowed():
    """Depth-4 chain settles on the final allowed pass (pass 4): allowed.
    The cap must not deny chains that just barely settle in time."""
    deep = "/"
    for _ in range(4):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    path = "Documents" + deep + "paper"
    d = check_access(path, "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


def test_grant_path_over_max_length_grants_nothing():
    """A grant whose own path exceeds the length cap is malformed and
    grants nothing, even if the request matches its prefix."""
    bogus = Grant(path="a" * 3000, mode="read", expires_at=NOW + timedelta(hours=1), id=1)
    d = check_access("a" * 3000, "read", [bogus], NOW)
    assert not d.allowed


def test_grant_with_invalid_mode_grants_nothing():
    bogus = Grant(path="Documents/paper", mode="admin", expires_at=NOW + timedelta(hours=1), id=1)
    d = check_access("Documents/paper/draft.tex", "read", [bogus], NOW)
    assert not d.allowed


def test_grant_with_none_expiry_grants_nothing():
    """A grant with expires_at=None (never parsed / corrupt record) grants
    nothing: fail closed on corrupt state."""
    bogus = Grant(path="Documents/paper", mode="read", expires_at=None, id=1)
    d = check_access("Documents/paper/draft.tex", "read", [bogus], NOW)
    assert not d.allowed


def test_second_expired_grant_keeps_first_denial_reason():
    """Two expired grants covering the path: the first denial reason wins
    (best is not overwritten by subsequent expired grants)."""
    e1 = Grant(path="Documents/paper", mode="read", expires_at=NOW - timedelta(hours=2), id=1)
    e2 = Grant(path="Documents/paper", mode="read", expires_at=NOW - timedelta(hours=1), id=2)
    d = check_access("Documents/paper/draft.tex", "read", [e1, e2], NOW)
    assert not d.allowed
    assert "1" in d.reason


def test_second_readonly_grant_keeps_first_denial_reason():
    """Write requested, two read-only grants covering the path: the first
    read-only reason wins and no shadowing occurs."""
    r1 = grant("Documents/paper", "read", gid=1)
    r2 = grant("Documents/paper", "read", gid=2)
    d = check_access("Documents/paper/draft.tex", "write", [r1, r2], NOW)
    assert not d.allowed
    assert "read-only" in d.reason
    assert "1" in d.reason


def test_decode_stable_after_two_passes_allowed():
    """Normal double encoding settles within the cap: %252F -> %2F -> / and
    resolves to a real path inside the grant."""
    d = check_access("Documents%252Fpaper%252Fdraft.tex", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


# --------------------------------------------------------- mode and expiry


def test_expired_grant_denied():
    expired = Grant(path="Documents/paper", mode="read", expires_at=NOW - timedelta(seconds=1), id=9)
    d = check_access("Documents/paper/draft.tex", "read", [expired], NOW)
    assert not d.allowed
    assert "expired" in d.reason.lower()


def test_expires_exactly_now_is_expired():
    """Boundary: expires_at == now means expired (fail closed)."""
    g = Grant(path="Documents/paper", mode="read", expires_at=NOW, id=9)
    d = check_access("Documents/paper/draft.tex", "read", [g], NOW)
    assert not d.allowed


def test_read_only_grant_refuses_write():
    d = check_access("Documents/paper/draft.tex", "write", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed
    assert "read" in d.reason.lower() or "write" in d.reason.lower()


def test_write_grant_allows_read():
    """WRITE implies READ within scope (design doc section 3.6 read/write
    semantics; recorded in DEVIATIONS.md as confirmed behavior)."""
    d = check_access("Documents/paper/draft.tex", "read", [grant("Documents/paper", "write")], NOW)
    assert d.allowed


def test_write_grant_allows_write():
    d = check_access("Documents/paper/new.tex", "write", [grant("Documents/paper", "write")], NOW)
    assert d.allowed


def test_multiple_grants_first_match_wins_but_any_match_suffices():
    grants = [grant("Photos", "read", gid=1), grant("Documents/paper", "write", gid=2)]
    d = check_access("Documents/paper/draft.tex", "write", grants, NOW)
    assert d.allowed
    assert d.grant_id == 2


def test_expired_grant_does_not_shadow_live_grant_for_same_path():
    expired = Grant(path="Documents", mode="write", expires_at=NOW - timedelta(hours=1), id=1)
    live = Grant(path="Documents/paper", mode="read", expires_at=NOW + timedelta(hours=1), id=2)
    d = check_access("Documents/paper/draft.tex", "read", [expired, live], NOW)
    assert d.allowed
    assert d.grant_id == 2


def test_new_file_created_inside_granted_area_is_covered():
    """READ/WRITE on a folder covers files created later inside it (recursive)."""
    d = check_access("Documents/paper/figures/generated_later.pdf", "read", [grant("Documents/paper", "read")], NOW)
    assert d.allowed


# ------------------------------------------------------------ malformed input


@pytest.mark.parametrize(
    "bad",
    ["", "   ", None, 123, "Documents/paper/\x00draft.tex"],
)
def test_malformed_paths_fail_closed(bad):
    d = check_access(bad, "read", [grant("Documents/paper", "read")], NOW)
    assert not d.allowed


def test_unknown_mode_fails_closed():
    d = check_access("Documents/paper/draft.tex", "admin", [grant("Documents/paper", "write")], NOW)
    assert not d.allowed


def test_empty_and_whitespace_grant_paths_are_ignored():
    bogus = Grant(path="", mode="read", expires_at=NOW + timedelta(hours=1), id=1)
    d = check_access("anything", "read", [bogus], NOW)
    assert not d.allowed


# ------------------------------------------- property-based fuzz (T1.9)


def test_fuzz_no_random_path_allowed_outside_grant():
    from hypothesis import given, settings
    from hypothesis import strategies as st

    components = st.text(
        alphabet=st.characters(
            codec="utf-8",
            categories=("Lu", "Ll", "Nd", "Pc", "Pd", "Po"),
            exclude_characters="/%",
        ),
        min_size=0,
        max_size=12,
    )
    paths = st.lists(components, min_size=0, max_size=6).map(lambda parts: "/".join(parts))

    @given(paths)
    @settings(max_examples=500, deadline=None)
    def fuzz(p):
        d = check_access(p, "read", [grant("Documents/paper", "read")], NOW)
        if d.allowed:
            # The invariant: allowed implies the normalized path is, byte for
            # byte, inside the granted prefix after normalization.
            normalized = normalize_for_test(p)
            assert normalized == "Documents/paper" or normalized.startswith("Documents/paper/"), (
                f"allowed outside scope: {p!r} -> {normalized!r}"
            )

    fuzz()


def normalize_for_test(p):
    """Test-side mirror of the checker's normalization, used only to verify
    the invariant (the production function is broker.paths.normalize_path)."""
    from broker.paths import normalize_path

    return normalize_path(p)