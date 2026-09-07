"""R1 attack battery: the wall, attacked with cases NOT in tests/.

Review contract rule 3: no attacks copied from the existing test
battery. Every case documents the expected verdict and the rationale;
a case 'passing' means the wall behaved as it must (deny unless
proven inside scope). A surprise is a finding.

Run: .venv/bin/python review/attack_battery.py
Exit 0 = all cases behaved as expected. Exit 1 = findings exist.
"""

import sys
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.paths import Grant, check_access

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
GRANT_PATH = "Documents/paper"
EXPECT_DENIED = []
SURPRISES = []


def grant(path=GRANT_PATH, mode="read"):
    return Grant(path=path, mode=mode, expires_at=NOW + timedelta(hours=8), id=1)


def attack(name, path, mode="read", should_allow=False, g=None):
    """Attempt (mode, path). should_allow=False means the wall MUST deny.
    Any mismatch is a SURPRISE (finding)."""
    decision = check_access(path, mode, [g or grant()], NOW)
    got_allow = decision.allowed
    if got_allow != should_allow:
        SURPRISES.append(
            f"{name}: expected {'ALLOW' if should_allow else 'DENY'}, "
            f"got {'ALLOW' if got_allow else 'DENY'} ({decision.reason}) | path={path!r}"
        )
        print(f"  [!!] {name}: {path!r} -> {decision.allowed} ({decision.reason})")
    else:
        print(f"  [ok] {name}")


print("=== R1 attack battery: fresh cases against the wall ===")

# --- Section A: unicode normalization attacks (NOT in tests/) ---------

# A1: NFC vs NFD composed/decomposed equivalents of a granted path.
# 'é' as NFC (single codepoint) vs NFD (e + combining acute).
nfc_doc = "Docume" + "nts/papér"
nfd_doc = unicodedata.normalize("NFD", nfc_doc)
attack("A1 nfc vs nfd mismatch must deny", nfd_doc)
# and granting the NFD form must NOT admit the NFC form (and vice versa)
g_nfd = Grant(path=nfd_doc, mode="read", expires_at=NOW + timedelta(hours=8), id=1)
attack("A1b nfc against nfd grant must deny", nfc_doc, g=g_nfd)

# A2: Turkish dotless i / capital İ confusable in a granted prefix
attack("A2 turkish-i confusable", "Documents/papİr/draft.tex")

# A3: homoglyph Cyrillic 'а' (U+0430) inside granted-looking path
cyr = "Documents/pаper/draft.tex"  # second 'a' is Cyrillic
assert cyr != "Documents/paper/draft.tex"
attack("A3 cyrillic homoglyph", cyr)

# --- Section B: separator lookalikes (new variants) ---------------------

# B1: backslash separators (Windows-style smuggling) outside the guard
attack("B1 backslash traversal", "Documents\\..\\..\\secret")
# B1b: backslash normalization (wall step 4: '\' -> '/'). After
# normalization 'Documents\paper' IS 'Documents/paper', i.e. inside the
# grant, so ALLOW is the documented, correct verdict. The original
# expectation (DENY) was stale: it predated the normalization contract
# and contradicted the wall. Note the backslash does not buy escape
# scope (see B1) and the normalization is applied uniformly - an
# attacker gains nothing by swapping separators.
attack("B1b backslash path inside grant", "Documents\\paper", should_allow=True)

# B2: S3-style ':' separator
attack("B2 colon separator", "Documents:paper")

# B3: overlong UTF-8 encoding of '/' (C0 AF) - invalid UTF-8 sequence
attack("B3 overlong utf8 slash", "Documents\xC0\xAFpaper", should_allow=False)

# B4: NUL inside a granted-looking prefix (control char must fail)
attack("B4 embedded nul", "Documents/pap\0er/draft.tex", should_allow=False)

# B5: fullwidth solidus (U+FF0F) already tested; try REVERSE solidus
attack("B5 reverse solidus", "Documents﹨paper")

# --- Section C: grant-path edge cases (new) ------------------------------

# C1: trailing-dot folder names (Windows quirk: 'paper.' == 'paper')
g_dot = Grant(path="Documents/paper", mode="read", expires_at=NOW + timedelta(hours=8), id=1)
attack("C1 trailing-dot folder", "Documents/paper./draft.tex", g=g_dot)
attack("C1b trailing-space folder", "Documents/paper /draft.tex", g=g_dot)

# C2: grant ON a trailing-dot path must not admit the clean path
g_dotgrant = Grant(path="Documents/paper.", mode="read", expires_at=NOW + timedelta(hours=8), id=1)
attack("C2 dot-grant admits clean path?", "Documents/paper/draft.tex", g=g_dotgrant)

# C3: 8.3 short-name style (DOCUME~1) - must not prefix-match
attack("C3 8.3 short name", "DOCUME~1/paper/draft.tex")

# C4: grant with mode uppercase 'READ' (invalid mode on grant) must grant nothing
g_upper = Grant(path="Documents/paper", mode="READ", expires_at=NOW + timedelta(hours=8), id=1)
attack("C4 uppercase-mode grant", "Documents/paper/draft.tex", g=g_upper, should_allow=False)

# --- Section D: discovery boundary probes (namespace guard) -------------

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from broker.grants import GrantStore
from broker.nextcloud import AccessRefused, NextcloudLayer

store = GrantStore(db_path=":memory:", now=lambda: NOW)

class DeadDav:
    def __init__(self):
        self.calls = []
    def propfind(self, p): self.calls.append(p); return {}
    def get(self, p): self.calls.append(p); return {}
    def put(self, p, d): self.calls.append(p); return {}
    def move(self, s, d): self.calls.append((s, d)); return {}
    def delete(self, p): self.calls.append(p); return {}

from broker.nextcloud import NextcloudClient


def make_layer(discovery=True):
    dav = DeadDav()
    layer = NextcloudLayer(
        store=store,
        clients={"x": NextcloudClient(url="u", username="user", password="pw", dav=dav)},
        audit=None, now=lambda: NOW,
        discovery_instances={"x"} if discovery else set(),
    )
    return layer, dav

for label, probe in [
    ("D1 trashbin plain", "trashbin"),
    ("D2 trashbin slash", "trashbin/user/trash"),
    ("D3 Trashbin case", "Trashbin"),
    ("D4 url-encoded trashbin", "%74rashbin"),
    ("D5 double-encoded trashbin", "%2574rashbin"),
    ("D6 dot-prefixed", "./trashbin"),
    ("D7 dotdot-prefixed", "a/../trashbin"),
    ("D8 remote.php/dav/trashbin", "remote.php/dav/trashbin/user/trash"),
    ("D9 files_trashbin app dir", "files_trashbin"),
    ("D10 trashbin via backslash", "trashbin\\user"),
    ("D11 trailing-slash trashbin", "trashbin/"),
]:
    layer, dav = make_layer()
    try:
        layer.list("x", probe)
        result = "ALLOWED"
    except AccessRefused:
        result = "denied"
    if result == "ALLOWED":
        SURPRISES.append(f"{label}: trashbin probe {probe!r} was ALLOWED")
        print(f"  [!!] {label}: {probe!r} -> ALLOWED")
    else:
        print(f"  [ok] {label}: {probe!r} -> denied")

# D12: discovery must not leak into read on trashbin
layer, dav = make_layer()
try:
    layer.read("x", "trashbin/user/trash/item")
    SURPRISES.append("D12: read on trashbin namespace ALLOWED")
    print("  [!!] D12: read on trashbin ALLOWED")
except AccessRefused:
    print("  [ok] D12: read on trashbin denied")

# D13: discovery list of root must not be grantable to READ content
layer, dav = make_layer(discovery=False)
try:
    layer.read("x", "")
    SURPRISES.append("D13: read of root allowed without grant")
    print("  [!!] D13: read of root ALLOWED")
except AccessRefused:
    print("  [ok] D13: read of root denied without grant")

print()
if SURPRISES:
    print(f"=== FINDINGS: {len(SURPRISES)} ===")
    for s in SURPRISES:
        print(" -", s)
    sys.exit(1)
print("=== ALL CASES BEHAVED AS EXPECTED ===")
sys.exit(0)