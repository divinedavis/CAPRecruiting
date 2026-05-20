"""End-to-end test for the post-signup contract gate.

Runs ON the bearcats server, against the live recruiting.db + running app.
Exercises the same code path Stripe takes on successful checkout, then drives
the player through real HTTP to confirm the gate works.

Usage:  sudo -u bearcats python3 e2e_gate_test.py
"""
import os
import sys
import secrets
sys.path.insert(0, "/home/recruiting/bearcats")
os.chdir("/home/recruiting/bearcats")

from datetime import datetime, timedelta
import requests

import main  # imports the app + DB + helpers
from main import (
    SessionLocal, User, PendingSignup, PlayerProfile, LegalContract,
    hash_password, _finalize_pending_signup,
)

BASE = "https://caprecruiting.com"
# CSRF middleware requires Origin or Referer hostname to match Host header.
CSRF_HEADERS = {"Referer": f"{BASE}/login", "Origin": BASE}
RESULTS = []

def step(label, ok, detail=""):
    mark = "PASS" if ok else "FAIL"
    RESULTS.append((mark, label, detail))
    print(f"[{mark}] {label}" + (f"  ({detail})" if detail else ""))

def cleanup(db, username):
    u = db.query(User).filter(User.username == username).first()
    if u:
        db.query(LegalContract).filter(LegalContract.user_id == u.id).delete()
        db.query(PlayerProfile).filter(PlayerProfile.user_id == u.id).delete()
        db.delete(u)
    db.query(PendingSignup).filter(PendingSignup.username == username).delete()
    db.commit()

def main_test():
    db = SessionLocal()
    rand = secrets.token_hex(4)
    username = f"gatetest_{rand}"
    email = f"gatetest_{rand}@example.invalid"
    password = "TestGate!" + rand

    # Clean slate in case of prior failed run
    cleanup(db, username)

    # ── 1. Stand up a PendingSignup row exactly like a paid signup ─────────
    pending = PendingSignup(
        uuid=secrets.token_hex(16),
        username=username,
        email=email,
        password_hash=hash_password(password),
        tier="essentials",
        school_name="Test High School",
        school_city="Brooklyn",
        school_state="NY",
        school_county="Kings",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(pending)
    db.commit()
    db.refresh(pending)

    # ── 2. Trigger the same finalize the Stripe webhook + /upgrade/success use
    user = _finalize_pending_signup(db, pending, "cus_test_xxx", "sub_test_xxx")
    step("finalize_pending_signup returns a User", user is not None, f"user_id={getattr(user,'id',None)}")
    if user is None:
        return

    # ── 3. Confirm a gated LegalContract was auto-created ──────────────────
    contract = (db.query(LegalContract)
                .filter(LegalContract.user_id == user.id)
                .order_by(LegalContract.created_at.desc()).first())
    step("LegalContract auto-created for new player", contract is not None)
    step("contract.gate_access == True", bool(contract and contract.gate_access))
    step("contract.status == 'pending'", bool(contract and contract.status == "pending"))
    step("contract.user_id matches user.id", bool(contract and contract.user_id == user.id))
    token = contract.token if contract else None

    # ── 4. Log in over real HTTP ───────────────────────────────────────────
    s = requests.Session()
    # Grab CSRF: hit /login first
    r = s.get(f"{BASE}/login", allow_redirects=False)
    step("/login GET reachable", r.status_code == 200, f"HTTP {r.status_code}")
    csrf = s.cookies.get("csrftoken") or ""
    r = s.post(f"{BASE}/login",
               data={"username": username, "password": password},
               headers=CSRF_HEADERS,
               allow_redirects=False)
    step("login POST succeeds (302)", r.status_code in (302, 303), f"HTTP {r.status_code} → {r.headers.get('location','')}")

    # ── 5. Gated player hitting /dashboard should be redirected to /sign/{token}
    r = s.get(f"{BASE}/dashboard", allow_redirects=False)
    loc = r.headers.get("location", "")
    step("/dashboard 302s to /sign/{token}",
         r.status_code == 302 and loc.endswith(f"/sign/{token}"),
         f"HTTP {r.status_code} → {loc}")

    # Try a few more sensitive routes
    for path in ("/profile/edit", "/messages", "/profile/me"):
        r = s.get(f"{BASE}{path}", allow_redirects=False)
        loc = r.headers.get("location", "")
        step(f"GET {path} gated → /sign/{{token}}",
             r.status_code == 302 and loc.endswith(f"/sign/{token}"),
             f"HTTP {r.status_code} → {loc}")

    # ── 6. /sign/{token} itself must be reachable while gated ──────────────
    r = s.get(f"{BASE}/sign/{token}", allow_redirects=False)
    step("/sign/{token} reachable while gated", r.status_code == 200, f"HTTP {r.status_code}")

    # Static + logout must be reachable too
    r = s.get(f"{BASE}/static/cap-logo.png", allow_redirects=False)
    step("/static reachable while gated", r.status_code in (200, 404), f"HTTP {r.status_code}")

    # ── 7. Simulate completing the signature (set DB state directly) ───────
    contract.status = "signed"
    contract.signed_at = datetime.utcnow()
    db.commit()

    # ── 8. Now /dashboard should NOT be gated ──────────────────────────────
    r = s.get(f"{BASE}/dashboard", allow_redirects=False)
    not_gated = not (r.status_code == 302 and r.headers.get("location","").startswith("/sign/"))
    step("After signing, /dashboard is NOT redirected to /sign", not_gated,
         f"HTTP {r.status_code} → {r.headers.get('location','')}")

    # ── 9. Existing pending contract with gate_access=0 must NOT gate ──────
    legacy = (db.query(LegalContract)
              .filter(LegalContract.status == "pending",
                      LegalContract.gate_access == False)
              .first())
    step("At least one legacy pending contract has gate_access=False (existing players safe)",
         legacy is not None, f"id={getattr(legacy,'id',None)} player={getattr(legacy,'player_name',None)}")

    # ── 10. Cleanup ────────────────────────────────────────────────────────
    cleanup(db, username)
    step("cleanup test user", True)

    # Summary
    print()
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(f"=== {len(RESULTS) - len(fails)}/{len(RESULTS)} passed ===")
    if fails:
        for mark, label, detail in fails:
            print(f"  FAIL: {label}  {detail}")
        sys.exit(1)
    print("ALL PASS")

if __name__ == "__main__":
    main_test()
