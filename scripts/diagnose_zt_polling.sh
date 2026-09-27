#!/usr/bin/env bash
# Why has the ZT-Authenticator stopped receiving intents?
# Checks the six filters in the pending-intent endpoint against live state.
C="${POIA_CONTAINER:-poia-prototype_poia-bank_1}"
podman exec -i "$C" python3 - <<'PY'
import csv, os, sqlite3, time
from collections import Counter

db = os.environ.get("POIA_DB", "/data/bank.db")
csvp = os.environ.get("POIA_CSV", "/data/poia_experiments.csv")
now = int(time.time())
TTL = 60

print("="*70); print("1. ZT ENROLLMENT  (filters: device_not_enrolled / poia_zt_enabled)"); print("="*70)
con = sqlite3.connect(db); con.row_factory = sqlite3.Row
try:
    users = con.execute("SELECT id, email, poia_zt_enabled FROM users ORDER BY id").fetchall()
except Exception as e:
    print("  users query failed:", e); users = []
for u in users:
    devs = con.execute("""SELECT dk.device_id, dk.rp_id FROM device_keys dk
                          JOIN devices d ON d.id = dk.device_id
                          WHERE d.user_id = ?""", (u["id"],)).fetchall()
    flag = "ZT-ENABLED" if u["poia_zt_enabled"] else "** ZT DISABLED **"
    print(f"  user {u['id']:<3} {u['email']:<42} {flag}")
    for d in devs:
        print(f"        enrolled device_id={d['device_id']}  rp_id={d['rp_id']}")
    if not devs:
        print("        (no enrolled ZT device)")

print(); print("="*70); print("2. PER-USER BREAKDOWN  (who creates, who signs, on which backend)"); print("="*70)
if not os.path.exists(csvp):
    print("  no telemetry file"); raise SystemExit(0)
rows = list(csv.DictReader(open(csvp, newline="", encoding="utf-8")))
def ev(name, **kw):
    out=[r for r in rows if r.get("event")==name]
    for k,v in kw.items(): out=[r for r in out if r.get(k)==v]
    return out
created = ev("intent_created")
served  = ev("pending_served")
zt_ok   = ev("intent_approve", method="zt_authenticator", status="approved")
wa_ok   = ev("passkey_complete", method="webauthn", status="approved")

users = sorted({r.get("user_id","") for r in created if r.get("user_id")})
print(f"  {'user':<6}{'created':>9}{'served-to-ZT':>14}{'ZT approved':>13}{'WebAuthn appr':>15}{'unresolved':>12}")
for u in users:
    c=[r for r in created if r.get("user_id")==u]
    s_=[r for r in served if r.get("user_id")==u]
    z=[r for r in zt_ok if r.get("user_id")==u]
    w=[r for r in wa_ok if r.get("user_id")==u]
    unres=len(c)-len(z)-len(w)
    print(f"  {u:<6}{len(c):>9}{len(s_):>14}{len(z):>13}{len(w):>15}{unres:>12}")

print()
print("  interpretation:")
for u in users:
    c=len([r for r in created if r.get("user_id")==u])
    s_=len([r for r in served if r.get("user_id")==u])
    z=len([r for r in zt_ok if r.get("user_id")==u])
    w=len([r for r in wa_ok if r.get("user_id")==u])
    role = "ZT (phone)" if z>w else ("WebAuthn (browser)" if w>z else "unclear")
    note=""
    if role.startswith("WebAuthn") and s_>0:
        note = f"  <-- WARNING: {s_} ZT polls served for a browser user; a ZT device is still enrolled+polling as user {u}"
    print(f"    user {u}: {role}, {c} created, {z} ZT / {w} WebAuthn approvals{note}")

print()
print("  polling continuity (gaps suggest the app was backgrounded / screen locked):")
sts=sorted(int(r["server_ts"]) for r in served if r.get("server_ts","").isdigit())
if len(sts)>1:
    gaps=[(sts[i+1]-sts[i], sts[i]) for i in range(len(sts)-1)]
    big=[g for g in gaps if g[0]>90]
    print(f"    {len(sts)} serves, {len(big)} gaps longer than 90s")
    for g,at in sorted(big, reverse=True)[:5]:
        print(f"      gap of {g:>5}s ending {int((now-at-g)/60)} min ago")
    if not big: print("      no long gaps: polling has been continuous")

print(); print("="*70); print("3. DELIVERY LAG  (creation -> served)"); print("="*70)
cmap = {r.get("intent_id"): int(r["server_ts"]) for r in created if r.get("server_ts","").isdigit()}
lags = sorted(int(r["server_ts"]) - cmap[r["intent_id"]]
              for r in served if r.get("intent_id") in cmap and r.get("server_ts","").isdigit())
if lags:
    print(f"  n={len(lags)}  min={lags[0]}s  median={lags[len(lags)//2]}s  max={lags[-1]}s   (TTL is {TTL}s)")
    over = sum(1 for l in lags if l > TTL*0.5)
    print(f"  {over} of {len(lags)} took more than half the TTL")
else:
    print("  no served intents to measure")
PY
