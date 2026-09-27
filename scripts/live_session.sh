#!/usr/bin/env bash
# One command for the whole live-approval session.
#   ./scripts/live_session.sh start          archive old telemetry, start clean
#   ./scripts/live_session.sh status [N]     progress + action mix (default target 100)
#   ./scripts/live_session.sh watch  [N]     status, refreshing every 10s
#   ./scripts/live_session.sh finish         copy telemetry out + run the analysis
set -euo pipefail
C="${POIA_CONTAINER:-poia-prototype_poia-bank_1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d)"
OUT="$ROOT/experiments/live_approval_$STAMP"
cd "$ROOT"

progress() {
podman exec -i "$C" python3 - "${1:-100}" <<'PY'
import csv, os, sys, time
from collections import Counter
target=int(sys.argv[1]) if len(sys.argv)>1 else 100
p=os.environ.get("POIA_CSV","/data/poia_experiments.csv")
if not os.path.exists(p):
    print("No telemetry file yet -- clean slate. 0 approvals so far."); raise SystemExit(0)
rows=list(csv.DictReader(open(p,newline="",encoding="utf-8")))
wa=[r for r in rows if r.get("event")=="passkey_complete" and r.get("method")=="webauthn" and r.get("status")=="approved"]
zt=[r for r in rows if r.get("event")=="intent_approve" and r.get("method")=="zt_authenticator" and r.get("status")=="approved"]
wad=[r for r in rows if r.get("event")=="passkey_complete" and r.get("method")=="webauthn" and r.get("status")!="approved"]
ztd=[r for r in rows if r.get("event")=="intent_approve" and r.get("method")=="zt_authenticator" and r.get("status")!="approved"]
tm=[r for r in rows if r.get("method")=="test_mode" and r.get("status")=="approved"]
notime=sum(1 for r in wa+zt if not (r.get("latency_ms") or "").strip())
bar=lambda n,t,w=22:"["+"#"*min(int(w*n/t),w)+"."*(w-min(int(w*n/t),w))+"]"
print("PoIA live approval progress --",time.strftime("%H:%M:%S"))
print("last write:",time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(os.path.getmtime(p))));print()
for name,sel in (("WebAuthn",wa),("ZT-Auth ",zt)):
    n=len(sel);print(f"  {name}  {n:>4} / {target}  {bar(n,target)} {100*n/target:5.1f}%{'  DONE' if n>=target else ''}")
print()
print(f"  denied / other:   WebAuthn {len(wad):<4} ZT-Auth {len(ztd)}")
print(f"  missing timing:   {notime:<4} (excluded from latency)")
print(f"  test_mode rows:   {len(tm):<4} ({'OK' if not tm else '!! CONTAMINATED'})")
aw,az=Counter(r.get("action","") for r in wa),Counter(r.get("action","") for r in zt)
acts=sorted(set(aw)|set(az))
if acts:
    print();print(f"  {'action mix (approved)':<28}{'WebAuthn':>9}{'ZT-Auth':>9}{'diff':>7}")
    for a in acts:
        d=aw[a]-az[a]
        print(f"    {a:<26}{aw[a]:>9}{az[a]:>9}{d:>+7}{'   <-- rebalance' if abs(d)>=5 else ''}")
    if wa and zt:
        skew=sum(abs(aw[a]/len(wa)-az[a]/len(zt)) for a in acts)/2
        print();print(f"  mix divergence: {skew*100:5.1f}%  (keep under ~10%)")
PY
}

case "${1:-status}" in
  start)
    mkdir -p "$ROOT/experiments/archive"
    if podman exec "$C" test -f /data/poia_experiments.csv; then
      podman cp "$C:/data/poia_experiments.csv" \
        "$ROOT/experiments/archive/poia_experiments_PRE_LIVE_$STAMP.csv"
      podman exec "$C" sh -c 'mv /data/poia_experiments.csv /data/poia_experiments_pre_live.csv'
      echo "archived -> experiments/archive/poia_experiments_PRE_LIVE_$STAMP.csv"
    else
      echo "no existing telemetry file; already clean"
    fi
    echo "bank.db untouched:"; podman exec "$C" ls -la /data/ | grep -E "bank.db|poia_experiments" || true
    echo; progress "${2:-100}"
    ;;
  status) progress "${2:-100}" ;;
  watch)  while true; do clear; progress "${2:-100}"; sleep 10; done ;;
  finish)
    mkdir -p "$OUT"
    podman cp "$C:/data/poia_experiments.csv" "$OUT/poia_experiments_live.csv"
    echo "copied -> $OUT/poia_experiments_live.csv"
    python3 scripts/analyze_live_approval_timing.py \
      --poia-csv "$OUT/poia_experiments_live.csv" --out-dir "$OUT"
    echo; python3 scripts/prepare_live_latency_fill.py \
      --summary "$OUT/approval_latency_summary.json"
    ;;
  *) echo "usage: $0 {start|status|watch|finish} [target]"; exit 1 ;;
esac
