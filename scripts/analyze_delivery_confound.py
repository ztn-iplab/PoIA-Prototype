#!/usr/bin/env python3
"""Separate poll-delivery lag from human interaction time for ZT approvals.

The ZT-Authenticator approval latency recorded by the application is
    approval_ts - intent.created_at
which for a polled authenticator includes the time the intent waited before
the device was served it. The WebAuthn browser modal is rendered immediately
on creation and has no equivalent wait, so the two backends' creation-to-
approval intervals are not like-for-like: any delivery lag inflates ZT.

This script decomposes the ZT interval using the `pending_served` events:

    creation -> served    delivery lag (transport + poll interval + queue)
    served   -> approval  interaction  (comparable to WebAuthn)
    creation -> approval  total        (what the app records)

It reports all three so the manuscript can state the endpoint it means.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path


def pct(vals, p):
    if not vals:
        return None
    o = sorted(vals)
    k = (len(o) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(o) - 1)
    return o[f] if f == c else o[f] + (o[c] - o[f]) * (k - f)


def summarize(vals):
    if not vals:
        return {"n": 0}
    return {"n": len(vals), "median_s": round(statistics.median(vals), 2),
            "mean_s": round(statistics.mean(vals), 2),
            "p95_s": round(pct(vals, 95), 2), "p99_s": round(pct(vals, 99), 2),
            "min_s": round(min(vals), 2), "max_s": round(max(vals), 2)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--poia-csv", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()

    rows = list(csv.DictReader(a.poia_csv.open(newline="", encoding="utf-8")))
    ts = lambda r: float(r["server_ts"]) if r.get("server_ts", "").strip() else None

    # earliest serve per intent = when the device first displayed it
    first_served = {}
    for r in rows:
        if r.get("event") == "pending_served" and r.get("intent_id") and ts(r) is not None:
            i = r["intent_id"]
            first_served[i] = min(first_served.get(i, ts(r)), ts(r))
    created = {r["intent_id"]: ts(r) for r in rows
               if r.get("event") == "intent_created" and r.get("intent_id") and ts(r) is not None}

    zt = [r for r in rows if r.get("event") == "intent_approve"
          and r.get("method") == "zt_authenticator" and r.get("status") == "approved"]
    wa = [r for r in rows if r.get("event") == "passkey_complete"
          and r.get("method") == "webauthn" and r.get("status") == "approved"]

    delivery, interaction, total, unmatched = [], [], [], 0
    for r in zt:
        i, t = r.get("intent_id"), ts(r)
        if t is None or i not in created:
            unmatched += 1
            continue
        total.append(t - created[i])
        if i in first_served:
            delivery.append(first_served[i] - created[i])
            interaction.append(t - first_served[i])
        else:
            unmatched += 1

    wa_total = []
    for r in wa:
        i, t = r.get("intent_id"), ts(r)
        if t is not None and i in created:
            wa_total.append(t - created[i])

    out = {
        "zt_delivery_creation_to_served": summarize(delivery),
        "zt_interaction_served_to_approval": summarize(interaction),
        "zt_total_creation_to_approval": summarize(total),
        "webauthn_creation_to_approval": summarize(wa_total),
        "zt_approvals_without_matching_serve_event": unmatched,
        "note": ("WebAuthn has no polled-delivery stage: its browser modal renders on creation. "
                 "Compare webauthn_creation_to_approval against zt_interaction_served_to_approval "
                 "for a like-for-like human-interaction comparison; zt_total includes delivery lag."),
    }
    print(json.dumps(out, indent=2))
    if delivery and interaction:
        d, i_, t = out["zt_delivery_creation_to_served"], out["zt_interaction_served_to_approval"], out["zt_total_creation_to_approval"]
        w = out["webauthn_creation_to_approval"]
        print()
        print(f"  ZT delivery lag      median {d['median_s']:>6.2f}s   <- not present in WebAuthn")
        print(f"  ZT interaction       median {i_['median_s']:>6.2f}s   <- comparable to WebAuthn")
        print(f"  ZT total (recorded)  median {t['median_s']:>6.2f}s")
        if w.get("n"):
            print(f"  WebAuthn total       median {w['median_s']:>6.2f}s")
            infl = t["median_s"] - i_["median_s"]
            print(f"\n  delivery inflates the recorded ZT median by {infl:.2f}s "
                  f"({100*infl/t['median_s']:.0f}% of it)")
    if a.out:
        a.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(f"\nwritten: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
