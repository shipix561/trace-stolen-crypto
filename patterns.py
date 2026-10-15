#!/usr/bin/env python3
"""
patterns.py - explainable behavior detectors for fund flows. Python 3.8+.

    python patterns.py graph.json [--features features.csv]

It looks for the shapes money-laundering and scam operations leave in a trace:
  FAN_OUT       one wallet splits funds across many wallets (more weight when the amounts are equal)
  FAN_IN        many wallets collect into one wallet (not counted for known exchanges: normal there)
  SPLIT_MERGE   split into several wallets that then converge on the same destination
  CHAIN         long peel/hop chain of single-path transfers
  RAPID_PASS    wallets that forward funds within an hour of receiving them
  MIXING        a CoinJoin-like transaction or a mixer-labeled address
  RISK_CONTACT  contact with an address labeled scam / sanctioned / mixer / theft ...

Every finding states its evidence and the score is the sum of transparent weights. This is NOT a
probability and NOT a verdict on anyone: legitimate services show some of these shapes too.
Use the findings as leads to verify, never as proof.

--features writes one row per address (degrees, volumes, depth, flags). That table is the input you
would need to train a graph neural network later, but a model is only as good as its labeled data:
use a published labeled dataset plus your verified cases, and keep humans in the loop.
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

import verify

RISK = {"sanctioned", "scam", "mixer", "darknet", "ransomware", "theft"}
TIERS = [(6, "HIGH", "نمط يتوافق بقوة مع تمويه الأموال"), (3, "MEDIUM", "مؤشرات مقلقة تستحق المراجعة"),
         (0, "LOW", "لا أنماط واضحة")]


def to_epoch(t):
    if isinstance(t, (int, float)):
        return t / 1000 if t > 1e11 else float(t)
    if isinstance(t, str):
        try:
            return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def adjacency(g):
    out, inc = defaultdict(list), defaultdict(list)
    for e in g["edges"]:
        out[e["from"]].append(e)
        inc[e["to"]].append(e)
    return out, inc


def is_exchange(g, a):
    n = g["nodes"].get(a, {})
    return bool(n.get("label")) and n.get("category") == "exchange"


def analyze(g, fan=8, fan_in=5):
    nodes, (out, inc), F = g["nodes"], adjacency(g), []

    for a, es in out.items():
        dests = {e["to"] for e in es}
        if len(dests) >= fan:
            amts = [round(verify.amount(e), 6) for e in es]
            top, eq = Counter(amts).most_common(1)[0]
            F.append({"type": "FAN_OUT", "weight": 2 + (1 if eq >= 3 else 0), "nodes": [a],
                      "text": "%s وزّع أمواله على %d محفظة%s" % (a, len(dests), " (%d منها بمبلغ متساوٍ %s)" % (eq, top) if eq >= 3 else "")})
    for a, es in inc.items():
        srcs = {e["from"] for e in es}
        if len(srcs) >= fan_in and not is_exchange(g, a):
            F.append({"type": "FAN_IN", "weight": 1, "nodes": [a],
                      "text": "%s جمّع أموالًا من %d محفظة" % (a, len(srcs))})
    for s, es in out.items():
        mids = {e["to"] for e in es}
        if len(mids) < 3:
            continue
        reach = Counter(d for m in mids for d in {e["to"] for e in out.get(m, [])} if d != s and d not in mids)
        if reach:
            d, k = reach.most_common(1)[0]
            if k >= max(3, 0.6 * len(mids)):
                F.append({"type": "SPLIT_MERGE", "weight": 3, "nodes": [s, d],
                          "text": "%s قسّم الأموال على %d محفظة ثم اجتمعت %d منها في %s" % (s, len(mids), k, d)})
    # long single-path chains (follow the largest transfer; allow one small side payment)
    best = []
    for a in nodes:
        path, cur = [a], a
        while out.get(cur) and len({e["to"] for e in out[cur]}) <= 2:
            nxt = max(out[cur], key=verify.amount)["to"]
            if nxt in path:
                break
            path.append(nxt)
            cur = nxt
        if len(path) > len(best):
            best = path
    if len(best) - 1 >= 4:
        F.append({"type": "CHAIN", "weight": 2, "nodes": best,
                  "text": "سلسلة تحويلات متتابعة من %d قفزة تنتهي عند %s" % (len(best) - 1, best[-1])})
    # wallets that forward funds within an hour of receiving them (reported as a group when 3+)
    rapid = []
    for a in nodes:
        ins = [t for t in (to_epoch(e.get("time")) for e in inc.get(a, [])) if t]
        outs = [t for t in (to_epoch(e.get("time")) for e in out.get(a, [])) if t]
        deltas = [min((o - i for i in ins if o >= i), default=None) for o in outs]
        deltas = [d for d in deltas if d is not None]
        if deltas and max(deltas) < 3600:
            rapid.append(a)
    if len(rapid) >= 3:
        F.append({"type": "RAPID_PASS", "weight": 1, "nodes": rapid[:5],
                  "text": "%d محفظة تمرّر الأموال خلال أقل من ساعة من استلامها (مثال: %s)" % (len(rapid), rapid[0])})
    for a, n in nodes.items():
        if a.startswith("coinjoin:") or n.get("category") == "mixer":
            F.append({"type": "MIXING", "weight": 2, "nodes": [a], "text": "تماسّ مع خلط أو CoinJoin محتمل: %s" % a})
        elif n.get("category") in RISK and not n.get("inferred"):
            F.append({"type": "RISK_CONTACT", "weight": 3, "nodes": [a],
                      "text": "وصلت أموال إلى جهة مصنّفة (%s): %s [%s]" % (n["category"], a, n.get("label", ""))})

    best_w = {}
    cnt = Counter(f["type"] for f in F)
    for f in F:
        best_w[f["type"]] = max(best_w.get(f["type"], 0), f["weight"])
    score = sum(best_w.values()) + sum(1 for t, c in cnt.items() if c >= 3)
    tier, desc = next((t, d) for lim, t, d in TIERS if score >= lim)
    for f in F:
        for a in f["nodes"]:
            nodes.get(a, {}).setdefault("patterns", [])
            if f["type"] not in nodes.get(a, {}).get("patterns", []):
                nodes.get(a, {}).get("patterns", []).append(f["type"])
    F.sort(key=lambda f: -f["weight"])
    return {"score": score, "tier": tier, "tier_text": desc, "findings": F}


def features(g):
    out, inc = adjacency(g)
    rows = []
    for a, n in g["nodes"].items():
        rows.append({"address": a, "depth": n.get("depth"), "in_degree": len({e["from"] for e in inc.get(a, [])}),
                     "out_degree": len({e["to"] for e in out.get(a, [])}),
                     "in_volume": round(sum(verify.amount(e) for e in inc.get(a, [])), 8),
                     "out_volume": round(sum(verify.amount(e) for e in out.get(a, [])), 8),
                     "label_category": n.get("category") or "", "tainted": n.get("taint") or 0,
                     "patterns": "|".join(n.get("patterns", []))})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("graph")
    ap.add_argument("--features")
    a = ap.parse_args()
    g = json.load(open(a.graph, encoding="utf-8"))
    res = analyze(g)
    print("المؤشرات السلوكية: %s (%d نقطة) - %s" % (res["tier"], res["score"], res["tier_text"]))
    for f in res["findings"][:20]:
        print("- [%s] %s" % (f["type"], f["text"]))
    print("هذه مؤشرات للمراجعة وليست حكمًا على أحد.")
    if a.features:
        rows = features(g)
        with open(a.features, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print("features written to", a.features)


if __name__ == "__main__":
    main()
