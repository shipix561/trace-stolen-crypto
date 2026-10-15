#!/usr/bin/env python3
"""
clusters.py - Bitcoin address clustering with safeguards and explanations. Python 3.8+.

The common-input heuristic ("addresses spent together in one transaction belong to one owner") is
useful but NOT certain. It fails with CoinJoin and PayJoin, and exchanges or custodial wallets spend
from dozens of customers' addresses at once, so a naive merge can mean "the exchange", not "the scammer".

So every link is kept as evidence and every cluster gets:
  confidence  high / medium / low   (explained, never a probability)
  type        personal-likely or service-likely
  reasons     what supports it and what weakens it

Safeguards:
  - CoinJoin-like transactions are never used (the tracers skip them before recording evidence).
  - A transaction with more than MAX_INPUTS distinct input addresses is NOT used: it is typical of a
    service sweeping deposits. It is counted in cluster_skipped.
  - A cluster containing an address labeled as an exchange or service is typed "service-likely":
    it describes the service, not a person.
  - Large clusters and clusters linked only by crowded transactions lose confidence.

The tracers call evidence_from_tx() for each spending transaction they process and compute() once at
the end. Results: g["cluster_info"] (full detail), g["clusters"] (members of high/medium clusters),
g["cluster_skipped"].
"""
from collections import defaultdict

MAX_INPUTS = 20
import taxonomy  # noqa: E402

SERVICE_CATEGORIES = set(taxonomy.PLATFORM)
CONF_AR = {"high": "عالية", "medium": "متوسطة", "low": "منخفضة"}
TYPE_AR = {"personal-likely": "غالبًا محفظة شخصية", "service-likely": "غالبًا خدمة أو بورصة (ليست شخصًا)"}


def evidence_from_tx(tx):
    ins, types = set(), set()
    for v in tx.get("vin", []):
        pv = v.get("prevout") or {}
        if pv.get("scriptpubkey_address"):
            ins.add(pv["scriptpubkey_address"])
            types.add(pv.get("scriptpubkey_type"))
    return {"txid": tx.get("txid"), "inputs": sorted(ins), "types": sorted(t for t in types if t),
            "fp": {"version": tx.get("version"), "locktime": bool(tx.get("locktime")),
                   "rbf": any(v.get("sequence", 0xffffffff) < 0xfffffffe for v in tx.get("vin", []))}}


def _label(g, labels, a):
    n = g["nodes"].get(a, {})
    if n.get("label") and n.get("category") != "coinjoin":
        return n["label"], n.get("category")
    v = (labels or {}).get(a)
    if isinstance(v, dict) and (v.get("review") or {}).get("status") == "rejected":
        v = None
    if isinstance(v, dict) and v.get("label"):
        return v["label"], v.get("category")
    if isinstance(v, str):
        return v, None
    return None, None


def compute(g, labels=None, max_inputs=MAX_INPUTS):
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    used, skipped = [], 0
    for e in g.get("cluster_evidence", []):
        ins = e["inputs"]
        if len(ins) < 2:
            continue
        if len(ins) > max_inputs:
            skipped += 1
            continue
        for a in ins[1:]:
            parent[find(a)] = find(ins[0])
        used.append(e)
    groups = defaultdict(set)
    for a in list(parent):
        groups[find(a)].add(a)
    info = []
    for members in groups.values():
        if len(members) < 2:
            continue
        evs = [e for e in used if e["inputs"][0] in members]
        txs = {e["txid"] for e in evs}
        types = {t for e in evs for t in e["types"]}
        fps = {(e["fp"]["version"], e["fp"]["rbf"], e["fp"]["locktime"]) for e in evs}
        entities = {_label(g, labels, a) for a in members} - {(None, None)}
        service = any(c in SERVICE_CATEGORIES for _, c in entities)
        score, reasons = 0, []
        score += min(len(txs), 3)
        reasons.append("رُبطت عبر %d معاملة مستقلة" % len(txs))
        if len(types) == 1:
            score += 1
            reasons.append("كل المدخلات من نوع عنوان واحد (%s)" % next(iter(types)))
        elif len(types) > 1:
            reasons.append("أنواع عناوين مختلطة (يضعف الربط)")
        if len(txs) >= 2 and len(fps) == 1:
            score += 1
            reasons.append("بصمة محفظة متسقة عبر المعاملات (الإصدار وRBF وlocktime)")
        if max(len(e["inputs"]) for e in evs) >= 10:
            score -= 1
            reasons.append("بعض المعاملات كثيرة المدخلات (قد تكون تجميع خدمة)")
        if len(members) > 100:
            score -= 3
            reasons.append("مجموعة ضخمة جدًا (%d عنوانًا)" % len(members))
        elif len(members) > 30:
            score -= 2
            reasons.append("مجموعة كبيرة (%d عنوانًا): احتمال أن تكون خدمة" % len(members))
        names = sorted({n for n, _ in entities if n})
        if service:
            score = min(score, 1)
            reasons.append("تضم عنوانًا مصنّفًا كخدمة (%s): المجموعة تمثّل الخدمة وليس شخصًا" % ", ".join(names))
        elif names:
            reasons.append("تضم عنوانًا مصنّفًا: %s" % ", ".join(names))
        conf = "high" if score >= 4 else "medium" if score >= 2 else "low"
        info.append({"members": sorted(members), "confidence": conf, "score": score,
                     "type": "service-likely" if service else "personal-likely",
                     "reasons": reasons, "txids": sorted(txs)[:10]})
    info.sort(key=lambda c: -len(c["members"]))
    g["cluster_info"] = info
    g["cluster_skipped"] = skipped
    g["cluster_evidence"] = used
    g["clusters"] = [c["members"] for c in info if c["confidence"] in ("high", "medium")]
    return info
