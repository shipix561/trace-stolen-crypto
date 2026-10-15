#!/usr/bin/env python3
"""
btc_tracer.py - Bitcoin fund tracer (MVP). Python 3.8+, no dependencies.

Usage:
    python btc_tracer.py ADDRESS [--depth 3] [--min-btc 0.001] [--max-txs 200]

What it does:
  1. Starts at ADDRESS and follows where its funds went, hop by hop.
  2. Stops at addresses found in labels.json (exchanges, known scams...).
  3. Flags high-activity addresses (likely services) instead of expanding them.
  4. Groups addresses that were co-spent in one transaction (common-input heuristic).
  5. Saves everything to graph.json and prints a short report.

Extras:
  --taint [--stolen-btc X]  follow the stolen funds only (proportional/haircut taint, address level):
                            each edge shows how much of the BTC it carries is tainted.
  CoinJoin-like transactions are detected: they are never used for clustering, and the trail
  stops there (flagged), because the outputs cannot be tied to the inputs.

Data source: Blockstream public API (no key needed).
Results are probabilistic: a cluster means "probably the same entity", not proof.
"""
import argparse
import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict, deque

import chains
import clusters as cl
import opreturn

API = "https://blockstream.info/api"
DELAY = 0.4  # seconds between calls, be polite to the public API
RISK = {"sanctioned", "scam", "mixer", "darknet", "ransomware", "theft"}


def label_info(labels, addr):
    """Accept simple ("name") and rich ({"label":..., "category":...}) entries."""
    v = labels.get(addr)
    if v is None or (isinstance(v, dict) and (v.get("review") or {}).get("status") == "rejected"):
        return None
    if isinstance(v, str):
        return {"label": v}
    return {k: v[k] for k in ("label", "category", "source", "confidence") if k in v}


_ctx = threading.local()


class use_chain:
    """with btc_tracer.use_chain("ltc"): ... every read below goes to that Bitcoin-like network (per thread)."""

    def __init__(self, chain):
        if not chains.is_utxo(chain):
            raise ValueError("ليست شبكة بتكوين-الشكل: %s" % chain)
        self.chain = chain

    def __enter__(self):
        self.prev = getattr(_ctx, "chain", "btc")
        _ctx.chain = self.chain
        return self

    def __exit__(self, *e):
        _ctx.chain = self.prev
        return False


def current_chain():
    return getattr(_ctx, "chain", "btc")


def get(path):
    ch = current_chain()
    if ch != "btc" and chains.get(ch).get("shim"):
        import utxo_shim
        return utxo_shim.get(ch, path)
    base = API if ch == "btc" else chains.get(ch)["api"]
    for attempt in range(4):
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent": "btc-tracer/0.1"})
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            time.sleep(1 + attempt)
    raise RuntimeError("request failed: " + path)


def address_txs(addr, max_txs):
    """Return (txs, total_count). txs is None if the address is too busy."""
    info = get("/address/" + addr)
    total = info["chain_stats"]["tx_count"] + info["mempool_stats"]["tx_count"]
    if total > max_txs:
        return None, total
    txs, last = [], None
    while True:
        path = "/address/%s/txs" % addr if last is None else "/address/%s/txs/chain/%s" % (addr, last)
        page = get(path)
        time.sleep(DELAY)
        if not page:
            break
        txs += page
        last = page[-1]["txid"]
        if len(page) < 25:
            break
    return txs, total


class UnionFind:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def is_coinjoin(tx):
    """Heuristic: 3+ inputs and 3+ equal-value outputs that make up a large share of the outputs."""
    outs = [o["value"] for o in tx["vout"] if o.get("scriptpubkey_address")]
    if len(tx["vin"]) < 3 or len(outs) < 3:
        return False
    top = Counter(outs).most_common(1)[0][1]
    return top >= 3 and top >= 0.4 * len(outs)


def trace(start, depth, max_txs, min_btc, labels, taint=False, stolen=None, min_taint=0.0005):
    min_sat = int(min_btc * 1e8)
    nodes = {start: {"depth": 0}}
    edges, seen_tx = [], set()
    uf = UnionFind()
    evidence, messages = [], []
    visited = set()
    q = deque([(start, 0)])
    taint_in = defaultdict(float)  # tainted BTC received, per address
    phi = {}                       # share of an address's funds that is tainted
    coinjoins = 0

    while q:
        addr, d = q.popleft()
        if addr in visited:
            continue
        visited.add(addr)
        if addr != start and label_info(labels, addr):
            continue  # reached a known entity: stop here

        txs, total = address_txs(addr, max_txs)
        if txs is None:
            nodes[addr]["note"] = "high activity (%d txs), likely a service; not expanded" % total
            continue
        if taint:
            recv = sum(o["value"] for tx in txs for o in tx["vout"]
                       if o.get("scriptpubkey_address") == addr) / 1e8
            if addr == start:
                taint_in[start] = stolen if stolen is not None else recv
            phi[addr] = min(1.0, taint_in[addr] / recv) if recv > 0 else 0.0

        for tx in txs:
            if tx["txid"] in seen_tx:
                continue
            ins = {}
            for v in tx["vin"]:
                pv = v.get("prevout") or {}
                if pv.get("scriptpubkey_address"):
                    ins[pv["scriptpubkey_address"]] = ins.get(pv["scriptpubkey_address"], 0) + pv["value"]
            if addr not in ins:
                continue  # this tx received funds, we only follow spending
            seen_tx.add(tx["txid"])
            when = tx["status"].get("block_time")

            if is_coinjoin(tx):  # trail is ambiguous: do not cluster, do not follow
                coinjoins += 1
                cj = "coinjoin:" + tx["txid"]
                e = {"from": addr, "to": cj, "txid": tx["txid"], "btc": ins[addr] / 1e8, "time": when}
                if taint:
                    e["taint"] = phi.get(addr, 0.0) * ins[addr] / 1e8
                edges.append(e)
                nodes.setdefault(cj, {"depth": d + 1, "label": "CoinJoin (محتمل)", "category": "coinjoin",
                                      "note": "possible CoinJoin: outputs cannot be tied to inputs, trail not followed"})
                continue

            evidence.append(cl.evidence_from_tx(tx))  # used by clusters.compute with safeguards
            messages += opreturn.scan_tx(tx)
            total_in = sum(ins.values())
            tainted_in = sum(phi.get(x, 0.0) * val for x, val in ins.items()) if taint else 0.0
            frac = tainted_in / total_in if total_in else 0.0

            for o in tx["vout"]:
                a = o.get("scriptpubkey_address")
                if not a or a in ins or o["value"] < min_sat:
                    continue  # skip change back to the sender and dust
                t_out = o["value"] / 1e8 * frac
                if taint and t_out < min_taint:
                    continue
                e = {"from": addr, "to": a, "txid": tx["txid"], "btc": o["value"] / 1e8, "time": when}
                if taint:
                    e["taint"] = t_out
                    taint_in[a] += t_out
                edges.append(e)
                if a not in nodes:
                    nodes[a] = {"depth": d + 1}
                    info = label_info(labels, a)
                    if info:
                        nodes[a].update(info)
                if d + 1 < depth:
                    q.append((a, d + 1))

    if taint:
        for a, t in taint_in.items():
            if a in nodes and t > 0:
                nodes[a]["taint"] = round(t, 8)
    res = {"start": start, "nodes": nodes, "edges": edges, "clusters": [],
           "mode": "taint" if taint else "all", "coinjoins": coinjoins,
           "cluster_evidence": evidence, "messages": messages}
    cl.compute(res, labels)
    if current_chain() != "btc":  # same graph shape; the coin symbol travels with every edge
        res["chain"] = current_chain()
        for e in edges:
            e["asset"] = chains.native(current_chain())
    return res


def report(g):
    print("\nStart:", g["start"])
    print("Addresses reached: %d | transfers: %d" % (len(g["nodes"]), len(g["edges"])))
    hits = {a: n for a, n in g["nodes"].items() if "label" in n}
    print("\nKnown entities reached:")
    if not hits:
        print("  none (add labels to labels.json)")
    for a, n in hits.items():
        extra = ", ".join(str(n[k]) for k in ("category", "source", "confidence") if k in n)
        if n.get("taint"):
            extra = (extra + ", " if extra else "") + "tainted %.4f BTC" % n["taint"]
        print("  %s -> %s%s" % (a, n["label"], " (%s)" % extra if extra else ""))
    risky = [a for a, n in hits.items() if n.get("category") in RISK]
    if risky:
        print("\n!! High-risk entities reached (%s): %d address(es)" % (", ".join(sorted(RISK)), len(risky)))
    print("Labeled: %d of %d reached addresses" % (len(hits), len(g["nodes"])))
    if g.get("coinjoins"):
        print("CoinJoin-like transactions (trail ambiguous, not followed): %d" % g["coinjoins"])
    busy = {a: n for a, n in g["nodes"].items() if "note" in n}
    if busy:
        print("\nHigh-activity addresses (possible exchange/service, check manually):")
        for a, n in busy.items():
            print("  %s: %s" % (a, n["note"]))
    if g["clusters"]:
        print("\nAddresses likely controlled by the same entity:")
        for c in g["clusters"]:
            print("  " + ", ".join(c))
    print("\nFull graph saved to graph.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("address")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--min-btc", type=float, default=0.001)
    ap.add_argument("--max-txs", type=int, default=200)
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--taint", action="store_true", help="follow only the stolen funds")
    ap.add_argument("--stolen-btc", type=float, default=None, help="stolen amount received at the start address")
    ap.add_argument("--min-taint", type=float, default=0.0005, help="ignore tainted flows below this BTC")
    args = ap.parse_args()

    labels = {}
    if os.path.exists(args.labels):
        with open(args.labels, encoding="utf-8") as f:
            labels = json.load(f)

    g = trace(args.address, args.depth, args.max_txs, args.min_btc, labels,
              taint=args.taint or args.stolen_btc is not None, stolen=args.stolen_btc,
              min_taint=args.min_taint)
    with open("graph.json", "w", encoding="utf-8") as f:
        json.dump(g, f, ensure_ascii=False, indent=2)
    report(g)


if __name__ == "__main__":
    main()
