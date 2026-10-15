#!/usr/bin/env python3
"""
utxo_trace.py - follow the exact bitcoin of YOUR payment, transaction by transaction. Python 3.8+.

    python utxo_trace.py TXID VOUT [--stolen 0.6] [--depth 6] [--cache btc_cache.db]

TXID:VOUT is the output of your payment transaction that went to the scammer (intake.py shows it).

Why this is more accurate than tracing an address:
  - An address mixes the money of many people; a UTXO is one specific coin. We follow only that coin.
  - It never enumerates an address's history, so busy addresses (exchanges) no longer stop the trace.
  - "Is it still there?" is answered exactly: an output that has not been spent is still unspent.

Taint is reported as a RANGE, because there is no single correct way to split mixed coins:
  taint      proportional (haircut): each output gets its share of the tainted value that entered the transaction
  taint_max  upper bound (poison): any output of a transaction with a tainted input is counted as fully tainted
Courts and exchanges understand both; state which one you cite.

Stops (and flags) at: labeled addresses (exchanges and other entities), CoinJoin-like transactions
(outputs cannot be tied to inputs), outputs with no address (e.g. bare multisig), the depth limit,
and the transaction limit. Unconfirmed spends are marked, and confirmations are counted per edge.
The result uses the same graph.json format as the other tools.
"""
import argparse
import json
import os
import sqlite3
import sys
from collections import Counter, deque

import btc_tracer
import chains
import clusters as cl
import opreturn

SAT = 1e8


class Cache:
    """In-memory memo plus an optional SQLite file for confirmed transactions (they never change)."""

    def __init__(self, path=None):
        self.mem, self.db = {}, None
        if path:
            self.db = sqlite3.connect(path)
            self.db.execute("CREATE TABLE IF NOT EXISTS tx(txid TEXT PRIMARY KEY, body TEXT)")

    def tx(self, txid):
        if txid in self.mem:
            return self.mem[txid]
        if self.db:
            row = self.db.execute("SELECT body FROM tx WHERE txid=?", (txid,)).fetchone()
            if row:
                self.mem[txid] = json.loads(row[0])
                return self.mem[txid]
        t = btc_tracer.get("/tx/" + txid)
        self.mem[txid] = t
        if self.db and (t.get("status") or {}).get("confirmed"):
            with self.db:
                self.db.execute("INSERT OR REPLACE INTO tx VALUES(?,?)", (txid, json.dumps(t)))
        return t


def likely_change(tx):
    """Index of the output that is probably change returning to the sender, or None (heuristic)."""
    outs = [(i, o) for i, o in enumerate(tx["vout"]) if o.get("scriptpubkey_address")]
    if len(outs) != 2:
        return None
    types = Counter((v.get("prevout") or {}).get("scriptpubkey_type") for v in tx["vin"])
    itype = types.most_common(1)[0][0] if types else None
    same = [i for i, o in outs if o.get("scriptpubkey_type") == itype]
    if len(same) == 1 and len(types) == 1:
        return same[0]
    rnd = [i for i, o in outs if o["value"] % 10000 == 0]
    return [i for i, o in outs if i != rnd[0]][0] if len(rnd) == 1 else None


def trace_outpoint(txid, vout, depth=6, labels=None, stolen=None, min_taint=0.0005, max_tx=300, cache=None):
    labels, cache = labels or {}, cache or Cache()
    try:
        tip = int(btc_tracer.get("/blocks/tip/height"))
    except Exception:
        tip = None
    root = cache.tx(txid)
    o = root["vout"][vout]
    start = o.get("scriptpubkey_address")
    if not start:
        raise ValueError("That output has no standard address (it cannot be traced by address).")
    value = o["value"] / SAT
    taint = {(txid, vout): (min(stolen, value) if stolen is not None else value, value)}
    nodes, edges = {start: {"depth": 0}}, []
    evidence, messages = [], opreturn.scan_tx(root)
    unspent, beyond, gaps = [], [], []
    ntaint, nmax = {start: taint[(txid, vout)][0]}, {start: value}
    coinjoins, processed, truncated = 0, {txid}, False
    queue = deque([(txid, 0)])

    def confs(tx):
        st = tx.get("status") or {}
        return (tip - st["block_height"] + 1) if (st.get("confirmed") and tip is not None) else 0

    while queue and not truncated:
        ptxid, d = queue.popleft()
        parent = cache.tx(ptxid)
        spends = btc_tracer.get("/tx/%s/outspends" % ptxid)
        for idx, out in enumerate(parent["vout"]):
            key = (ptxid, idx)
            if key not in taint:
                continue
            addr = out.get("scriptpubkey_address")
            if addr != start and btc_tracer.label_info(labels, addr):
                continue  # arrived at a known entity: stop here
            sp = spends[idx] if idx < len(spends) else {}
            if not sp.get("spent"):
                unspent.append({"address": addr, "value": out["value"] / SAT, "taint": taint[key][0],
                                "txid": ptxid, "vout": idx})
                continue
            if d >= depth:
                beyond.append({"address": addr, "txid": sp.get("txid"), "taint": taint[key][0]})
                continue
            ctx = sp["txid"]
            if ctx in processed:
                continue
            if len(processed) > max_tx:
                truncated = True
                break
            processed.add(ctx)
            c = cache.tx(ctx)
            ins = []
            for v in c["vin"]:
                pv = v.get("prevout") or {}
                ins.append(((v.get("txid"), v.get("vout")), pv.get("scriptpubkey_address"), pv.get("value", 0)))
            total_in = sum(x[2] for x in ins)
            tainted = [(k, a, val, taint[k][0]) for k, a, val in ins if k in taint]
            tainted_in, tv = sum(t[3] for t in tainted), sum(t[2] for t in tainted)
            when, cf = (c.get("status") or {}).get("block_time"), confs(c)
            if btc_tracer.is_coinjoin(c):
                coinjoins += 1
                cj = "coinjoin:" + ctx
                nodes.setdefault(cj, {"depth": d + 1, "label": "CoinJoin (محتمل)", "category": "coinjoin",
                                      "note": "possible CoinJoin: outputs cannot be tied to inputs, trail not followed"})
                for k, a, val, tt in tainted:
                    edges.append({"from": a, "to": cj, "txid": ctx, "btc": val / SAT, "taint": tt, "taint_max": val / SAT,
                                  "time": when, "confs": cf})
                continue
            evidence.append(cl.evidence_from_tx(c))  # clustering evidence, filtered by safeguards later
            messages += opreturn.scan_tx(c)
            frac = tainted_in / (total_in / SAT) if total_in else 0.0
            change = likely_change(c)
            carried = False
            for j, oo in enumerate(c["vout"]):
                a = oo.get("scriptpubkey_address")
                v = oo["value"] / SAT
                if not a:
                    if oo.get("scriptpubkey_type") != "op_return" and oo["value"] > 0:
                        gaps.append({"txid": ctx, "vout": j, "value": v, "type": oo.get("scriptpubkey_type")})
                    continue
                t_out = v * frac
                if t_out < min_taint:
                    continue
                taint[(ctx, j)] = (t_out, v)
                carried = True
                if a not in nodes:
                    nodes[a] = {"depth": d + 1}
                    info = btc_tracer.label_info(labels, a)
                    if info:
                        nodes[a].update(info)
                for k, ia, ival, itt in tainted:
                    h = t_out * itt / tainted_in if tainted_in else 0.0
                    m = v * ival / tv if tv else 0.0
                    ntaint[a] = ntaint.get(a, 0.0) + h
                    nmax[a] = nmax.get(a, 0.0) + m
                    if ia != a:
                        edges.append({"from": ia, "to": a, "txid": ctx, "btc": v * ival / (total_in / SAT),
                                      "taint": h, "taint_max": m, "time": when, "confs": cf,
                                      **({"change": True} if j == change else {})})
            if carried:
                queue.append((ctx, d + 1))

    for a in nodes:
        if a in ntaint:
            nodes[a]["taint"] = round(ntaint[a], 8)
            nodes[a]["taint_max"] = round(nmax.get(a, 0.0), 8)
    ch = btc_tracer.current_chain()
    if ch != "btc":
        for e in edges:
            e["asset"] = chains.native(ch)
    res = {"chain": ch, "start": start, "mode": "taint", "model": "utxo-haircut+poison",
           "start_outpoint": [txid, vout], "nodes": nodes, "edges": edges, "clusters": [], "coinjoins": coinjoins,
           "unspent": unspent, "beyond_depth": beyond, "gaps": gaps, "truncated": truncated, "tip": tip,
           "cluster_evidence": evidence, "messages": messages}
    cl.compute(res, labels)
    return res


def report(g):
    L = ["Start: %s (outpoint %s:%d)" % (g["start"], g["start_outpoint"][0], g["start_outpoint"][1]),
         "Addresses: %d | transfers: %d | transactions followed" % (len(g["nodes"]), len(g["edges"]))]
    hits = {a: n for a, n in g["nodes"].items() if n.get("label") and n.get("category") != "coinjoin"}
    L.append("Reached known entities:" + ("" if hits else " none (add labels with labels_tool.py)"))
    for a, n in hits.items():
        L.append("  %s -> %s (%s): tainted %.4f BTC (upper bound %.4f)" % (a, n["label"], n.get("category"), n.get("taint", 0), n.get("taint_max", 0)))
    if g["unspent"]:
        L.append("STILL UNSPENT (tainted coins that have not moved):")
        for u in g["unspent"]:
            L.append("  %s: %.8f BTC (tainted %.6f) in %s:%d" % (u["address"], u["value"], u["taint"], u["txid"], u["vout"]))
    L.append("CoinJoin stops: %d | spent beyond the depth limit: %d | unattributable outputs: %d" % (
        g["coinjoins"], len(g["beyond_depth"]), len(g["gaps"])))
    if g["truncated"]:
        L.append("Stopped at the transaction limit: raise --max-tx to continue.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("txid")
    ap.add_argument("vout", type=int)
    ap.add_argument("--stolen", type=float, default=None)
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--min-taint", type=float, default=0.0005)
    ap.add_argument("--max-tx", type=int, default=300)
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--cache", default=None, help="SQLite file to keep downloaded transactions")
    ap.add_argument("--out", default="graph.json")
    a = ap.parse_args()
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    g = trace_outpoint(a.txid, a.vout, a.depth, labels, a.stolen, a.min_taint, a.max_tx, Cache(a.cache))
    json.dump(g, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(report(g))
    print("\nSaved to", a.out)


if __name__ == "__main__":
    main()
