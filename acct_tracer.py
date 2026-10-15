#!/usr/bin/env python3
"""
acct_tracer.py - Ethereum and TRON fund tracer (MVP). Python 3.8+, no dependencies.
Produces the same graph.json as btc_tracer.py, so the web page draws it unchanged.

Usage:
    python acct_tracer.py eth  0xADDRESS [--depth 3]
    python acct_tracer.py tron TADDRESS  [--depth 3]

Tracks outgoing transfers of: ETH + USDT/USDC/DAI (Ethereum), TRX + USDT (TRON).
Use --all-tokens to follow every token (noisy: spam tokens appear).

Data sources (free, no key needed for light use):
  Ethereum: Blockscout public instance (eth.blockscout.com). Its free endpoints are
            marked for deprecation, so pass --api-key if it starts refusing requests.
  TRON:     TronGrid (api.trongrid.io). Pass --api-key for higher rate limits.

Differences from Bitcoin: account chains have no "co-spent inputs", so there is no
address clustering here. Instead, an address that receives from 3+ traced addresses
is flagged as a collection point (often an exchange or service hot wallet).
Internal contract transfers (ETH sent through contracts) are not followed yet.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque

RISK = {"sanctioned", "scam", "mixer", "darknet", "ransomware", "theft"}
import chains  # noqa: E402
import evm_api  # noqa: E402

ETH_BASE = chains.CHAINS["eth"]["providers"][0][1]
TRON_BASE = chains.CHAINS["tron"]["node"]
DELAY = 0.4
NATIVE = {k: chains.native(k) for k in chains.ORDER if chains.is_account(k)}
DEFAULT_MIN_NATIVE = {k: chains.DEFAULT_MIN_NATIVE[chains.native(k)] for k in NATIVE}
STABLES = {k: chains.stables(k) for k in NATIVE}
EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def label_info(labels, addr):
    v = labels.get(addr)
    if v is None or (isinstance(v, dict) and (v.get("review") or {}).get("status") == "rejected"):
        return None
    if isinstance(v, str):
        return {"label": v}
    return {k: v[k] for k in ("label", "category", "source", "confidence") if k in v}


def http(url, headers=None):
    h = {"User-Agent": "acct-tracer/0.1"}
    h.update(headers or {})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=25) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            time.sleep(1 + attempt)
    raise RuntimeError("request failed: " + url)


def hex_to_tron(h):
    raw = bytes.fromhex(h)
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n, s = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return s


# ---------- Ethereum (Blockscout) ----------
def eth_pages(path, params, key, max_pages, chain="eth"):
    return evm_api.pages(chain, path, params, key, max_pages)


def eth_out(addr, a, chain="eth"):
    out = []
    kw = {} if chain == "eth" else {"chain": chain}
    txs, b1 = eth_pages("/addresses/%s/transactions" % addr, {}, a.api_key, a.max_pages, **kw)
    for t in txs:
        if ((t.get("from") or {}).get("hash") or "").lower() != addr or not t.get("to"):
            continue
        if t.get("status") not in (None, "ok"):
            continue
        v = int(t.get("value") or 0)
        if v:
            out.append(dict(to=t["to"]["hash"].lower(), asset=NATIVE[chain], amount=v / 1e18,
                            txid=t["hash"], time=t.get("timestamp")))
    trs, b2 = eth_pages("/addresses/%s/token-transfers" % addr, {"type": "ERC-20"}, a.api_key, a.max_pages, **kw)
    for t in trs:
        if ((t.get("from") or {}).get("hash") or "").lower() != addr or not t.get("to"):
            continue
        tok = t.get("token") or {}
        ca = (tok.get("address_hash") or "").lower()
        if not a.all_tokens and ca not in STABLES[chain]:
            continue
        tot = t.get("total") or {}
        dec = int(tot.get("decimals") or tok.get("decimals") or 18)
        out.append(dict(to=t["to"]["hash"].lower(),
                        asset=STABLES[chain].get(ca) or tok.get("symbol") or "?",
                        amount=int(tot.get("value") or 0) / 10 ** dec,
                        txid=t["transaction_hash"], time=t.get("timestamp")))
    b3 = False
    if getattr(a, "internal", False):
        try:  # ETH sent through contracts does not appear in normal transfers
            its, b3 = eth_pages("/addresses/%s/internal-transactions" % addr, {}, a.api_key, a.max_pages, **kw)
            for t in its:
                f = ((t.get("from") or {}).get("hash") or "").lower()
                to = ((t.get("to") or {}).get("hash") or "").lower()
                v = int(t.get("value") or 0)
                if f == addr and to and v and t.get("success", True) is not False:
                    out.append(dict(to=to, asset=NATIVE[chain], amount=v / 1e18, txid=t.get("transaction_hash") or "",
                                    time=t.get("timestamp"), internal=True))
        except Exception:
            pass  # endpoint unavailable: continue with what we have
    return out, b1 or b2 or b3


# ---------- TRON (TronGrid) ----------
def tron_pages(path, params, key, max_pages):
    items, fp, pages = [], None, 0
    hdr = {"TRON-PRO-API-KEY": key} if key else None
    while True:
        q = dict(params, limit=200)
        if fp:
            q["fingerprint"] = fp
        d = http(TRON_BASE + path + "?" + urllib.parse.urlencode(q), hdr)
        items += d.get("data", [])
        pages += 1
        time.sleep(DELAY)
        fp = (d.get("meta") or {}).get("fingerprint")
        if not fp or not d.get("data"):
            return items, False
        if pages >= max_pages:
            return items, True


def tron_out(addr, a):
    out = []
    params = {} if a.all_tokens else {"contract_address": next(iter(STABLES["tron"]))}
    trs, b1 = tron_pages("/v1/accounts/%s/transactions/trc20" % addr, params, a.api_key, a.max_pages)
    for t in trs:
        if t.get("from") != addr or not t.get("to"):
            continue
        ti = t.get("token_info") or {}
        out.append(dict(to=t["to"], asset=ti.get("symbol") or "?",
                        amount=int(t.get("value") or 0) / 10 ** int(ti.get("decimals") or 6),
                        txid=t["transaction_id"], time=t.get("block_timestamp")))
    nat, b2 = tron_pages("/v1/accounts/%s/transactions" % addr, {"only_from": "true"}, a.api_key, a.max_pages)
    for t in nat:
        c = ((t.get("raw_data") or {}).get("contract") or [{}])[0]
        if c.get("type") != "TransferContract":
            continue
        ret = (t.get("ret") or [{}])[0].get("contractRet")
        v = (c.get("parameter") or {}).get("value") or {}
        if (ret and ret != "SUCCESS") or not v.get("amount") or not v.get("to_address"):
            continue
        if hex_to_tron(v["owner_address"]) != addr:
            continue
        out.append(dict(to=hex_to_tron(v["to_address"]), asset="TRX", amount=v["amount"] / 1e6,
                        txid=t["txID"], time=t.get("block_timestamp")))
    return out, b1 or b2


# ---------- tracing ----------
def trace(chain, start, a, labels):
    if chains.is_evm(chain):
        fetch = lambda addr_, a_: eth_out(addr_, a_, chain)  # noqa: E731
    elif chain == "sol":
        import sol_api
        fetch = sol_api.sol_out
    else:
        fetch = tron_out
    norm = (lambda x: x.lower()) if chains.is_evm(chain) else (lambda x: x)
    start = norm(start)
    labels = {(k.lower() if k.startswith("0x") else k): v for k, v in labels.items()}
    min_native = a.min_native if a.min_native is not None else DEFAULT_MIN_NATIVE[chain]
    nodes, edges, inflow = {start: {"depth": 0}}, [], defaultdict(set)
    visited, q = set(), deque([(start, 0)])

    while q:
        addr, d = q.popleft()
        if addr in visited:
            continue
        visited.add(addr)
        if addr != start and label_info(labels, addr):
            continue  # known entity: stop here
        try:
            out, busy = fetch(addr, a)
        except Exception as e:  # keep going even if one address fails
            nodes[addr]["note"] = "fetch failed: %s" % e
            continue
        if busy:
            nodes[addr]["note"] = ("high activity (more than %d pages of history), "
                                   "likely a service; not expanded" % a.max_pages)
            continue
        keep = []
        for t in out:
            to = norm(t["to"])
            floor = min_native if t["asset"] == NATIVE[chain] else a.min_stable
            if to != addr and t["amount"] >= floor:
                keep.append((to, t))
        keep.sort(key=lambda x: -x[1]["amount"])
        for to, t in keep[:a.max_fanout]:
            edges.append({"from": addr, "to": to, "txid": t["txid"], "amount": t["amount"],
                          "asset": t["asset"], "time": t["time"],
                          **({"internal": True} if t.get("internal") else {})})
            inflow[to].add(addr)
            if to not in nodes:
                nodes[to] = {"depth": d + 1}
                info = label_info(labels, to)
                if info:
                    nodes[to].update(info)
            if d + 1 < a.depth:
                q.append((to, d + 1))

    for n, srcs in inflow.items():
        if len(srcs) >= 3 and "note" not in nodes[n] and "label" not in nodes[n]:
            nodes[n]["note"] = ("collection point: received from %d traced addresses "
                                "(possible service or hot wallet)" % len(srcs))
    return {"chain": chain, "start": start, "nodes": nodes, "edges": edges, "clusters": []}


def report(g):
    print("\nChain: %s | Start: %s" % (g["chain"], g["start"]))
    print("Addresses reached: %d | transfers: %d" % (len(g["nodes"]), len(g["edges"])))
    totals = defaultdict(float)
    for e in g["edges"]:
        if e["from"] == g["start"]:
            totals[e["asset"]] += e["amount"]
    if totals:
        print("Sent directly from start: " + ", ".join("%.4f %s" % (v, k) for k, v in totals.items()))
    hits = {a: n for a, n in g["nodes"].items() if "label" in n}
    print("\nKnown entities reached:")
    if not hits:
        print("  none (build labels.json with labels_tool.py)")
    for a, n in hits.items():
        extra = ", ".join(str(n[k]) for k in ("category", "source", "confidence") if k in n)
        print("  %s -> %s%s" % (a, n["label"], " (%s)" % extra if extra else ""))
    risky = [a for a, n in hits.items() if n.get("category") in RISK]
    if risky:
        print("\n!! High-risk entities reached: %d address(es)" % len(risky))
    notes = {a: n["note"] for a, n in g["nodes"].items() if "note" in n}
    if notes:
        print("\nCheck manually:")
        for a, t in notes.items():
            print("  %s: %s" % (a, t))
    print("\nLabeled: %d of %d reached addresses" % (len(hits), len(g["nodes"])))
    print("Full graph saved to graph.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=["eth", "tron"])
    ap.add_argument("address")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--min-stable", type=float, default=10, help="min amount for tokens (default 10)")
    ap.add_argument("--min-native", type=float, default=None, help="min ETH/TRX (default 0.01 / 100)")
    ap.add_argument("--max-pages", type=int, default=4, help="history pages per address before it counts as busy")
    ap.add_argument("--max-fanout", type=int, default=30, help="max transfers followed per address")
    ap.add_argument("--all-tokens", action="store_true")
    ap.add_argument("--internal", action="store_true", help="also follow ETH sent through contracts (internal transactions)")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--out", default="graph.json")
    a = ap.parse_args()

    ok = EVM_RE.match(a.address) if a.chain == "eth" else TRON_RE.match(a.address)
    if not ok:
        sys.exit("Address format does not match chain '%s'." % a.chain)
    labels = {}
    if os.path.exists(a.labels):
        with open(a.labels, encoding="utf-8") as f:
            labels = json.load(f)
    g = trace(a.chain, a.address, a, labels)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(g, f, ensure_ascii=False, indent=2)
    report(g)


if __name__ == "__main__":
    main()
