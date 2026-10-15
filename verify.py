#!/usr/bin/env python3
"""
verify.py - verification and audit layer for the tracing tools. Python 3.8+.

    python verify.py audit graph.json [--labels labels.json] [--second URL] [--max-check 40]
                                      [--archive evidence/] [--no-network] [--out verification_report.md]
    python verify.py check-archive evidence/

What it does, in order of strength:
  1. Evidence archive: every raw API response is saved with its SHA-256 and a hash chain
     (each entry commits to the previous one), so later tampering is detectable.
  2. Cross-source check: the transactions that carry the findings are fetched from a SECOND
     independent source and compared field by field.
       Bitcoin:  any Esplora-compatible API (--second, default mempool.space)
       Ethereum: any JSON-RPC node (--second-eth, default ethereum-rpc.publicnode.com). Sender,
                 receiver, amount, success status, official token contract, confirmations.
       TRON:     any full node with the standard HTTP API (--second-tron URL, no default).
                 Same fields; fake tokens named "USDT" are caught by the contract address.
  3. Reconciliation (Bitcoin): per-address totals computed from transactions must equal the
     totals the provider reports for the address.
  4. Graph audit: conservation of taint, duplicate/impossible edges, clusters whose members carry
     different entity labels (a contradiction), coverage gaps (busy addresses, CoinJoin, depth limit).
  5. Confidence grade A-D for every finding that reaches a labeled entity, with the reasons.

No tool can guarantee zero mistakes. This one makes mistakes visible before a report is filed.
A licensed forensic analyst should still review anything that goes to court.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

import acct_tracer
import chains
import btc_tracer

DELAY = 0.3
REC = None  # evidence recorder, set by install_recorder
ERC20_DEC = {"USDT": 6, "USDC": 6, "DAI": 18}
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
MIN_CONF = {"eth": 12, "tron": 20}
STATUS_ORDER = ["mismatch", "unavailable", "unsupported", "recent", "ok"]
GRADE = {3: "A", 2: "B", 1: "C"}


# ---------------- evidence archive ----------------
def _redact(url):
    return re.sub(r"(apikey=)[^&]+", r"\1REDACTED", url, flags=re.I)  # never store API keys


def _rkey(url, data=None):
    """Key of a recorded request: the URL, plus for POST a hash of the body WITHOUT its changing 'id' counter."""
    url = _redact(url)
    if data is None:
        return url
    try:
        body = {k: v for k, v in json.loads(data).items() if k != "id"}
    except (ValueError, AttributeError):
        body = data.decode("utf-8", "replace")
    return url + "#" + hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def fetch_raw(url, headers=None, data=None):
    h = {"User-Agent": "verify/0.1"}
    if data:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h), timeout=25) as r:
                raw = r.read()
            if REC:
                REC.record(_rkey(url, data), raw)
            return raw
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            if REC:
                REC.record(_rkey(url, data), b"", e.code)  # a 404 is an answer too: replay must reproduce it
            raise
        except urllib.error.URLError as e:
            last = e
            time.sleep(1 + attempt)
    raise RuntimeError("request failed: %s (%s)" % (url, last))


def fetch_json(url):
    return json.loads(fetch_raw(url))


class Recorder:
    """Saves raw responses and a tamper-evident manifest (hash chain)."""

    def __init__(self, folder):
        self.dir, self.lock = folder, threading.Lock()
        os.makedirs(folder, exist_ok=True)
        self.path = os.path.join(folder, "manifest.json")
        self.items = []
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.items = json.load(f)

    def record(self, url, raw, status=None):
        url = _redact(url)
        digest = hashlib.sha256(raw).hexdigest()
        fn = digest[:24] + ".json"
        with self.lock:
            fp = os.path.join(self.dir, fn)
            if not os.path.exists(fp):
                with open(fp, "wb") as f:
                    f.write(raw)
            prev = self.items[-1]["entry_hash"] if self.items else "0" * 64
            at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            eh = hashlib.sha256(("|".join([prev, url, digest, at] + ([str(status)] if status is not None else []))).encode()).hexdigest()
            item = {"url": url, "retrieved_at": at, "sha256": digest, "bytes": len(raw), "file": fn, "prev": prev, "entry_hash": eh}
            if status is not None:
                item["status"] = status
            self.items.append(item)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.items, f, indent=1)


def install_recorder(rec):
    """Make the tracers archive every raw API response they receive (recording happens once, inside fetch_raw)."""
    global REC
    REC = rec
    btc_tracer.get = lambda path: json.loads(fetch_raw(btc_tracer.API + path))
    acct_tracer.http = lambda url, headers=None: json.loads(fetch_raw(url, headers))


def check_archive(folder):
    """Return a list of problems (empty list = archive is intact)."""
    problems, prev = [], "0" * 64
    with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
        items = json.load(f)
    for i, it in enumerate(items):
        eh = hashlib.sha256("|".join([it["prev"], it["url"], it["sha256"], it["retrieved_at"]]
                                     + ([str(it["status"])] if "status" in it else [])).encode()).hexdigest()
        if it["prev"] != prev:
            problems.append("entry %d: chain broken (entries removed or reordered)" % i)
        if eh != it["entry_hash"]:
            problems.append("entry %d: entry hash does not match its content (edited)" % i)
        fp = os.path.join(folder, it["file"])
        if not os.path.exists(fp):
            problems.append("entry %d: file %s missing" % (i, it["file"]))
        elif hashlib.sha256(open(fp, "rb").read()).hexdigest() != it["sha256"]:
            problems.append("entry %d: file %s was modified" % (i, it["file"]))
        prev = it["entry_hash"]
    return problems


# ---------------- network checks (Bitcoin) ----------------
def norm_tx(t):
    pv = lambda v: v.get("prevout") or {}
    return {"vin": sorted((str(pv(v).get("scriptpubkey_address")), pv(v).get("value", 0)) for v in t["vin"]),
            "vout": sorted((str(o.get("scriptpubkey_address")), o.get("value", 0)) for o in t["vout"]),
            "confirmed": bool(t["status"].get("confirmed")), "height": t["status"].get("block_height")}


def amount(e):
    return e.get("amount", e.get("btc", 0)) or 0


def cross_check_btc(g, second, limit, fetch=None):
    fetch = fetch or fetch_json
    labeled = {a for a, n in g["nodes"].items() if n.get("label")}
    ranked = sorted(g["edges"], key=lambda e: (e["to"] in labeled, e.get("taint") or 0, amount(e)),
                    reverse=True)
    seen, res = [], {}
    for e in ranked:
        if e["txid"] in res or len(seen) >= limit:
            continue
        t = e["txid"]
        seen.append(t)
        try:
            a = norm_tx(fetch(btc_tracer.API + "/tx/" + t))
            b = norm_tx(fetch(second.rstrip("/") + "/tx/" + t))
            res[t] = ("ok", "") if a == b else ("mismatch", ", ".join(k for k in a if a[k] != b[k]))
        except Exception as ex:
            res[t] = ("unavailable", str(ex)[:80])
        time.sleep(DELAY)
    return res


def reconcile_btc(addrs, fetch=None, max_txs=500, limit=5):
    fetch = fetch or fetch_json
    res = {}
    for a in addrs[:limit]:
        try:
            cs = fetch(btc_tracer.API + "/address/" + a)["chain_stats"]
            txs, total = btc_tracer.address_txs(a, max_txs)
            if txs is None:
                res[a] = ("skipped", "%d transactions, too many" % total)
                continue
            conf = [t for t in txs if t["status"].get("confirmed")]
            funded = sum(o["value"] for t in conf for o in t["vout"] if o.get("scriptpubkey_address") == a)
            spent = sum(v["prevout"]["value"] for t in conf for v in t["vin"]
                        if (v.get("prevout") or {}).get("scriptpubkey_address") == a)
            ok = funded == cs["funded_txo_sum"] and spent == cs["spent_txo_sum"]
            res[a] = ("ok", "") if ok else ("mismatch", "funded %d vs %d, spent %d vs %d (re-run once to rule out "
                                                         "a new block)" % (funded, cs["funded_txo_sum"], spent,
                                                                           cs["spent_txo_sum"]))
        except Exception as ex:
            res[a] = ("unavailable", str(ex)[:80])
        time.sleep(DELAY)
    return res


# ---------------- network checks (Ethereum, TRON) ----------------
def post_json(url, body):
    data = json.dumps(body).encode()
    return json.loads(fetch_raw(url, data=data))


def make_rpc(url):
    state = {"id": 0, "head": (0, None)}

    def call(method, params):
        if method == "eth_blockNumber" and time.time() - state["head"][0] < 30:
            return state["head"][1]
        state["id"] += 1
        d = post_json(url, {"jsonrpc": "2.0", "id": state["id"], "method": method, "params": params})
        if d.get("error"):
            raise RuntimeError(str((d["error"] or {}).get("message", "rpc error")))
        if method == "eth_blockNumber":
            state["head"] = (time.time(), d.get("result"))
        return d.get("result")
    return call


# Independent TRON full nodes (standard HTTP API) tried in order when no --second-tron is given.
# NOT verified by the author: each one is probed at run time and used only if it answers like a real node.
INDEPENDENT_TRON_NODES = ["https://tron-rpc.publicnode.com", "https://api.tronstack.io", "https://tron.drpc.org"]


def pick_independent_tron(primary="https://api.trongrid.io", candidates=None, post_fn=None):
    """First candidate (other than the primary provider) that returns a plausible current block, or None."""
    post_fn = post_fn or post_json
    for base in (candidates or INDEPENDENT_TRON_NODES):
        if base.rstrip("/") == primary.rstrip("/"):
            continue
        try:
            b = post_fn(base.rstrip("/") + "/wallet/getnowblock", {})
            if int(b["block_header"]["raw_data"]["number"]) > 1000000:
                return base
        except Exception:
            continue
    return None


def make_post(base):
    state = {"head": (0, None)}

    def post(path, body):
        if path == "/wallet/getnowblock" and time.time() - state["head"][0] < 30:
            return state["head"][1]
        d = post_json(base.rstrip("/") + path, body)
        if path == "/wallet/getnowblock":
            state["head"] = (time.time(), d)
        return d
    return post


def _eq(a, b):
    return abs(a - b) <= max(1e-9, 1e-9 * abs(b))


def verify_eth_edge(e, call, chain="eth"):
    if e.get("internal"):
        return ("unsupported", "internal transfer (through a contract): confirming it needs a trace-enabled node")
    tx = call("eth_getTransactionByHash", [e["txid"]])
    rc = call("eth_getTransactionReceipt", [e["txid"]])
    if not tx or not rc:
        return ("mismatch", "transaction not found on the second source")
    if rc.get("status") != "0x1":
        return ("mismatch", "transaction failed on-chain")
    asset = e.get("asset")
    if asset == chains.native(chain):
        ok = (tx["from"].lower() == e["from"] and (tx.get("to") or "").lower() == e["to"]
              and _eq(int(tx["value"], 16) / 1e18, e["amount"]))
        res = ("ok", "") if ok else ("mismatch", "native transfer differs (sender, receiver or amount)")
    elif asset not in set(acct_tracer.STABLES[chain].values()):
        return ("unsupported", "token %s: decimals unknown, cannot compare amounts" % asset)
    else:
        res = ("mismatch", "no matching Transfer event (sender, receiver, amount and official contract)")
        for lg in rc.get("logs", []):
            t = lg.get("topics", [])
            if (len(t) == 3 and t[0].lower() == TRANSFER_TOPIC
                    and acct_tracer.STABLES[chain].get((lg.get("address") or "").lower()) == asset
                    and ("0x" + t[1][-40:]).lower() == e["from"] and ("0x" + t[2][-40:]).lower() == e["to"]
                    and _eq(int(lg["data"], 16) / 10 ** chains.stable_decimals(chain, lg.get("address"), ERC20_DEC.get(asset, 6)), e["amount"])):
                res = ("ok", "")
                break
    if res[0] == "ok":
        conf = int(call("eth_blockNumber", []), 16) - int(rc["blockNumber"], 16) + 1
        if conf < MIN_CONF["eth"]:
            return ("recent", "only %d confirmations (reorg risk)" % conf)
    return res


def verify_tron_edge(e, post):
    tx = post("/wallet/gettransactionbyid", {"value": e["txid"]})
    if not tx or not tx.get("raw_data"):
        return ("mismatch", "transaction not found on the second node")
    ret = (tx.get("ret") or [{}])[0].get("contractRet")
    if ret != "SUCCESS":
        return ("mismatch", "transaction not successful (%s)" % ret)
    c = tx["raw_data"]["contract"][0]
    v, typ, b58, asset = c["parameter"]["value"], c["type"], acct_tracer.hex_to_tron, e.get("asset")
    if asset == "TRX":
        if typ != "TransferContract":
            return ("unsupported", "not a plain TRX transfer (%s)" % typ)
        ok = (b58(v["owner_address"]) == e["from"] and b58(v["to_address"]) == e["to"]
              and _eq(v["amount"] / 1e6, e["amount"]))
        res = ("ok", "") if ok else ("mismatch", "TRX transfer differs (sender, receiver or amount)")
    elif asset not in acct_tracer.STABLES["tron"].values():
        return ("unsupported", "token %s: not an officially known token" % asset)
    else:
        d = v.get("data", "")
        if typ != "TriggerSmartContract" or not d.startswith("a9059cbb") or len(d) < 136:
            return ("unsupported", "not a direct transfer() call, cannot decode")
        official = acct_tracer.STABLES["tron"].get(b58(v["contract_address"]))
        ok = (official == asset and b58(v["owner_address"]) == e["from"] and b58("41" + d[32:72]) == e["to"]
              and _eq(int(d[72:136], 16) / 10 ** ERC20_DEC[asset], e["amount"]))
        res = ("ok", "") if ok else ("mismatch", "token transfer differs (sender, receiver, amount or the "
                                                  "token contract is not the official %s)" % asset)
    if res[0] == "ok":
        blk = (post("/wallet/gettransactioninfobyid", {"value": e["txid"]}) or {}).get("blockNumber")
        now = ((post("/wallet/getnowblock", {}) or {}).get("block_header", {}).get("raw_data", {}) or {}).get("number")
        if blk and now and now - blk + 1 < MIN_CONF["tron"]:
            return ("recent", "only %d confirmations" % (now - blk + 1))
    return res


def cross_check_account(g, chain, second, limit, call=None):
    labeled = {a for a, n in g["nodes"].items() if n.get("label")}
    ranked = sorted(g["edges"], key=lambda e: (e["to"] in labeled, e.get("taint") or 0, amount(e)),
                    reverse=True)
    verify = (lambda e_, c_: verify_eth_edge(e_, c_, chain)) if chains.is_evm(chain) else verify_tron_edge
    call = call or (make_rpc(second) if chains.is_evm(chain) else make_post(second))
    res = {}
    for e in ranked[:limit]:
        try:
            st = verify(e, call)
        except Exception as ex:
            st = ("unavailable", str(ex)[:80])
        old = res.get(e["txid"])
        res[e["txid"]] = st if old is None or STATUS_ORDER.index(st[0]) < STATUS_ORDER.index(old[0]) else old
        time.sleep(DELAY)
    return res


# ---------------- graph audit ----------------
def parents(g):
    adj = defaultdict(list)
    for e in g["edges"]:
        adj[e["from"]].append(e)
    par, q = {g["start"]: None}, deque([g["start"]])
    while q:
        n = q.popleft()
        for e in adj[n]:
            if e["to"] not in par:
                par[e["to"]] = e
                q.append(e["to"])
    return par


def path_of(par, node):
    ids = []
    while par.get(node):
        ids.append(par[node]["txid"])
        node = par[node]["from"]
    return ids[::-1]


def label_of(labels, a):
    v = (labels or {}).get(a)
    if isinstance(v, dict) and (v.get("review") or {}).get("status") == "rejected":
        return None
    return (v.get("label") if isinstance(v, dict) else v) if v else None


def audit_graph(g, labels=None):
    F, nodes, edges = [], g["nodes"], g["edges"]
    key = lambda e: (e["from"], e["to"], e["txid"], e.get("asset"), round(amount(e), 12))
    for k, c in Counter(map(key, edges)).items():
        if c > 1:
            F.append(("WARN", "Possible duplicate edge %s -> %s in tx %s (x%d)" % (k[0], k[1], k[2], c)))
    for e in edges:
        if amount(e) <= 0:
            F.append(("FAIL", "Non-positive amount on edge in tx %s" % e["txid"]))
        if e["from"] not in nodes or e["to"] not in nodes:
            F.append(("FAIL", "Edge in tx %s points to an unknown node" % e["txid"]))
    if g.get("mode") == "taint":
        out = defaultdict(float)
        for e in edges:
            out[e["from"]] += e.get("taint") or 0
        for a, t in out.items():
            if t > (nodes.get(a, {}).get("taint") or 0) + 1e-6:
                F.append(("FAIL", "Taint conservation violated at %s: %.6f out > %.6f in" % (
                    a, t, nodes.get(a, {}).get("taint") or 0)))
    for a, n in nodes.items():
        if n.get("note"):
            F.append(("WARN", "Coverage gap at %s: %s" % (a, n["note"])))
        if n.get("label") and n.get("category") != "coinjoin" and (
                n.get("confidence") in (None, "low") or not n.get("source")):
            F.append(("WARN", "Weak label on %s (%s): confidence/source missing or low" % (a, n["label"])))
        v = (labels or {}).get(a)
        if isinstance(v, dict) and v.get("alt"):
            F.append(("WARN", "Conflicting labels for %s: %s vs %s" % (
                a, v["label"], "; ".join(x["label"] for x in v["alt"]))))
    maxd = max((n.get("depth", 0) for n in nodes.values()), default=0)
    out_from = {e["from"] for e in edges}
    frontier = [a for a, n in nodes.items() if n.get("depth") == maxd and maxd > 0 and a not in out_from
                and not n.get("label") and not n.get("note") and a not in {u["address"] for u in g.get("unspent", [])}]
    if frontier:
        F.append(("WARN", "%d addresses at the depth limit were not expanded: the trail may continue "
                          "(re-run with a larger depth)" % len(frontier)))
    for c in g.get("clusters", []):
        names = {label_of(labels, a) or nodes.get(a, {}).get("label") for a in c} - {None}
        if len(names) > 1:
            F.append(("FAIL", "Cluster holds addresses labeled as different entities (%s): clustering "
                              "or labels are wrong" % ", ".join(sorted(names))))
        elif len(names) == 1 and any(not (label_of(labels, a) or nodes.get(a, {}).get("label")) for a in c):
            F.append(("INFO", "Cluster of %d addresses contains one labeled address (%s): the others are "
                              "probably the same entity (inferred, medium confidence)" % (len(c), names.pop())))
        if len(c) > 20:
            F.append(("WARN", "Cluster of %d addresses is unusually large: possible service or CoinJoin leakage" % len(c)))
    if g.get("coinjoins"):
        F.append(("INFO", "%d CoinJoin-like transactions: trail ambiguous there and intentionally not followed" % g["coinjoins"]))
    if g.get("gaps"):
        F.append(("WARN", "%d output(s) have no standard address (e.g. bare multisig) and were not followed" % len(g["gaps"])))
    if g.get("truncated"):
        F.append(("WARN", "The trace stopped at the transaction limit: the trail continues beyond it"))
    if g.get("beyond_depth"):
        F.append(("WARN", "%d tainted output(s) were spent beyond the depth limit: the trail continues" % len(g["beyond_depth"])))
    return F


def key_findings(g):
    par, out = parents(g), []
    for a, n in g["nodes"].items():
        if n.get("label") and n.get("category") != "coinjoin" and a != g["start"] and a in par:
            ids = path_of(par, a)
            out.append({"node": a, "label": n["label"], "category": n.get("category"),
                        "confidence": n.get("confidence"), "source": n.get("source"),
                        "taint": n.get("taint"), "txids": ids, "hops": len(ids)})
    return out


def grade(k, ver):
    pts = {"high": 2, "medium": 1}.get(k["confidence"], 0)
    why = ["label confidence %s" % (k["confidence"] or "unknown")]
    stat = [(ver or {}).get(t, ("none",))[0] for t in k["txids"]]
    if "mismatch" in stat:
        return "D", ["a transaction on the path differs between data sources"]
    if stat and all(s == "ok" for s in stat):
        pts += 1
        why.append("every path transaction confirmed by a second source")
    else:
        why.append("path not fully confirmed by a second source")
    if k["hops"] > 3:
        pts -= 1
        why.append("long path (%d hops)" % k["hops"])
    return GRADE.get(pts, "A" if pts > 3 else "D"), why


# ---------------- report ----------------
def when(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "unknown"


def run_audit(g, labels, a):
    F = audit_graph(g, labels)
    ver, rec, second = None, None, a.second
    chain = g.get("chain", "btc")
    if a.archive:
        rec = Recorder(a.archive)
        install_recorder(rec)
    if a.no_network:
        F.append(("WARN", "Network checks were skipped: nothing was confirmed by a second source"))
    elif chain == "sol" or (chains.is_utxo(chain) and chain != "btc"):
        F.append(("WARN", "Second-source confirmation is not available for this network yet: nothing was confirmed by a second source"))
    elif chains.is_evm(chain) or chain == "tron":
        second = (getattr(a, "second_eth", None) if chain == "eth" else chains.get(chain)["rpc"] if chains.is_evm(chain)
                  else (getattr(a, "second_tron", None) or pick_independent_tron()))
        if not second:
            F.append(("WARN", "No second %s source configured (use --second-%s URL): nothing was confirmed "
                              "by a second source" % (chain, chain)))
        else:
            ver = cross_check_account(g, chain, second, a.max_check)
            for t, (st, d) in ver.items():
                if st == "mismatch":
                    F.append(("FAIL", "Transaction %s differs from the second source: %s" % (t, d)))
                elif st != "ok":
                    F.append(("WARN", "Transaction %s not fully confirmed (%s): %s" % (t, st, d)))
    else:
        ver = cross_check_btc(g, a.second, a.max_check)
        imp = [e["to"] for e in sorted(g["edges"], key=lambda e: -(e.get("taint") or 0)) if g["nodes"].get(e["to"], {}).get("label")]
        addrs = list(dict.fromkeys([g["start"]] + imp))
        recon = reconcile_btc(addrs)
        for t, (s, d) in ver.items():
            if s == "mismatch":
                F.append(("FAIL", "Transaction %s differs between providers (%s)" % (t, d)))
            elif s == "unavailable":
                F.append(("WARN", "Transaction %s could not be checked: %s" % (t, d)))
        for ad, (s, d) in recon.items():
            if s == "mismatch":
                F.append(("FAIL", "Totals for %s do not reconcile: %s" % (ad, d)))
            elif s == "unavailable":
                F.append(("WARN", "Address %s could not be reconciled: %s" % (ad, d)))
    levels = [x[0] for x in F]
    verdict = ("FAIL: do not rely on this result until the failures are resolved" if "FAIL" in levels else
               "PASS WITH WARNINGS" if "WARN" in levels else "PASS")
    kf = key_findings(g)
    times = [e["time"] for e in g["edges"] if e.get("time")]
    L = ["# Verification report", "",
         "Start: %s | Network: %s | Mode: %s" % (g["start"], chain, g.get("mode", "all")),
         "Generated: %s | Data as of: %s" % (when(int(time.time())), when(max(times)) if times else "unknown"),
         "", "**Verdict: %s**" % verdict]
    if ver is not None:
        c = Counter(s for s, _ in ver.values())
        L.append("Cross-check against %s: %s (of %d transactions)" % (
            second, ", ".join("%d %s" % (n, k) for k, n in sorted(c.items())) or "nothing checked", len(ver)))
    if rec:
        L.append("Raw responses archived in %s (%d entries); verify later with: python verify.py check-archive %s" % (
            a.archive, len(rec.items), a.archive))
    L += ["", "## Findings reaching known entities"]
    if not kf:
        L.append("- None reached a labeled entity within the traced depth.")
    for k in sorted(kf, key=lambda k: -(k["taint"] or 0)):
        gr, why = grade(k, ver)
        L.append("- **[%s]** %s (%s): %s%d hops. Basis: %s." % (
            gr, k["label"], k["category"] or "no category",
            "tainted %.4f, " % k["taint"] if k["taint"] else "", k["hops"], "; ".join(why)))
    L += ["", "Grades: A = strong, B = good, C = needs more evidence, D = do not use."]
    for lvl in ("FAIL", "WARN", "INFO"):
        items = [t for l, t in F if l == lvl]
        if items:
            L += ["", "## %s (%d)" % (lvl, len(items))] + ["- " + t for t in items[:40]]
    L += ["", "## Before this goes to the police or a court",
          "- Open each key address and transaction in a public block explorer and confirm it matches.",
          "- Confirm every exchange label from an independent source (the exchange's own published addresses).",
          "- Keep the evidence archive untouched and give its manifest hash to the investigator.",
          "- Treat clusters, taint and time-zone estimates as leads, not proof. State the method used.",
          "- Do not contact or accuse the wallet holder. Submit through law enforcement."]
    return "\n".join(L), verdict


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("audit")
    p.add_argument("graph")
    p.add_argument("--labels", default="labels.json")
    p.add_argument("--second", default="https://mempool.space/api", help="Bitcoin: second Esplora-compatible API")
    p.add_argument("--second-eth", default="https://ethereum-rpc.publicnode.com", help="Ethereum: second JSON-RPC node")
    p.add_argument("--second-tron", default=None, help="TRON: second full node (standard HTTP API), no default")
    p.add_argument("--max-check", type=int, default=40)
    p.add_argument("--archive", default=None)
    p.add_argument("--no-network", action="store_true")
    p.add_argument("--out", default="verification_report.md")
    p = sub.add_parser("check-archive")
    p.add_argument("folder")
    a = ap.parse_args()
    if a.cmd == "check-archive":
        probs = check_archive(a.folder)
        print("Archive intact." if not probs else "PROBLEMS:\n" + "\n".join(probs))
        sys.exit(1 if probs else 0)
    with open(a.graph, encoding="utf-8") as f:
        g = json.load(f)
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    text, verdict = run_audit(g, labels, a)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(text)
    sys.exit(1 if verdict.startswith("FAIL") else 0)


if __name__ == "__main__":
    main()
