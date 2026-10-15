#!/usr/bin/env python3
"""
live_check.py - run the tools against the REAL networks and report which of their assumptions hold. Python 3.8+.

    python live_check.py                       everything (Bitcoin, Ethereum, TRON, a site scan of example.com)
    python live_check.py --only btc            one section: btc | eth | tron | site
    python live_check.py --txid TXID --vout 0  also trace a Bitcoin payment you know (see the result with your own eyes)

Why it exists: every earlier test of these tools used fake data. The real providers can differ in field names,
limits or availability. This script needs no known "correct answer": it takes the newest transactions that exist
right now, runs the real code paths on them, and checks that each provider response has the shape the tools
rely on and that independent providers agree.

Each line is PASS, WARN (a feature that degrades gracefully), SKIP, or FAIL. It writes live_check_report.txt
(no keys, no personal data). If anything FAILs, paste that file to Claude and the tools can be fixed.

It makes a few dozen read-only requests to public endpoints. If a provider answers 429 (rate limit), wait a minute
or pass --api-key / --eth-rpc / --tron-node for your own provider.
"""
import argparse
import os
import platform
import re
import sys
import tempfile
import types
from datetime import datetime, timezone

import acct_tracer
import btc_tracer
import case_builder
import chains
import intake
import opreturn
import site_scan
import utxo_trace
import verify

PIZZA = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"  # widely cited 2010 transaction (optional bonus check)
RESULTS = []


class Skip(Exception):
    pass


class Warn(Exception):
    pass


def rec(section, name, status, detail=""):
    RESULTS.append((section, name, status, detail))
    print("%-5s [%s] %s%s" % (status, section, name, (" - " + detail) if detail else ""))


def check(section, name, fn):
    try:
        rec(section, name, "PASS", fn() or "")
    except Skip as e:
        rec(section, name, "SKIP", str(e))
    except Warn as e:
        rec(section, name, "WARN", str(e))
    except AssertionError as e:
        rec(section, name, "FAIL", "assertion failed: %s" % e)
    except Exception as e:
        rec(section, name, "FAIL", "%s: %s" % (type(e).__name__, str(e)[:240]))


def check_tx_shape(tx):
    assert isinstance(tx.get("status", {}).get("confirmed"), bool), "status.confirmed missing"
    assert tx.get("vin") and tx.get("vout"), "vin/vout missing"
    coinbase = bool(tx["vin"][0].get("is_coinbase"))
    for v in tx["vin"]:
        if v.get("is_coinbase"):
            continue
        pv = v.get("prevout") or {}
        assert "value" in pv and "scriptpubkey_type" in pv and "txid" in v and "vout" in v, "vin fields missing (prevout/txid/vout)"
    for o in tx["vout"]:
        assert "value" in o and "scriptpubkey_type" in o, "vout fields missing"
    if not coinbase:
        tin, tout = sum(v["prevout"]["value"] for v in tx["vin"]), sum(o["value"] for o in tx["vout"])
        assert tin >= tout, "outputs exceed inputs (%d > %d)" % (tout, tin)


# ---------------- Bitcoin ----------------
def btc(a):
    S, ctx = "bitcoin", {}

    def tip():
        h = btc_tracer.get("/blocks/tip/height")
        assert isinstance(h, int) and h > 100000, "unexpected tip: %r" % (h,)
        ctx["tip"] = h
        return "height %d" % h
    check(S, "tip height (primary provider)", tip)

    def tip2():
        h2 = verify.fetch_json(a.second.rstrip("/") + "/blocks/tip/height")
        assert isinstance(h2, int) and abs(h2 - ctx["tip"]) <= 3, "primary %s vs second %s" % (ctx.get("tip"), h2)
        return "second provider at %d" % h2
    check(S, "second provider is reachable and agrees on the tip", tip2)

    def recent():
        bh = verify.fetch_raw(btc_tracer.API + "/blocks/tip/hash").decode().strip()
        assert re.fullmatch(r"[0-9a-f]{64}", bh), "tip hash not hex: %r" % bh[:40]
        txs = btc_tracer.get("/block/%s/txs" % bh)
        assert isinstance(txs, list) and len(txs) >= 2, "block tx list missing"
        ctx["txs"] = txs
        ctx["tx"] = next(t for t in txs if not t["vin"][0].get("is_coinbase"))
        return "%d transactions in the newest block" % len(txs)
    check(S, "newest block and its transactions", recent)

    def shapes():
        for t in ctx["txs"][:10]:
            check_tx_shape(t)
        return "%d transactions have the fields the tools use and value is conserved" % min(10, len(ctx["txs"]))
    check(S, "transaction shape (prevout, scriptpubkey_type, status, conservation)", shapes)

    def agree():
        t = ctx["tx"]
        other = verify.fetch_json(a.second.rstrip("/") + "/tx/" + t["txid"])
        assert verify.norm_tx(t) == verify.norm_tx(other), "providers disagree about %s" % t["txid"]
        return "both providers return the same inputs and outputs"
    check(S, "second provider returns the same transaction", agree)

    def outspends():
        t = ctx["tx"]
        o = btc_tracer.get("/tx/%s/outspends" % t["txid"])
        assert isinstance(o, list) and len(o) == len(t["vout"]) and all("spent" in x for x in o), "outspends shape unexpected"
        return "one entry per output with a 'spent' flag"
    check(S, "outspends endpoint (needed by the UTXO tracer)", outspends)

    def address():
        addr = next(o["scriptpubkey_address"] for o in ctx["tx"]["vout"] if o.get("scriptpubkey_address"))
        info = btc_tracer.get("/address/" + addr)
        cs = info["chain_stats"]
        assert all(k in cs for k in ("funded_txo_sum", "spent_txo_sum", "tx_count")), "chain_stats keys missing"
        assert "mempool_stats" in info, "mempool_stats missing"
        txs, total = btc_tracer.address_txs(addr, 60)
        assert (txs is None and total > 60) or isinstance(txs, list), "address_txs returned something unexpected"
        bal = case_builder.fetch_balance("btc", addr)
        assert "BTC" in bal, "balance missing"
        return "address stats, history paging and balance work (%s)" % ("busy address, not expanded" if txs is None else "%d txs" % len(txs))
    check(S, "address endpoints (stats, history, balance)", address)

    def opr():
        n = sum(len(opreturn.scan_tx(t)) for t in ctx["txs"])
        return "%d OP_RETURN message(s) decoded in this block without error" % n
    check(S, "OP_RETURN decoding on real data", opr)

    base = {}

    def pizza():
        try:
            tx = btc_tracer.get("/tx/" + PIZZA)
        except Exception as e:
            if "404" in str(e):
                raise Skip("known historic transaction not found (my memory of its id may be wrong; not a tool error)")
            raise
        check_tx_shape(tx)
        assert tx["status"]["confirmed"], "historic transaction not confirmed?"
        base["txid"], base["tx"] = PIZZA, tx
        return "historic transaction found and well-formed"
    check(S, "historic transaction (bonus)", pizza)

    def trace():
        txid, tx = (base["txid"], base["tx"]) if base else (ctx["tx"]["txid"], ctx["tx"])
        vout = next(i for i, o in enumerate(tx["vout"]) if o.get("scriptpubkey_address"))
        g = utxo_trace.trace_outpoint(txid, vout, 2, {}, None, max_tx=30)
        assert g["start"] == tx["vout"][vout]["scriptpubkey_address"], "start address mismatch"
        assert all(e["taint"] <= e["btc"] + 1e-9 for e in g["edges"]), "taint exceeds the flow on an edge"
        bad = [t for l, t in verify.audit_graph(g, {}) if l == "FAIL"]
        assert not bad, "audit FAIL: %s" % bad[0]
        ctx["g"] = g
        return "%d addresses, %d transfers, %d unspent output(s), %d CoinJoin stop(s)" % (len(g["nodes"]), len(g["edges"]), len(g["unspent"]), g["coinjoins"])
    check(S, "UTXO trace on real data (invariants, audit)", trace)

    def cross():
        g = ctx.get("g")
        if not g or not g["edges"]:
            raise Skip("the trace has no transfers (recent outputs are unspent): try --txid with an older payment")
        res = verify.cross_check_btc(g, a.second, 5)
        st = [s for s, _ in res.values()]
        assert "mismatch" not in st, "providers disagree: %s" % [t for t, (s, d) in res.items() if s == "mismatch"]
        assert st.count("ok") > 0, "no transaction could be confirmed by the second provider"
        return "%d of %d confirmed by the second provider" % (st.count("ok"), len(st))
    check(S, "cross-check of the traced transactions", cross)

    if a.txid:
        def mine():
            res = intake.find(a.txid, "btc")
            cands = res["candidates"]
            vout = a.vout if a.vout is not None else cands[0]["vout"]
            g = utxo_trace.trace_outpoint(a.txid, vout, 4, {}, None, max_tx=80)
            return "receivers: %s | traced from output %d: %d addresses, %d transfers, %d unspent (open graph.json in the site to inspect)" % (
                ", ".join("%s %.8g" % (c["to"], c["amount"]) for c in cands), vout, len(g["nodes"]), len(g["edges"]), len(g["unspent"]))
        check(S, "your own transaction %s" % a.txid[:12], mine)


# ---------------- Ethereum ----------------
def eth(a):
    S, ctx = "ethereum", {}
    call = verify.make_rpc(a.eth_rpc)
    key = "?apikey=%s" % a.api_key if a.api_key else ""

    def head():
        n = int(call("eth_blockNumber", []), 16)
        assert n > 1000000, "unexpected block number %d" % n
        ctx["n"] = n
        return "block %d" % n
    check(S, "JSON-RPC node answers (second source)", head)

    def pick():
        blk = call("eth_getBlockByNumber", [hex(ctx["n"] - 20), True])
        assert blk and blk.get("transactions"), "block without transactions"
        for t in blk["transactions"][:40]:
            try:
                res = intake.find(t["hash"], "eth", call=call)
            except ValueError:
                continue
            ctx.update(res=res, frm=t["from"].lower(), hash=t["hash"])
            return "decoded %s with %d receiver(s)" % (t["hash"][:12], len(res["candidates"]))
        raise AssertionError("none of the first 40 transactions could be decoded")
    check(S, "intake decodes a real transaction (native ETH or USDT/USDC/DAI)", pick)

    def vedge():
        c, r = ctx["res"]["candidates"][0], ctx["res"]
        st, d = verify.verify_eth_edge({"from": c.get("from") or r["senders"][0], "to": c["to"], "txid": r["txid"], "asset": c["asset"], "amount": c["amount"]}, call)
        assert st in ("ok", "recent"), "second-source check says %s: %s" % (st, d)
        return "status %s" % st
    check(S, "second-source verification of that transfer", vedge)

    def shapes():
        d = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/" + ctx["frm"] + key)
        assert "coin_balance" in d, "address object has no coin_balance"
        t = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/%s/transactions%s" % (ctx["frm"], key))
        assert isinstance(t.get("items"), list), "transactions response has no 'items' list"
        for it in t["items"][:3]:
            assert all(k in it for k in ("hash", "from", "to", "value", "timestamp")), "transaction item fields missing"
            assert "hash" in (it["from"] or {}), "from.hash missing"
        tt = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/%s/token-transfers?type=ERC-20%s" % (ctx["frm"], key.replace("?", "&")))
        assert isinstance(tt.get("items"), list), "token-transfers response has no 'items' list"
        return "address, transactions and token-transfers have the expected shape"
    check(S, "Blockscout response shapes the tracer reads", shapes)

    def internal():
        try:
            d = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/%s/internal-transactions%s" % (ctx["frm"], key))
        except Exception as e:
            raise Warn("internal-transactions endpoint unavailable (%s): the tracer continues without internal transfers" % str(e)[:80])
        assert isinstance(d.get("items"), list), "internal-transactions response has no 'items' list"
        return "endpoint answers"
    check(S, "internal transactions endpoint (optional feature)", internal)

    def trace():
        args = types.SimpleNamespace(depth=1, min_stable=10, min_native=None, max_pages=2, max_fanout=10, all_tokens=False, api_key=a.api_key, internal=True)
        g = acct_tracer.trace("eth", ctx["frm"], args, {})
        bal = case_builder.fetch_balance("eth", ctx["frm"], a.api_key)
        assert g["start"] == ctx["frm"] and "ETH" in bal, "trace or balance failed"
        return "%d transfers followed; balance read" % len(g["edges"])
    check(S, "tracer and balance run on a real address", trace)


# ---------------- TRON ----------------
def tron(a):
    S, ctx = "tron", {}
    post = verify.make_post(a.tron_node)
    indep = verify.pick_independent_tron(a.tron_node)
    vpost = verify.make_post(indep) if indep else post
    hdr = {"TRON-PRO-API-KEY": a.api_key} if a.api_key else None

    def now():
        b = post("/wallet/getnowblock", {})
        n = b["block_header"]["raw_data"]["number"]
        assert n > 1000000 and isinstance(b.get("transactions", []), list), "unexpected block shape"
        ctx["n"], ctx["txs"] = n, b.get("transactions", [])
        return "block %d with %d transactions" % (n, len(ctx["txs"]))
    check(S, "full-node HTTP API answers (getnowblock)", now)

    def pick():
        for t in ctx["txs"]:
            try:
                res = intake.tron_intake(t["txID"], post)
            except ValueError:
                continue
            ctx["res"], ctx["frm"] = res, res["senders"][0]
            return "decoded %s: %s %s" % (t["txID"][:12], res["candidates"][0]["amount"], res["candidates"][0]["asset"])
        raise Skip("no TRX or USDT transfer in the newest block (run again in a few seconds)")
    check(S, "intake decodes a real TRX or USDT transfer", pick)

    def vedge():
        if "res" not in ctx:
            raise Skip("no decoded transfer")
        c, r = ctx["res"]["candidates"][0], ctx["res"]
        st, d = verify.verify_tron_edge({"from": r["senders"][0], "to": c["to"], "txid": r["txid"], "asset": c["asset"], "amount": c["amount"]}, vpost)
        assert st in ("ok", "recent"), "second-source check says %s: %s" % (st, d)
        return "status %s" % st
    check(S, "verification of that transfer", vedge)

    def shapes():
        if "frm" not in ctx:
            raise Skip("no decoded transfer")
        d = acct_tracer.http(acct_tracer.TRON_BASE + "/v1/accounts/" + ctx["frm"], hdr)
        assert isinstance(d.get("data"), list), "account response has no 'data' list"
        t = acct_tracer.http(acct_tracer.TRON_BASE + "/v1/accounts/%s/transactions/trc20?limit=5" % ctx["frm"], hdr)
        assert isinstance(t.get("data"), list), "trc20 response has no 'data' list"
        for it in t["data"][:3]:
            assert all(k in it for k in ("transaction_id", "from", "to", "value", "token_info", "block_timestamp")), "trc20 item fields missing"
        return "account and TRC20 history have the expected shape"
    check(S, "TronGrid response shapes the tracer reads", shapes)

    def tronscan():
        if "frm" not in ctx:
            raise Skip("no decoded transfer")
        try:
            d = acct_tracer.http("https://apilist.tronscanapi.com/api/account?address=" + ctx["frm"])
        except Exception as e:
            raise Warn("TronScan account endpoint unavailable (%s): identity falls back to the other sources" % str(e)[:80])
        if not isinstance(d, dict) or d.get("address") != ctx["frm"]:
            raise Warn("TronScan answered in a shape the identity engine does not expect (no matching 'address'): its tags will be ignored")
        return "account endpoint answers with the expected address field%s" % (" and a name tag" if d.get("name") or d.get("addressTag") else "")
    check(S, "TronScan account endpoint (identity evidence, optional)", tronscan)

    def trace():
        if "frm" not in ctx:
            raise Skip("no decoded transfer")
        args = types.SimpleNamespace(depth=1, min_stable=10, min_native=None, max_pages=2, max_fanout=10, all_tokens=False, api_key=a.api_key)
        g = acct_tracer.trace("tron", ctx["frm"], args, {})
        bal = case_builder.fetch_balance("tron", ctx["frm"], a.api_key)
        assert g["start"] == ctx["frm"] and "TRX" in bal, "trace or balance failed"
        return "%d transfers followed; balance read" % len(g["edges"])
    check(S, "tracer and balance run on a real address", trace)
    if indep:
        rec(S, "independence of the second source", "PASS", "verification used an independent node: %s" % indep)
    else:
        rec(S, "independence of the second source", "WARN", "no independent TRON node answered (tried %s); verification used the same provider as the tracer. Pass --second-tron URL." % ", ".join(verify.INDEPENDENT_TRON_NODES))


# ---------------- website scan ----------------
def site(a):
    def scan():
        with tempfile.TemporaryDirectory() as d:
            out = site_scan.scan("https://example.com", 1, d, None, False)
        assert out["tier"] == "LOW" and out["domain"] == "example.com", "unexpected result for the IANA example domain"
        assert "تقرير فحص موقع" in out["report"], "report missing"
        return "fetched, assessed and reported (tier %s); no wallets expected: %d found" % (out["tier"], len(out["addresses"]))
    def scan_or_skip():
        try:
            return scan()
        except ValueError as e:
            if "does not resolve" in str(e):
                raise Skip("this computer's DNS cannot resolve example.com (%s); the scanner itself is covered by the offline tests" % str(e).split(": ")[-1][:60])
            raise
    check("site", "scan of example.com (safe, reserved by IANA)", scan_or_skip)



# ---------------- experimental networks (a failure here is a WARN with the details to send for correction) ----------------
def xcheck(section, name, fn):
    def wrapped():
        try:
            return fn()
        except (Skip, Warn):
            raise
        except Exception as e:
            raise Warn("EXPERIMENTAL, not working yet: %s: %s" % (type(e).__name__, str(e)[:200]))
    check(section, name, wrapped)


def evm(a):
    for ch in ("bsc", "polygon", "arbitrum", "base"):
        S = ch
        cfg = chains.get(ch)

        def rpc_ok(cfg=cfg):
            n = int(verify.make_rpc(cfg["rpc"])("eth_blockNumber", []), 16)
            assert n > 1000000, "unexpected block number %r" % n
            return "block %d" % n
        xcheck(S, "public RPC node answers (eth_blockNumber)", rpc_ok)

        def prov(ch=ch):
            import evm_api
            contract = next(iter(chains.get(ch)["stables"]))
            call = verify.make_rpc(chains.get(ch)["rpc"])
            n = int(call("eth_blockNumber", []), 16)
            logs = call("eth_getLogs", [{"fromBlock": hex(n - 40), "toBlock": hex(n - 2), "address": contract, "topics": [verify.TRANSFER_TOPIC]}])
            assert logs, "no recent stablecoin transfer found through the RPC node to use as a test address"
            holder = "0x" + logs[-1]["topics"][1][-40:]
            info = evm_api.address_info(ch, holder, a.api_key)
            assert "coin_balance" in info, "no coin_balance in the address answer"
            items, _ = evm_api.pages(ch, "/addresses/%s/token-transfers" % holder, {"type": "ERC-20"}, a.api_key, 1)
            assert items, "no token transfers returned for a real holder address"
            t = items[0]
            assert (t.get("from") or {}).get("hash") and (t.get("to") or {}).get("hash") and t.get("transaction_hash") and (t.get("total") or {}).get("value") is not None, "transfer fields missing"
            return "%d transfers; provider shape is what the tools expect" % len(items)
        def prov_or_key(prov=prov):
            try:
                return prov()
            except AssertionError:
                raise
            except Exception as e:
                if not os.environ.get("ETHERSCAN_API_KEY") and "ETHERSCAN_API_KEY" in str(e):
                    raise Skip("no free history provider answers from here (Blockscout blocks scripts); set a free ETHERSCAN_API_KEY to use this network")
                raise
        xcheck(S, "history provider answers in the shape the tools use", prov_or_key)


def utxo_new(a):
    S = "litecoin"

    def ltc():
        with btc_tracer.use_chain("ltc"):
            h = btc_tracer.get("/blocks/tip/height")
            assert isinstance(h, int) and h > 100000, "unexpected tip %r" % (h,)
            bh = verify.fetch_raw(chains.get("ltc")["api"] + "/blocks/tip/hash").decode().strip()
            txs = btc_tracer.get("/block/%s/txs" % bh)
            for t in txs[:5]:
                check_tx_shape(t)
            o = btc_tracer.get("/tx/%s/outspends" % txs[-1]["txid"])
            assert isinstance(o, list) and all("spent" in x for x in o), "outspends shape unexpected"
        return "height %d, %d transactions have the expected shape" % (h, len(txs))
    xcheck(S, "Esplora-style provider answers (tip, block, transactions, outspends)", ltc)
    for ch in ("doge", "bch"):
        def shim(ch=ch):
            import utxo_shim
            h = utxo_shim.get(ch, "/blocks/tip/height")
            assert isinstance(h, int) and h > 100000, "unexpected tip %r" % (h,)
            return "height %d (transaction shape is checked only with --txid on that network)" % h
        xcheck(ch, "Blockchair adapter answers (tip height)", shim)


def sol(a):
    S = "solana"

    def go():
        import sol_api
        mint = next(iter(chains.get("sol")["stables"]))
        sigs = sol_api.rpc("getSignaturesForAddress", [mint, {"limit": 3}])
        assert sigs and sigs[0].get("signature"), "no signatures returned"
        tx = None
        for sg in sigs:
            tx = sol_api.get_tx(sg["signature"])
            if tx:
                break
        assert tx and tx.get("meta") and tx["transaction"]["message"]["accountKeys"], "transaction shape unexpected"
        n = len(sol_api.transfers(tx, sigs[0]["signature"]))
        return "transaction decoded, %d transfers read from balance changes" % n
    xcheck(S, "JSON-RPC answers and a real transaction can be decoded", go)


def run(a, sections=None):
    del RESULTS[:]
    sections = sections or ["btc", "eth", "tron", "evm", "utxo", "sol", "site"]
    for name, fn in (("btc", btc), ("eth", eth), ("tron", tron), ("evm", evm), ("utxo", utxo_new), ("sol", sol), ("site", site)):
        if name in sections:
            print("\n== %s ==" % name)
            fn(a)
    counts = {s: sum(1 for r in RESULTS if r[2] == s) for s in ("PASS", "WARN", "SKIP", "FAIL")}
    print("\nPASS %(PASS)d | WARN %(WARN)d | SKIP %(SKIP)d | FAIL %(FAIL)d" % counts)
    text = ["live_check report", "date: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "python: %s | %s" % (sys.version.split()[0], platform.platform()), ""]
    for section, name, status, detail in RESULTS:
        text.append("%-5s [%s] %s%s" % (status, section, name, (" - " + detail) if detail else ""))
    text += ["", "PASS %(PASS)d | WARN %(WARN)d | SKIP %(SKIP)d | FAIL %(FAIL)d" % counts,
             "If anything says FAIL, paste this whole file to Claude."]
    report = "\n".join(text)
    if a.api_key:
        report = report.replace(a.api_key, "***")
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(report)
    print("report written to", a.out)
    if counts["FAIL"] and not counts["PASS"]:
        print("Nothing passed: check that this computer is online (and not behind a proxy or firewall) before reading anything into it.")
    elif counts["FAIL"]:
        print("Some checks FAILED: paste %s to Claude and the tools can be fixed." % a.out)
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", choices=["btc", "eth", "tron", "evm", "utxo", "sol", "site"])
    ap.add_argument("--second", default="https://mempool.space/api", help="second Bitcoin provider (Esplora-compatible)")
    ap.add_argument("--eth-rpc", default="https://ethereum-rpc.publicnode.com")
    ap.add_argument("--tron-node", default=acct_tracer.TRON_BASE)
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    ap.add_argument("--txid", help="a Bitcoin payment you know: it is decoded and traced so you can inspect the result")
    ap.add_argument("--vout", type=int, default=None)
    ap.add_argument("--out", default="live_check_report.txt")
    ap.add_argument("--record", metavar="DIR", help="record the real provider answers into DIR and make DIR.zip to send for fixing")
    ap.add_argument("--replay", metavar="DIR", help="run offline against a recording made with --record")
    a = ap.parse_args()
    import capture
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if a.record and a.replay:
        sys.exit("اختر --record أو --replay وليس الاثنين.")
    if a.record:
        cap = capture.Capture(a.record)
        with cap:
            counts = run(a, a.only)
        print("\nسُجّل %d ردًّا في %s؛ أرسل الملف: %s" % (len(cap.items), a.record, capture.pack(a.record)))
        sys.exit(1 if counts["FAIL"] else 0)
    if a.replay:
        rp = capture.Replay(a.replay)
        with rp:
            counts = run(a, a.only)
        if rp.misses:
            print("\nطلبات غير موجودة في التسجيل: %d" % len(set(rp.misses)))
        sys.exit(1 if counts["FAIL"] else 0)
    counts = run(a, a.only)
    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
