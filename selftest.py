#!/usr/bin/env python3
"""
selftest.py - offline self-test. No internet needed, writes nothing to this folder.

    python selftest.py

Runs every module against fake data and prints PASS/FAIL for each check.
If all lines say PASS, the files are intact and ready for real use.
"""
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import types
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
FAILS = []


def _raises(fn):
    try:
        fn()
    except (ValueError, RuntimeError):
        return True
    return False


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        FAILS.append(name)


def section(fn):
    try:
        fn()
    except Exception:
        FAILS.append(fn.__name__)
        print("FAIL  %s crashed:\n%s" % (fn.__name__, traceback.format_exc()))


def mktx(i, ins, outs, ts=1700000000):
    return {"txid": i, "version": 2, "locktime": 0, "status": {"block_time": ts, "confirmed": True},
            "vin": [{"sequence": 0xfffffffd, "prevout": {"scriptpubkey_address": a, "value": v}} for a, v in ins],
            "vout": [{"scriptpubkey_address": a, "value": v, "scriptpubkey_type": "v0_p2wpkh"} for a, v in outs]}


def t_bitcoin():
    import btc_tracer as b
    S, M, EX, V = "S", "M", "EX", "V"
    t0, t1, t2 = (mktx("t0", [(V, 10**8)], [(S, 10**8)]), mktx("t1", [(S, 10**8)], [(EX, 5 * 10**7), (M, 49 * 10**6)]),
                  mktx("t2", [(M, 49 * 10**6)], [(EX, 48 * 10**6)]))
    DB = {S: [t0, t1], M: [t1, t2], EX: []}
    b.get = lambda p: ({"chain_stats": {"tx_count": len(DB[p.split("/")[2]])}, "mempool_stats": {"tx_count": 0}}
                       if p == "/address/" + p.split("/")[2] else DB[p.split("/")[2]])
    b.DELAY = 0
    lab = {EX: {"label": "Demo Exchange", "category": "exchange", "source": "t", "confidence": "high"}}
    g = b.trace(S, 3, 200, 0.001, lab, taint=True, stolen=0.6)
    check("bitcoin: taint reaches the exchange (0.588 BTC)", abs(g["nodes"][EX]["taint"] - 0.588) < 1e-6)
    ins, outs = list("ABCDE"), list("FGHIJ")
    cj = mktx("cj", [(a, 10**7) for a in ins], [(a, 10**7) for a in outs])
    b.get = lambda p: ({"chain_stats": {"tx_count": 1}, "mempool_stats": {"tx_count": 0}} if p == "/address/A" else [cj])
    g = b.trace("A", 3, 200, 0.001, {})
    check("bitcoin: CoinJoin is not clustered and the trail stops", g["clusters"] == [] and g["coinjoins"] == 1)


def t_labels():
    import labels_tool as lt
    check("labels: address formats (btc, eth, tron)", lt.norm("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
          and lt.norm("0x" + "A" * 40) == "0x" + "a" * 40 and lt.norm("TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy")
          and lt.norm("garbage") is None)
    db = {}
    lt.merge(db, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "Ex A", "exchange", "s1", "medium")
    lt.merge(db, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "Ex B", "exchange", "s2", "high")
    v = db["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"]
    check("labels: higher confidence wins, conflict kept", v["label"] == "Ex B" and v["alt"][0]["label"] == "Ex A")
    with tempfile.TemporaryDirectory() as d:
        x = os.path.join(d, "sdn.xml")
        open(x, "w").write('<l xmlns="u"><sdnEntry><lastName>DEMO</lastName><idList><id>'
                           "<idType>Digital Currency Address - ETH</idType>"
                           "<idNumber>0x1111111111111111111111111111111111111111</idNumber></id></idList></sdnEntry></l>")
        check("labels: OFAC XML import", [a for a, _ in lt.ofac_entries(x)] == ["0x" + "1" * 40])


def t_account_chains():
    import acct_tracer as at
    check("tron: hex to base58 conversion", at.hex_to_tron("41a614f803b6fd780986a42c78ec9c7f77e6ded13c")
          == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
    A, B = "0x" + "a" * 40, "0x" + "b" * 40
    at.DELAY = 0
    at.http = lambda url, h=None: ({"items": [{"from": {"hash": A}, "to": {"hash": B}, "value": str(3 * 10**18),
                                               "hash": "0xe1", "status": "ok", "timestamp": "t"}]}
                                   if ("/addresses/%s/transactions" % A) in url else {"items": []})
    a = types.SimpleNamespace(depth=2, min_stable=10, min_native=None, max_pages=4, max_fanout=30,
                              all_tokens=False, api_key=None)
    g = at.trace("eth", A, a, {})
    check("ethereum: outgoing ETH transfer followed", len(g["edges"]) == 1 and g["edges"][0]["amount"] == 3.0)


def t_profile():
    import wallet_profile as w
    rows = []
    for d in range(10):
        for h in (6, 8, 10, 12):
            t = 1700000000 - (1700000000 % 86400) + d * 86400 + h * 3600
            rows += [w.row("in", "c1", "USDT", 100, "i%d%d" % (d, h), t), w.row("out", "c2", "USDT", 100, "o%d%d" % (d, h), t + 600)]
    m = w.analyze(rows, {})
    check("profile: daily rhythm and pass-through detected", m["tz"]["reliable"] and m["pass_through"])
    check("profile: report renders with the legal-route annex", "Annex" in w.build_report("eth", "0xabc", m, {}))


def t_verify():
    import verify as v
    v.DELAY = 0
    g = {"start": "S", "chain": "btc", "mode": "all", "coinjoins": 0,
         "nodes": {"S": {"depth": 0}, "A": {"depth": 1, "label": "X1", "category": "exchange", "source": "t", "confidence": "high"},
                   "B": {"depth": 1, "label": "X2", "category": "exchange", "source": "t", "confidence": "high"}},
         "edges": [{"from": "S", "to": "A", "txid": "t1", "btc": 1.0}], "clusters": [["A", "B"]]}
    check("verify: cluster with two different entities is a FAIL",
          any(l == "FAIL" and "different entities" in t for l, t in v.audit_graph(g, {})))
    with tempfile.TemporaryDirectory() as d:
        rec = v.Recorder(os.path.join(d, "ev"))
        rec.record("http://x?apikey=SECRET", b'{"a":1}')
        intact = v.check_archive(os.path.join(d, "ev")) == []
        open(os.path.join(d, "ev", rec.items[0]["file"]), "wb").write(b"{}")
        check("verify: archive intact, then tampering detected",
              intact and v.check_archive(os.path.join(d, "ev")) != [] and "SECRET" not in json.dumps(rec.items))
    A, B = "0x" + "a" * 40, "0x" + "b" * 40
    call = lambda m, p: (hex(200) if m == "eth_blockNumber" else
                         {"from": A, "to": B, "value": hex(10**18)} if m == "eth_getTransactionByHash"
                         else {"status": "0x1", "blockNumber": hex(100), "logs": []})
    st = v.verify_eth_edge({"from": A, "to": B, "txid": "0x1", "asset": "ETH", "amount": 1.0}, call)
    bad = v.verify_eth_edge({"from": A, "to": B, "txid": "0x1", "asset": "ETH", "amount": 2.0}, call)
    check("verify: second-source check accepts a match and rejects a different amount",
          st[0] == "ok" and bad[0] == "mismatch")


def t_case():
    import btc_tracer as b
    import case_builder as cb
    import watch
    cb.DELAY = b.DELAY = 0
    S, M, EX, V = "1" + "S" * 33, "1" + "M" * 33, "1" + "E" * 33, "1" + "V" * 33
    t0, t1 = (mktx("t0", [(V, 10**8)], [(S, 10**8)]), mktx("t1", [(S, 10**8)], [(EX, 5 * 10**7), (M, 49 * 10**6)]))
    DB = {S: [t0, t1], M: [t1], EX: []}
    FUND = {S: (10**8, 10**8), M: (49 * 10**6, 0), EX: (5 * 10**7, 0)}

    def get(p):
        a = p.split("/")[2]
        if p == "/address/" + a:
            return {"chain_stats": {"tx_count": len(DB[a]), "funded_txo_sum": FUND[a][0], "spent_txo_sum": FUND[a][1]},
                    "mempool_stats": {"tx_count": 0}}
        return DB[a]
    b.get = get
    lab = {EX: {"label": "Demo Exchange", "category": "exchange", "source": "OFAC", "confidence": "high"}}
    with tempfile.TemporaryDirectory() as root:
        out = cb.run_case("btc", S, 3, 0.6, lab, os.path.join(root, "cases"), {"victim": "Test Victim", "report_no": "77/2026"})
        files = os.listdir(out["folder"])
        check("case: report, letters, freeze list and graph are written",
              {"summary.md", "police_report.md", "freeze_targets.csv", "graph.json",
               "exchange_notice_demo_exchange.md"} <= set(files))
        check("ledger: building a case records the platforms reached and writes evidence_ledger.md in the case folder",
              os.path.exists(os.path.join(root, "ledger.db")) and "evidence_ledger.md" in files and out.get("case_id"))
        groups = cb.classify(out["graph"], {M: {"BTC": 0.49}})
        check("case: money split into 'reached exchange' and 'still in a wallet'",
              [i["address"] for i in groups["EXCHANGE"]] == [EX] and [i["address"] for i in groups["HOLDING"]] == [M])
        check("case: letter carries the victim details and report number",
              "Test Victim" in out["letters"]["exchange_notice_demo_exchange.md"]
              and "77/2026" in out["letters"]["exchange_notice_demo_exchange.md"])
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bals = [{"BTC": 0.49}, {"BTC": 0.0}]
            st = {}
            watch.check("btc", [M], st, fetch=lambda c, a, k=None: bals.pop(0))
            alerts = watch.check("btc", [M], st, fetch=lambda c, a, k=None: bals.pop(0))
        finally:
            os.chdir(cwd)
        check("watch: alert fires when the balance moves out", len(alerts) == 1 and "MOVED OUT" in alerts[0])


def t_sites():
    import labels_tool as lt
    import site_scan as ss
    ss.DELAY = 0
    gen, bad = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
    eth = "0x" + "AB" * 20
    found = ss.find_addresses("a %s b %s c %s" % (gen, bad, eth))
    check("sites: only checksum-valid wallets are extracted", set(found) == {gen, eth.lower()})
    pages = {"https://scam.example/": '<title>Profit Bank</title><a href="/deposit">d</a>',
             "https://scam.example/deposit": "Guaranteed profit. Daily profit. Withdrawal fee. Send to %s %s "
                                             "<a href='https://t.me/FakeSupport99'>s</a>" % (gen, eth)}
    ss.get_page = lambda u: pages[u].encode() if u in pages else None
    ss.resolve = lambda h: ["93.184.216.34"]
    ss.tls_info = lambda h: {}
    ss.rdap = lambda d: {"created": "2026-09-25"}
    with tempfile.TemporaryDirectory() as base:
        lab = os.path.join(base, "labels.json")
        out = ss.scan("https://scam.example/", 8, base, lab)
        db = lt.load(lab)
        check("sites: scam indicators score HIGH and the wallets get labeled", out["tier"] == "HIGH"
              and db[gen]["category"] == "scam" and bad not in db)
    ss.resolve = lambda h: ["127.0.0.1"]
    try:
        ss.check_url("http://localhost/")
        blocked = False
    except ValueError:
        blocked = True
    check("sites: local/private addresses are refused (SSRF protection)", blocked)


def t_intake_and_inference():
    import urllib.error
    import acct_tracer as at
    import btc_tracer as b
    import case_builder as cb
    import enrich
    import intake
    import verify as v
    V, SC, CH = "1" + "V" * 33, "1" + "S" * 33, "1" + "C" * 33
    b.get = lambda p: {"status": {"block_time": 1700000000}, "vin": [{"prevout": {"scriptpubkey_address": V, "value": 100}}],
                       "vout": [{"scriptpubkey_address": SC, "value": 80}, {"scriptpubkey_address": CH, "value": 15}]}
    r = intake.find("a" * 64, "btc")
    check("intake: Bitcoin payment lists the receiver and the change", r["candidates"][0]["to"] == SC and len(r["candidates"]) == 2)
    A, B2 = "0x" + "a" * 40, "0x" + "b" * 40
    usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7"

    def call(m, p):
        if m == "eth_getTransactionByHash":
            return {"from": A, "to": usdt, "value": "0x0"}
        if m == "eth_getTransactionReceipt":
            return {"status": "0x1", "blockNumber": "0x64", "logs": [{"address": usdt, "data": hex(2500 * 10**6), "topics": [
                v.TRANSFER_TOPIC, "0x" + "0" * 24 + A[2:], "0x" + "0" * 24 + B2[2:]]}]}
        return {"timestamp": hex(1700000000)}
    r = intake.find("0x" + "c" * 64, "auto", call=call)
    check("intake: Ethereum USDT payment decoded", r["candidates"] == [{"to": B2, "asset": "USDT", "from": A, "amount": 2500.0}])
    O, D = "41" + "11" * 20, "41" + "22" * 20
    post = lambda path, body: {"ret": [{"contractRet": "SUCCESS"}], "raw_data": {"timestamp": 1700000000000, "contract": [
        {"type": "TransferContract", "parameter": {"value": {"owner_address": O, "to_address": D, "amount": 5_000_000}}}]}}

    def b404(p):
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)
    b.get = b404
    r = intake.find("d" * 64, "auto", post=post)
    check("intake: a 64-hex hash unknown to Bitcoin falls back to TRON", r["chain"] == "tron" and r["candidates"][0]["amount"] == 5.0)
    g = {"start": "S", "chain": "btc", "mode": "all",
         "nodes": {"S": {"depth": 0}, "A": {"depth": 1}, "H": {"depth": 2, "label": "Demo Exchange", "category": "exchange",
                                                              "source": "OFAC", "confidence": "high"}},
         "edges": [{"from": "S", "to": "A", "txid": "t1", "btc": 1.0}, {"from": "A", "to": "H", "txid": "t2", "btc": 0.99}],
         "clusters": []}
    cb.infer_labels(g)
    check("inference: an address that sends everything to an exchange is a likely deposit address (low confidence)",
          g["nodes"]["A"]["label"] == "Demo Exchange" and g["nodes"]["A"]["confidence"] == "low")
    check("enrich: provider answer is stored with low confidence", enrich.parse_headline("Verified Binance (exchange)") == ("Binance", "exchange"))


def t_advanced():
    import acct_tracer as at
    import operation as op
    import patterns as pt
    import verify as v
    import watch
    T = 1700000000
    nodes, edges = {"S": {"depth": 0}, "D": {"depth": 2}}, []
    for i in range(10):
        m = "M%d" % i
        nodes[m] = {"depth": 1}
        edges += [{"from": "S", "to": m, "txid": "a%d" % i, "btc": 1.0, "time": T},
                  {"from": m, "to": "D", "txid": "b%d" % i, "btc": 0.99, "time": T + 600}]
    res = pt.analyze({"start": "S", "nodes": nodes, "edges": edges, "clusters": []})
    kinds = {f["type"] for f in res["findings"]}
    check("patterns: split into 10 wallets then merged is detected (HIGH, explainable)",
          {"FAN_OUT", "SPLIT_MERGE", "FAN_IN"} <= kinds and res["tier"] == "HIGH")
    calm = {"start": "S", "nodes": {"S": {"depth": 0}, "A": {"depth": 1}},
            "edges": [{"from": "S", "to": "A", "txid": "t", "btc": 1.0, "time": T}], "clusters": []}
    check("patterns: an ordinary transfer is LOW", pt.analyze(calm)["tier"] == "LOW")
    rows = [{"dir": "in", "other": "P%d" % i, "asset": "USDT", "amount": 100.0, "txid": "t%d" % i, "ts": T + i * 86400}
            for i in range(6)]
    o = op.analyze(rows, {})
    check("operation: 6 distinct payers are counted as a collection pattern", o["payers"] == 6 and o["totals"]["USDT"] == 600)
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "c.db")
        g = {"start": "S", "nodes": {"S": {}}, "edges": []}
        op.add_case(db, "c1", g)
        op.add_case(db, "c2", g)
        check("store: an address seen in two cases is linked", op.shared(db)[0][1] == 2)
    A, B2 = "0x" + "a" * 40, "0x" + "b" * 40
    _keep_pages = at.eth_pages
    at.eth_pages = lambda path, params, key, mx: (
        ([{"from": {"hash": A}, "to": {"hash": B2}, "value": str(2 * 10**18), "success": True,
           "transaction_hash": "0xi", "timestamp": "t"}], False) if "internal" in path else ([], False))
    out, _ = at.eth_out(A, types.SimpleNamespace(api_key=None, max_pages=2, all_tokens=False, internal=True))
    at.eth_pages = _keep_pages
    check("ethereum: internal (contract) transfers are followed and flagged for verification",
          out[0]["internal"] and v.verify_eth_edge(out[0], lambda m, p: None)[0] == "unsupported")
    W, D = "1" + "W" * 33, "1" + "D" * 33
    get = lambda p: [{"txid": "pend", "vin": [{"prevout": {"scriptpubkey_address": W}}],
                      "vout": [{"scriptpubkey_address": D, "value": 5 * 10**7}]}]
    st = {}
    check("watch: an unconfirmed (mempool) spend is reported once, with its destination",
          len(watch.pending_btc(W, st, get)) == 1 and watch.pending_btc(W, st, get) == [])


def t_utxo():
    import btc_tracer as b
    import utxo_trace as ut
    import verify as v
    V, S, X, EX, M, U = ["1" + c * 33 for c in "VSXEMU"]
    B = 10**8

    def vin(txid, vout, a, val):
        return {"txid": txid, "vout": vout, "prevout": {"scriptpubkey_address": a, "value": val, "scriptpubkey_type": "p2pkh"}}

    def vo(a, val):
        return {"scriptpubkey_address": a, "value": val, "scriptpubkey_type": "p2pkh"}

    def tx(i, vins, vouts, h):
        return {"txid": i, "version": 2, "locktime": 0, "status": {"confirmed": True, "block_height": h, "block_time": 1700000000 + h},
                "vin": vins, "vout": vouts}
    TX = {"V0": tx("V0", [vin("P0", 0, V, 5 * B)], [vo(S, B), vo("1" + "C" * 33, int(3.9 * B))], 90),
          "T1": tx("T1", [vin("V0", 0, S, B), vin("X0", 0, X, 3 * B)], [vo(EX, 2 * B), vo(M, int(1.9 * B)), vo(U, int(0.09 * B))], 95),
          "T2": tx("T2", [vin("T1", 1, M, int(1.9 * B))], [vo(EX, int(1.89 * B))], 99)}
    OUT = {"V0": [{"spent": True, "txid": "T1"}, {"spent": False}],
           "T1": [{"spent": False}, {"spent": True, "txid": "T2"}, {"spent": False}], "T2": [{"spent": False}]}
    b.get = lambda p: (100 if p == "/blocks/tip/height" else OUT[p.split("/")[2]] if p.endswith("/outspends") else TX[p.split("/")[2]])
    lab = {EX: {"label": "Demo Exchange", "category": "exchange", "source": "OFAC", "confidence": "high"}}
    g = ut.trace_outpoint("V0", 0, 6, lab, 0.6)
    check("utxo: tainted amount reaching the exchange is a range (0.5835 estimate, 3.89 upper bound)",
          abs(g["nodes"][EX]["taint"] - 0.5835) < 1e-6 and abs(g["nodes"][EX]["taint_max"] - 3.89) < 1e-6)
    check("utxo: the unspent tainted output is found exactly", len(g["unspent"]) == 1 and g["unspent"][0]["address"] == U)
    check("utxo: taint is conserved (audit has no FAIL)", not any(l == "FAIL" for l, _ in v.audit_graph(g, lab)))
    cj = tx("CJ", [vin("V0", 0, S, B)] + [vin("Z%d" % i, 0, "1" + "ABCD"[i] * 33, B) for i in range(4)],
            [vo("1" + c * 33, B) for c in "FGHIJ"], 96)
    TX["CJ"] = cj
    OUT["V0"][0] = {"spent": True, "txid": "CJ"}
    g3 = ut.trace_outpoint("V0", 0, 6, {}, None)
    check("utxo: a CoinJoin stops the trace and creates no false cluster", g3["coinjoins"] == 1 and g3["clusters"] == [])


def t_deep_bitcoin():
    import clusters as cl
    import opreturn as orr
    import reports_check as rc
    import wallet_profile as w

    def ev(txid, ins):
        return {"txid": txid, "inputs": sorted(ins), "types": ["v0_p2wpkh"], "fp": {"version": 2, "locktime": False, "rbf": True}}
    g = {"nodes": {"X1": {"label": "Demo Exchange", "category": "exchange"}},
         "cluster_evidence": [ev("t1", ["A", "B"]), ev("t2", ["B", "C"]), ev("t3", ["A", "C"]),
                              ev("b1", ["P%d" % i for i in range(25)]), ev("s1", ["X1", "Y1"])]}
    info = cl.compute(g, {})
    pers = next(c for c in info if set(c["members"]) == {"A", "B", "C"})
    svc = next(c for c in info if "X1" in c["members"])
    flat = {a for c in g["clusters"] for a in c}
    check("clusters: a wallet linked by 3 independent transactions is HIGH confidence", pers["confidence"] == "high")
    check("clusters: a cluster containing an exchange is typed as a service and never used as 'same owner'",
          svc["type"] == "service-likely" and "X1" not in flat)
    check("clusters: a 25-input transaction (service sweep) is excluded", g["cluster_skipped"] == 1 and "P0" not in flat)

    def script(data):
        n = len(data)
        return (bytes([0x6a, n]) if n <= 75 else bytes([0x6a, 0x4c, n])).hex() + data.hex()
    txt = b"Invest now https://scam.example/x t.me/FakeSupport99"
    omni = b"omni" + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + (31).to_bytes(4, "big") + (150 * 10**8).to_bytes(8, "big")
    m = orr.scan_tx({"txid": "tx1", "vout": [{"scriptpubkey_type": "op_return", "scriptpubkey": script(txt)},
                                             {"scriptpubkey_type": "op_return", "scriptpubkey": script(omni)},
                                             {"scriptpubkey_type": "op_return", "scriptpubkey": "zz"}]})
    check("opreturn: a link and a Telegram handle written into a transaction are extracted",
          m[0]["urls"] == ["https://scam.example/x"] and m[0]["telegram"] == ["FakeSupport99"])
    check("opreturn: an Omni USDT transfer is recognized (the value is in the token, not the BTC)",
          m[1]["protocol"] == "omni" and m[1]["omni"]["token"] == "USDT" and m[1]["omni"]["amount"] == 150.0)
    check("opreturn: malformed script data does not crash the trace", len(m) == 2)

    calls = []

    def fake(url, key):
        calls.append(url)
        return {"count": 3, "reports": [{"id": "r%d" % i, "checked": i == 0, "scamCategory": "PHISHING",
                                         "accusedScammers": [{"info": [{"value": "SECRET_HANDLE"}]}]} for i in range(3)]}
    with tempfile.TemporaryDirectory() as d:
        s1 = rc.lookup("A1", "btc", "KEY", limit=1, base_dir=d, fetch_fn=fake)
        s2 = rc.lookup("A1", "btc", "KEY", limit=1, base_dir=d, fetch_fn=fake)
        check("reports: an answer is cached, so the 10-calls-per-month key is not wasted", len(calls) == 1 and s2.get("cached"))
        try:
            rc.lookup("A2", "btc", "KEY", limit=1, base_dir=d, fetch_fn=fake)
            over = False
        except RuntimeError:
            over = True
        check("reports: the monthly call limit is enforced", over)
        check("reports: accused persons' contact details are not copied into reports or cache",
              "SECRET_HANDLE" not in "\n".join(rc.lines_ar(s1)) and "SECRET_HANDLE" not in open(os.path.join(d, "reports_cache.json")).read())
    check("reports: one unchecked report is only 'reported' (low), never 'scam'",
          rc.label_from({"count": 1, "checked": 0, "trusted": 0})[1:] == ("reported", "low"))
    T = 1700000000 - (1700000000 % 86400)
    rows = [w.row("in" if i % 2 == 0 else "out", "c", "BTC", 1.0, "t%d" % i, T + (i % 5) * 86400 + (8 + i % 4) * 3600) for i in range(40)]
    check("profile: the activity heatmap is rendered", "Activity heatmap" in w.build_report("btc", "1abc", w.analyze(rows, {}), {}))


def t_ledger():
    import sqlite3
    from datetime import date, timedelta
    import ledger as lg
    today = date.today().isoformat()
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "l.db")

        def add(kind="platform_registration", subject="X", country="MT", source="Registry", st="company_disclosure", when=None, **k):
            return lg.add(db, "C", kind, subject, source, st, when or today, "official extract", country, base_dir=d, **k)
        refused = 0
        for bad in ({"source": ""}, {"kind": "nonsense"}, {"when": "2999-01-01"}, {"country": "Malta"}):
            try:
                add(**bad)
            except ValueError:
                refused += 1
        check("ledger: a claim without a source, with a future date, or with a bad country is refused", refused == 4)
        add(kind="residence_evidence", subject="acct", country="EG", source="Exchange reply to police", st="official_record")
        add(kind="residence_evidence", subject="acct", country="TR", source="Chat screenshot", st="user_statement", reliability="high")
        check("ledger: a claim can never be more reliable than its source type allows", lg.claims(db, "C")[-1]["reliability"] == "low")
        check("ledger: an official record makes residence 'supported'; a screenshot alone would not",
              lg.assess(lg.claims(db, "C"))["residence"] == {"status": "supported", "countries": ["EG"]})
        con = sqlite3.connect(db)
        con.execute("UPDATE claims SET country='AE' WHERE id=1")
        con.commit()
        con.close()
        check("ledger: editing a stored claim is detected by the hash chain", any("عُدِّل" in p for p in lg.verify(db)))
    db2 = os.path.join(tempfile.mkdtemp(), "l.db")
    lg.add(db2, "C", "residence_evidence", "acct", "Public article", "public_source", today, "web", "AE")
    lg.add(db2, "C", "platform_registration", "Exchange X", "Registry", "company_disclosure", today, "extract", "MT")
    lg.add(db2, "C", "network_contact", "acct", "Provider reply", "provider_record", today, "letter", "TR", vpn_possible=True)
    a = lg.assess(lg.claims(db2, "C"))
    check("ledger: platform registration and network contact never stand in for residence (undetermined)",
          a["residence"]["status"] == "undetermined" and a["roles"]["platform_registration"][0]["strength"] == "strong"
          and a["roles"]["network_contact"][0]["strength"] == "moderate")
    db3 = os.path.join(tempfile.mkdtemp(), "l.db")
    lg.add(db3, "C", "network_contact", "a", "Official reply", "official_record", (date.today() - timedelta(days=400)).isoformat(), "letter", "DE")
    check("ledger: an old network-contact record is capped at 'moderate' (addresses change)",
          lg.assess(lg.claims(db3, "C"))["roles"]["network_contact"][0]["strength"] == "moderate")
    g = {"start": "S", "nodes": {"S": {}, "E": {"label": "Demo Exchange", "category": "exchange", "source": "OFAC", "confidence": "high"}}}
    check("ledger: automatic claims from a trace are idempotent and carry no country",
          lg.record_case(db3, "K", g) == 1 and lg.record_case(db3, "K", g) == 0 and lg.claims(db3, "K")[0]["country"] is None)
    check("ledger: the report states it is not a verdict and shows the chain head", "لا يُتخذ إجراء ضد شخص" in lg.report_text(db2, "C") and "بصمة الرأس" in lg.report_text(db2, "C"))


def t_brief():
    import json as js
    from datetime import date, timedelta
    import brief as br
    import ledger as lg
    today = date.today().isoformat()
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "ledger.db")

        def add(kind, subject, country=None, st="company_disclosure", when=None, **k):
            return lg.add(db, "GLOBAL", kind, subject, "Official page", st, when or today, "official page", country, base_dir=d, **k)
        refused = 0
        for bad in (None, "call me", "ftp://x"):
            try:
                add("platform_channel", "Demo Exchange", value=bad)
            except ValueError:
                refused += 1
        check("registry: a request channel must be an email or an http(s) link", refused == 3)
        add("platform_channel", "Demo Exchange", value="legal@demo.example")
        add("platform_registration", "Demo Exchange", "MT", value="Demo Exchange Ltd")
        add("platform_channel", "Old Platform", value="old@x.example", when=(date.today() - timedelta(days=500)).isoformat())
        add("platform_registration", "Old Platform", "MT")
        add("platform_registration", "Old Platform", "CY")
        check("registry: no verification break from the new value field (older hashes stay valid)", lg.verify(db) == [])
        reg = {p["platform"].casefold(): p for p in lg.platforms(db)}
        check("registry: legal entity, registration country and channel are collected per platform",
              reg["demo exchange"]["registration"][0]["entities"] == ["Demo Exchange Ltd"] and reg["demo exchange"]["channels"][0]["value"] == "legal@demo.example")
        cd = os.path.join(d, "cases")
        os.makedirs(os.path.join(cd, "K1"))
        E, F, S = "1" + "E" * 33, "1" + "F" * 33, "1" + "S" * 33
        g = {"start": S, "chain": "btc", "nodes": {
            S: {"depth": 0}, E: {"depth": 2, "label": "Demo Exchange", "category": "exchange", "source": "OFAC", "confidence": "high"},
            F: {"depth": 2, "label": "Old Platform", "category": "exchange", "source": "deposit pattern", "confidence": "low", "inferred": "sends all its funds to X"},
            "coinjoin:z": {"depth": 1, "label": "CoinJoin", "category": "coinjoin"}},
            "edges": [{"from": S, "to": E, "txid": "tx-e", "btc": 1.5, "time": 1700000000, "taint": 0.5, "taint_max": 1.5},
                      {"from": S, "to": F, "txid": "tx-f", "btc": 0.2, "time": 1700003600}]}
        js.dump(g, open(os.path.join(cd, "K1", "graph.json"), "w"))
        t = br.build("K1", cd, db)
        check("brief: a platform with documented entity, country and channel is listed with its transactions",
              "Demo Exchange Ltd" in t and "مالطا" in t and "legal@demo.example" in t and "tx-e" in t and "0.500000 / 1.500000" in t)
        check("brief: an undocumented fact is stated as undocumented, never invented",
              "الكيان القانوني: **غير موثّق" in t and "ناقص:" in t and "مكتمل المعلومات الأساسية" in t)
        check("brief: stale channels, conflicting registrations and inferred deposit addresses are flagged",
              "قديمة" in t and "تعارض في دولة التسجيل" in t and "مستنتج" in t)
        check("brief: a CoinJoin pseudo-node is not listed as a platform, and the brief says it names no one",
              "CoinJoin" not in t.split("## 2.")[1].split("## 3.")[0] and "لا تحدد هوية أحد" in t)
        bad_ids = 0
        for bad in ("../x", "a/b", ""):
            try:
                br.valid_case_id(bad)
            except ValueError:
                bad_ids += 1
        text, path = br.save("K1", cd, db)
        check("brief: case ids cannot traverse paths, and the brief is saved in the case folder", bad_ids == 3 and path and os.path.exists(path))


def t_live_check():
    import contextlib
    import io
    import urllib.error
    import acct_tracer as at
    import btc_tracer as b
    import live_check as lc
    import site_scan as ss
    import verify as v
    saved = (b.get, v.fetch_json, v.fetch_raw, v.post_json, at.http, at.DELAY, ss.get_page, ss.resolve, ss.tls_info, ss.rdap, ss.DELAY)
    B = 10**8
    A1, A2, A3, A4, M = ["1" + c * 33 for c in "ABCDM"]

    def vin(txid, vout, a, val):
        return {"txid": txid, "vout": vout, "prevout": {"scriptpubkey_address": a, "value": val, "scriptpubkey_type": "p2pkh"}}

    def vo(a, val):
        return {"scriptpubkey_address": a, "value": val, "scriptpubkey_type": "p2pkh"}

    def tx(i, vins, vouts, h):
        return {"txid": i, "version": 2, "locktime": 0, "status": {"confirmed": True, "block_height": h, "block_time": 1700000000},
                "vin": vins, "vout": vouts}
    TX = {"cb": {"txid": "cb", "status": {"confirmed": True, "block_height": 900000}, "vin": [{"is_coinbase": True}], "vout": [vo(M, 6 * B)]},
          "T1": tx("T1", [vin("P0", 0, A1, 2 * B)], [vo(A2, int(1.5 * B)), vo(A3, int(0.4 * B))], 899999),
          "T2": tx("T2", [vin("T1", 0, A2, int(1.5 * B))], [vo(A4, int(1.4 * B))], 900000)}
    OUT = {"cb": [{"spent": False}], "T1": [{"spent": True, "txid": "T2"}, {"spent": False}], "T2": [{"spent": False}]}

    def fget(path):
        if path == "/blocks/tip/height":
            return 900000
        if path.startswith("/block/") and path.endswith("/txs"):
            return [TX["cb"], TX["T1"]]
        if path == "/tx/" + lc.PIZZA:
            raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        if path.endswith("/outspends"):
            return OUT[path.split("/")[2]]
        if path.startswith("/tx/"):
            return TX[path.split("/")[2]]
        if path.endswith("/txs"):
            return []
        return {"chain_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0}, "mempool_stats": {"tx_count": 0}}
    EA, EB, EH = "0x" + "a" * 40, "0x" + "b" * 40, "0x" + "c" * 64
    O, D = "41" + "11" * 20, "41" + "22" * 20
    TXO = {"txID": "d" * 64, "ret": [{"contractRet": "SUCCESS"}], "raw_data": {"timestamp": 1700000000000, "contract": [
        {"type": "TransferContract", "parameter": {"value": {"owner_address": O, "to_address": D, "amount": 5_000_000}}}]}}

    def post(url, body):
        if "/wallet/" in url:
            if url.endswith("getnowblock"):
                return {"block_header": {"raw_data": {"number": 70_000_000}}, "transactions": [TXO]}
            if url.endswith("gettransactionbyid"):
                return TXO
            return {"blockNumber": 69_999_900}
        m = body["method"]
        ethtx = {"hash": EH, "from": EA, "to": EB, "value": hex(10**18)}
        return {"result": hex(20_000_000) if m == "eth_blockNumber" else {"transactions": [ethtx]} if m == "eth_getBlockByNumber"
                else ethtx if m == "eth_getTransactionByHash"
                else {"status": "0x1", "blockNumber": hex(20_000_000 - 20), "logs": []}}
    good = {"transactions": True}

    def fhttp(url, headers=None):
        if "tronscanapi" in url:
            return {"name": "x", "address": url.split("address=")[1]}
        if "internal-transactions" in url or "token-transfers" in url:
            return {"items": [], "next_page_params": None}
        if "token-balances" in url:
            return []
        if "/transactions/trc20" in url or url.endswith("/transactions") or "/transactions?" in url:
            if "api.trongrid" in url:
                return {"data": [{"transaction_id": "t", "from": "x", "to": "y", "value": "1", "token_info": {"symbol": "USDT", "decimals": 6}, "block_timestamp": 1}], "meta": {}}
            return {"items": [{"hash": EH, "from": {"hash": EA}, "to": {"hash": EB}, "value": "1000", "timestamp": "2024-01-01T00:00:00.000000Z", "status": "ok"}] if good["transactions"] else None,
                    "next_page_params": None} if good["transactions"] else {}
        if "/v1/accounts/" in url:
            return {"data": [{"balance": 5_000_000, "trc20": []}]}
        return {"coin_balance": "0"}
    try:
        b.get = fget
        v.fetch_json = lambda url: 900000 if url.endswith("/blocks/tip/height") else TX[url.rsplit("/", 1)[1]]
        v.fetch_raw = lambda url, headers=None, data=None: b"a" * 64
        v.post_json, at.http, at.DELAY, ss.DELAY = post, fhttp, 0, 0
        ss.get_page = lambda u: b"<title>Example Domain</title><p>This domain is for illustrative examples.</p>"
        ss.resolve, ss.tls_info, ss.rdap = (lambda h: ["93.184.216.34"]), (lambda h: {}), (lambda d: {"created": "1995-08-14"})
        with tempfile.TemporaryDirectory() as d:
            args = types.SimpleNamespace(only=None, second="http://second/api", eth_rpc="http://rpc", tron_node="http://node",
                                         api_key=None, txid="T1", vout=0, out=os.path.join(d, "r.txt"))
            with contextlib.redirect_stdout(io.StringIO()):
                counts = lc.run(args)
            report = open(args.out, encoding="utf-8").read()
            check("live check: against well-formed provider answers every step passes and a pasteable report is written",
                  counts["FAIL"] == 0 and counts["PASS"] >= 22 and "live_check report" in report and re.search(r"SKIP\s+\[bitcoin\] historic", report))
            good["transactions"] = False
            args.only = ["eth"]
            with contextlib.redirect_stdout(io.StringIO()):
                counts2 = lc.run(args, ["eth"])
            check("live check: when a provider changes the shape of its answer the check FAILS and names the broken step",
                  counts2["FAIL"] >= 1 and any(s == "FAIL" and "Blockscout" in n for _, n, s, _d in lc.RESULTS))
    finally:
        b.get, v.fetch_json, v.fetch_raw, v.post_json, at.http, at.DELAY, ss.get_page, ss.resolve, ss.tls_info, ss.rdap, ss.DELAY = saved


def t_identity():
    import copy
    import acct_tracer as at
    import btc_tracer as b
    import identify as idf
    import labels_tool as lt
    import links as lk
    import taxonomy as tx
    saved = (at.http, b.get, idf.p_explorer)
    BTC, P2SH, ETH = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "0x" + "ab" * 20
    try:
        with tempfile.TemporaryDirectory() as d:
            labels = {}
            lt.merge(labels, BTC, "Demo Exchange", "custodial", "OFAC SDN list", "high")
            lt.save(labels, os.path.join(d, "labels.json"))
            e = labels[BTC]
            check("taxonomy: one shared vocabulary (custodial = custodian) and every label records the date it was added",
                  e["category"] == "custodian" and e["added"] and tx.canon("CEX") == "exchange" and tx.is_platform("bridge") and not tx.is_platform("scam"))
            r = idf.identify("btc", BTC, d)
            a = r["assessment"]
            lab = [x for x in r["evidence"] if x["kind"] == "label"][0]
            check("identity: an official-source label gives a high-confidence entity with its source type and date",
                  a["status"] == "identified" and a["entity"]["confidence"] == "high" and lab["source_type"] == "official_record" and lab["date"] == e["added"])
            u = idf.identify("btc", P2SH, d)
            txt = idf.report_text(u)
            check("identity: with nothing known the report says 'not found in the sources consulted', not 'clean', and lists what was not consulted",
                  u["assessment"]["status"] == "unknown" and "غياب الأدلة" in txt and "لم يُفعَّل (استعمل --live)" in txt and "لا يحدد شخصًا" in txt)
            mk = lambda ent, src, st, conf: idf.ev(src, st, "label", "x", conf, "exchange", ent, "2026-01-01", ("entity",))
            check("identity: two entities each backed at medium level are reported as a conflict; automated evidence is capped at low",
                  idf.assess([mk("A", "S1", "public_source", "medium"), mk("B", "S2", "public_source", "medium")])["status"] == "conflict"
                  and idf.assess([mk("A", "S1", "automated_tool", "high")])["entity"]["confidence"] == "low")
            json.dump({"scam.example": {"tier": "HIGH", "scanned_at": "2026-10-01", "addresses": {P2SH: {"chain": "btc", "pages": ["x"]}}}}, open(os.path.join(d, "sites.json"), "w"))
            flags = {f["flag"] for f in idf.identify("btc", P2SH, d)["assessment"]["risk_flags"]}
            check("identity: a site that displayed the address raises a risk flag but never creates an entity",
                  "suspicious-site" in flags and idf.identify("btc", P2SH, d)["assessment"]["status"] == "unknown")
            at.http = lambda url, h=None: {"is_contract": True, "name": "Proxy", "ens_domain_name": "someone.eth", "public_tags": [{"display_name": "Binance 14"}]}
            r2 = idf.identify("eth", ETH, d, live=True)
            check("identity: explorer tags and contract status are evidence; an ENS name is shown but is never an entity",
                  r2["assessment"]["classification"]["type"] == "contract" and r2["assessment"]["entity"]["name"] == "Binance 14"
                  and r2["assessment"]["entity"]["confidence"] == "low" and not any(x["entity"] == "someone.eth" for x in r2["evidence"]))
            b.get = lambda p: {"chain_stats": {"tx_count": 5000, "funded_txo_sum": 10**9, "spent_txo_sum": 10**9}, "mempool_stats": {"tx_count": 0}}
            check("identity: very high activity is classified 'service-like' without naming a platform",
                  idf.identify("btc", "1" + "Z" * 33, d, live=True)["assessment"]["classification"]["type"] == "service-like")

            def boom(*a):
                raise RuntimeError("provider down")
            idf.p_explorer = boom
            check("identity: a provider that fails is listed as not consulted instead of breaking the report",
                  any("provider down" in s for s in idf.identify("eth", ETH, d, live=True)["not_consulted"]))
    finally:
        at.http, b.get, idf.p_explorer = saved
    S, A, B2, C, D, X1, X2, X3, H = ["1" + c * 33 for c in "SABCDXYZH"]

    def edge(f, t, txid, amt, **k):
        return dict({"from": f, "to": t, "txid": txid, "btc": amt, "time": 1700000000}, **k)
    g = {"start": S, "nodes": {n: {"depth": 1} for n in (S, A, B2, C, D, X1, X2, X3, H)}, "clusters": [],
         "cluster_info": [{"members": [A, B2], "confidence": "high", "type": "personal-likely", "reasons": ["r"], "txids": ["t1"]},
                          {"members": [C, D], "confidence": "low", "type": "service-likely", "reasons": ["r"], "txids": ["t2"]}],
         "edges": [edge(S, A, "e1", 2.0, change=True), edge(S, B2, "e2", 1.0), edge(X1, H, "e3", 1.0), edge(X2, H, "e4", 1.0), edge(X3, H, "e5", 1.0)]}
    g["nodes"][H].update(label="Demo Exchange", category="exchange")
    g["nodes"][X1].update(label="Demo Exchange", category="exchange", inferred="sends all its funds to " + H)
    before = copy.deepcopy(g)
    res = lk.analyze(g)
    ty = {(l["type"], l["strength"], l["kind"]) for l in res["links"]}
    check("links: co-spend, change, deposit-to-hot-wallet and common-destination links are found, in three separate kinds, without modifying the graph",
          g == before and ("co_spend", "strong", "ownership-heuristic") in ty and ("co_spend", "weak", "ownership-heuristic") in ty
          and ("change", "weak", "ownership-heuristic") in ty and ("deposit_to_hot_wallet", "moderate", "service-structure") in ty
          and ("common_destination", "weak", "financial-flow") in ty)
    f = lk.analyze(g, focus=A)
    t = lk.report_text(res)
    check("links: the focus filter keeps only links of that address, and every report states that money flow is not proof of one owner",
          f["links"] and all(A in l["members"] for l in f["links"]) and "لا يكفي دليلًا" in t and "ارتباط مالي فقط" in t)


def t_review():
    import copy
    import sqlite3
    from datetime import date, timedelta
    import acct_tracer as at
    import btc_tracer as b
    import identify as idf
    import labels_tool as lt
    import review as rv
    today = date.today().isoformat()
    A, B2, C, D, E, H, S = ["1" + c * 33 for c in "ABCDEHS"]
    BTC, ETH, TR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "0x" + "ab" * 20, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    with tempfile.TemporaryDirectory() as d:
        db, lp = os.path.join(d, "review.db"), os.path.join(d, "labels.json")
        lt.save({D: {"label": "Satoshi Guess", "category": "exchange", "source": "satoshidata (third-party, unverified)", "confidence": "low"}}, lp)
        g = {"start": S, "chain": "btc", "nodes": {
            S: {"depth": 0}, H: {"depth": 2, "label": "Demo Exchange", "category": "exchange"},
            A: {"depth": 1, "label": "Demo Exchange", "category": "exchange", "inferred": "sends all its funds to " + H},
            B2: {"depth": 1, "note": "high activity (4200 txs), likely a service; not expanded"},
            C: {"depth": 1, "note": "collection point: received from 3 traced addresses (possible service or hot wallet)"},
            D: {"depth": 1, "label": "Satoshi Guess", "category": "exchange", "source": "satoshidata (third-party, unverified)", "confidence": "low"},
            E: {"depth": 1}},
            "edges": [{"from": S, "to": x, "txid": "t" + x[1], "btc": v} for x, v in ((A, 1.0), (B2, 5.0), (C, 2.0), (D, 0.5), (E, 0.1))]}
        labels = lt.load(lp)
        added, updated = rv.enqueue(db, g, "CASE1", labels)
        q = rv.queue(db)
        reasons = {i["address"]: i["reasons"] for i in q}
        check("review: the queue holds busy, collection-point, inferred and low-confidence addresses, not ordinary ones, with Arabic reasons and an explorer link",
              (added, updated) == (4, 0) and reasons == {A: ["inferred"], B2: ["high_activity"], C: ["collection_point"], D: ["low_confidence_label"]}
              and all(i["reasons_ar"] and i["url"].endswith(i["address"]) for i in q))
        rv.enqueue(db, g, "CASE2", labels)
        q = rv.queue(db)
        check("review: an address seen in a second case is merged (not duplicated) and the queue is ordered by priority",
              len(q) == 4 and all(len(i["cases"]) == 2 for i in q) and q == sorted(q, key=lambda i: -i["priority"]))
        refused = 0
        for k in ({"reviewer": ""}, {"reviewer": "x"}, {"action": "delete"}, {"label": " "}, {"category": "nonsense"}, {"confidence": "low"},
                  {"confidence": "high", "evidence": "short"}, {"category": "scam", "evidence": ""}, {"address": "garbage"}):
            args = dict(db_path=db, labels_path=lp, address=A, action="confirm", reviewer="Sami", label="Demo Exchange", category="exchange", confidence="medium", evidence="")
            args.update(k)
            try:
                rv.decide(**args)
            except ValueError:
                refused += 1
        check("review: every decision rule is enforced (reviewer name, valid action/label/category, medium or high only, evidence for high and for risk labels)", refused == 9)
        r = rv.decide(db, lp, A, "confirm", "Sami", "Demo Exchange", "exchange", "medium", "")
        e = lt.load(lp)[A]
        rv.enqueue(db, g, "CASE3", lt.load(lp))
        check("review: a confirmation records reviewer and date, leaves the queue, and never comes back",
              r["status"] == "confirmed" and e["review"]["by"] == "Sami" and e["source"].startswith("review: Sami") and A not in {i["address"] for i in rv.queue(db)})
        rv.decide(db, lp, C, "confirm", "Sami", "Scam Wallet", "scam", "high", "Victim report plus matching transactions")
        rv.decide(db, lp, D, "confirm", "Dana", "Real Exchange", "exchange", "medium", "Official page")
        L = lt.load(lp)
        check("review: a risk label is capped at medium, and a conflicting confirmation keeps the earlier label as an alternative",
              L[C]["confidence"] == "medium" and L[D]["label"] == "Real Exchange" and L[D]["alt"][0]["label"] == "Satoshi Guess")
        rv.decide(db, lp, E, "reject", "Sami", note="personal wallet")
        L = lt.load(lp)
        ev = idf.p_labels(L, E)
        check("review: a rejected label is ignored by the tracers and the identity engine, which records the rejection",
              rv.rejected(L[E]) and b.label_info(L, E) is None and at.label_info(L, E) is None and "رفض مراجع" in ev[0]["statement"] and idf.assess(ev)["entity"] is None)
        rv.decide(db, lp, B2, "skip", "Sami")
        con = sqlite3.connect(db)
        intact = rv.verify_history(db) == [] and len(rv.history(db)) == 5
        con.execute("UPDATE decisions SET reviewer='Mallory' WHERE id=2")
        con.commit()
        tampered = any("عُدِّل" in p for p in rv.verify_history(db))
        con.close()
        check("review: the decision history is hash-chained, and editing an old decision is detected", intact and tampered)
        db2, lp2 = os.path.join(d, "r2.db"), os.path.join(d, "l2.json")
        txt = "%s, %s;\n%s %s garbage 0x123" % (BTC, ETH, TR, BTC)
        base = dict(db_path=db2, labels_path=lp2, file_path=None, platform="Demo Exchange", category="exchange", source_url="https://demo.example/proof", when=today, reviewer="Sami", text=txt)
        refused = 0
        for k in ({"source_url": "http://demo.example"}, {"when": ""}, {"when": (date.today() + timedelta(days=1)).isoformat()}, {"category": "scam"}, {"reviewer": "s"}, {"text": "nothing"}):
            try:
                rv.import_official(**dict(base, **k))
            except ValueError:
                refused += 1
        check("review: an official list is refused without an https source, a valid past date, a platform category, a reviewer, or any valid address", refused == 6)
        res = rv.import_official(**base)
        L2 = lt.load(lp2)
        ident = idf.identify("btc", BTC, tempfile.mkdtemp(), labels=L2)
        check("review: an official list adds each valid address once (duplicates and garbage skipped) as high confidence, and the identity engine then calls it identified from an official disclosure",
              res == {"addresses": 3, "added": 3, "updated": 0} and L2[BTC]["source"] == "official page: https://demo.example/proof (%s)" % today
              and ident["assessment"]["status"] == "identified" and ident["evidence"][0]["source_type"] == "company_disclosure")
        bundle = rv.export_bundle(lp)
        t = copy.deepcopy(bundle)
        t["labels"][C]["label"] = "Tampered"
        check("review: a label bundle contains only reviewed or official labels, never rejected ones, and a changed bundle fails its SHA-256 check",
              rv.verify_bundle(bundle)[0] and E not in bundle["labels"] and C in bundle["labels"] and not rv.verify_bundle(t)[0])
        other = {X: {"label": "Imported Co", "category": "exchange", "source": "x", "confidence": "high"} for X in (A, B2)}
        imp = {"format": "labels-bundle-1", "exported_at": "2026-10-01T00:00:00Z", "count": 2, "labels": other, "sha256": rv.bundle_hash(other)}
        lp3, db3 = os.path.join(d, "l3.json"), os.path.join(d, "r3.db")
        lt.save({A: {"label": "Mine", "category": "exchange", "source": "review: me", "confidence": "medium", "review": {"status": "confirmed", "by": "me", "at": today}}}, lp3)
        res = rv.import_bundle(db3, lp3, imp, "b.json", "Sami")
        L3 = lt.load(lp3)
        imp["labels"][B2]["label"] = "Sneaky"
        try:
            rv.import_bundle(db3, lp3, imp, "b.json", "Sami")
            refused_tampered = False
        except ValueError:
            refused_tampered = True
        check("review: an imported bundle is capped at medium, your own decision always wins, and a tampered bundle is refused",
              res["skipped"] == 1 and L3[A]["label"] == "Mine" and L3[B2]["confidence"] == "medium" and L3[B2]["review"]["status"] == "imported" and refused_tampered)
    import case_builder as cb
    with tempfile.TemporaryDirectory() as d2:
        cb.run_case("btc", S, 3, None, {}, os.path.join(d2, "cases"), {}, None, copy.deepcopy(g), False)
        queued = {i["address"] for i in rv.queue(os.path.join(d2, "review.db"))}
        check("review: building a case puts the addresses worth naming (inferred, busy, collection point) into the review queue automatically", {A, B2, C} <= queued and E not in queued)


def t_precheck():
    import re as _re
    import labels_tool as lt
    import precheck as pc
    today = __import__("datetime").date.today().isoformat()
    BTC, P2, B3, B4 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "1" + "Q" * 33, "1" + "R" * 33
    with tempfile.TemporaryDirectory() as d:
        def run(**k):
            return pc.precheck(base_dir=d, **k)
        check("precheck: each STOP flag alone gives STOP, each CAUTION flag alone gives CAUTION, and one STOP flag among others is enough",
              all(run(flags=[f])["verdict"] == "STOP" for f in ("seed_phrase", "withdrawal_fee", "guaranteed_returns", "remote_access", "recovery_offer"))
              and all(run(flags=[f])["verdict"] == "CAUTION" for f in ("online_relationship", "urgency", "unlicensed", "address_from_chat", "changed_address"))
              and run(flags=["urgency", "seed_phrase"])["verdict"] == "STOP")
        r = run(chain="btc", address=B3)
        check("precheck: with nothing found the verdict is 'no flags', says it does not mean safe, and lists what was not consulted",
              r["verdict"] == "NO_FLAGS" and "لا يعني أنه آمن" in r["verdict_ar"] and any("لم يُفعَّل" in n for n in r["not_checked"])
              and "لا يعني أن الطرف الآخر صادق" in pc.report_text(r))
        L = {}
        lt.merge(L, BTC, "Bad Actor", "sanctioned", "OFAC SDN list", "high")
        lt.merge(L, P2, "Demo Exchange", "exchange", "official page: https://demo.example (2026-09-30)", "high")
        lt.save(L, os.path.join(d, "labels.json"))
        ex = run(chain="btc", address=P2)
        json.dump({"btc:" + B3: {"count": 1, "checked": 0, "trusted": 0, "categories": {}, "losses": {}, "first": None, "last": None, "domains": [], "ids": [], "contacts_listed": 0, "checked_at": today}},
                  open(os.path.join(d, "reports_cache.json"), "w"))
        low = run(address=B3)
        json.dump({"btc:" + B3: {"count": 3, "checked": 1, "trusted": 0, "categories": {}, "losses": {}, "first": None, "last": None, "domains": [], "ids": [], "contacts_listed": 0, "checked_at": today}},
                  open(os.path.join(d, "reports_cache.json"), "w"))
        check("precheck: a sanctioned address and a scam-reported address (verified reports) give STOP, one unverified report gives CAUTION, and an exchange-labeled address gives only an informational line",
              run(address=BTC)["verdict"] == "STOP" and run(address=B3)["verdict"] == "STOP" and low["verdict"] == "CAUTION"
              and ex["verdict"] == "NO_FLAGS" and any(x["level"] == "info" and "مصنّف باسم" in x["text"] for x in ex["reasons"]))
        json.dump({"scam.example": {"tier": "HIGH", "scanned_at": "2026-10-01", "addresses": {}}, "iffy.example": {"tier": "MEDIUM", "scanned_at": "2026-10-02", "addresses": {}},
                   "calm.example": {"tier": "LOW", "scanned_at": "2026-10-03", "addresses": {}}}, open(os.path.join(d, "sites.json"), "w"))
        json.dump({"domains": {"blocked.example": "my trusted list"}}, open(os.path.join(d, "blocklist.json"), "w"))
        calm = run(url="https://calm.example/")
        check("precheck: previously scanned sites and your blocklist work offline (HIGH or blocked = STOP, MEDIUM = CAUTION, LOW = never safe)",
              run(url="https://www.scam.example/x")["verdict"] == "STOP" and run(url="https://iffy.example/")["verdict"] == "CAUTION"
              and run(url="https://sub.blocked.example/")["verdict"] == "STOP" and calm["verdict"] == "NO_FLAGS"
              and any("لا يعني أنه آمن" in x["text"] for x in calm["reasons"]))

        def scan(tier, addrs):
            return lambda url, n, base, lp, wl: {"tier": tier, "addresses": [{"address": a, "chain": "btc"} for a in addrs], "domain": "x", "report": "r", "labeled": 0}

        def boom(*a):
            raise RuntimeError("site down")
        mismatch = run(chain="btc", address=B4, url="https://new.example/", live=True, scanner=scan("LOW", [BTC]))
        down = run(url="https://new.example/", live=True, scanner=boom)
        check("precheck: a live scan counts (HIGH = STOP), a payment address the site does not display is a CAUTION, and a failed scan is reported instead of ignored",
              run(url="https://new.example/", live=True, scanner=scan("HIGH", []))["verdict"] == "STOP" and mismatch["verdict"] == "CAUTION"
              and any("site down" in n for n in down["not_checked"]))
        refused = 0
        for k in ({}, {"flags": ["nonsense"]}, {"url": "ftp://x.example"}, {"url": "not a url"}, {"address": "garbage"}):
            try:
                run(**k)
            except ValueError:
                refused += 1
        check("precheck: no input, an unknown flag, a non-http link or an invalid address are refused", refused == 5)
    h = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
    data = json.loads(_re.search(r"const PC=(\{.*?\});\nconst PCF", h, _re.S).group(1))
    check("precheck: the flag table, verdict wording and advice shown by the website are generated from precheck.py (they cannot drift apart)",
          data["flags"] == {k: list(v) for k, v in pc.RED_FLAGS.items()} and data["verdicts"] == pc.VERDICT_AR
          and data["general"] == pc.GENERAL_ADVICE and data["after"] == pc.AFTER_PAYING)


def t_leads():
    import case_builder as cb
    S, M, EX, SV = "1" + "S" * 33, "1" + "M" * 33, "1" + "E" * 33, "1" + "V" * 33
    base = {"start": S, "chain": "btc", "mode": "all", "nodes": {S: {"depth": 0}}, "edges": [], "clusters": []}

    def case(nodes, edges, extra=None, balances=None, params=None):
        g = dict(base, nodes=dict(base["nodes"], **nodes), edges=edges, **(extra or {}))
        return cb.build_case(g, {}, balances or {}, params or {})
    # 1. money that has not moved is the strongest lead, and the page tells you what to do about it
    c1 = case({M: {"depth": 1}}, [{"from": S, "to": M, "txid": "t1", "btc": 1.0}], {"unspent": [{"address": M, "value": 0.5, "taint": 0.1, "txid": "t1", "vout": 0}]}, {M: {"BTC": 0.5}})
    first = cb.leads(dict(base, mode="taint", nodes={S: {}, M: {}}, edges=[], unspent=[{"address": M, "value": 0.5, "taint": 0.1}]), {"HOLDING": [{"address": M, "balance": {"BTC": 0.5}, "amounts": {}}]}, "btc", {})[0]
    check("leads: money that has not moved is the first lead, with the watch command", "لم يتحرك" in first[0] and "python watch.py btc" in first[2])
    # 2. a known platform reached -> the ready notice, to be sent today and in parallel with the police
    c2 = case({EX: {"depth": 1, "label": "Demo Exchange", "category": "exchange", "source": "OFAC", "confidence": "high"}}, [{"from": S, "to": EX, "txid": "t2", "btc": 2.0}], params={"txid": "T" * 64})
    check("leads: a known platform reached gives the ready exchange notice as a same-day step, not a police-only answer",
          "وصل المال إلى منصة معروفة: Demo Exchange" in c2["summary"] and "exchange_notice_*.md" in c2["summary"] and "بالتوازي" in c2["summary"])
    # 3. a busy address nobody has named: the page shows how to find the name yourself, with the explorer link
    c3 = case({SV: {"depth": 1, "note": "high activity (4200 txs), likely a service; not expanded"}}, [{"from": S, "to": SV, "txid": "t3", "btc": 3.0}])
    check("leads: an unnamed busy address gives a do-it-yourself way to find its name (explorer link, search, review tab)",
          "https://blockstream.info/address/" + SV in c3["summary"] and "مراجعة التصنيفات" in c3["summary"] and "علامتي تنصيص" in c3["summary"])
    # 4. the platform you paid from is always a lead and carries the payment txid
    check("leads: the platform or bank you paid from is always a lead and carries your payment transaction id",
          "المنصة أو البنك الذي حوّلت منه" in c3["summary"] and ("T" * 64) in c2["summary"] and "الاعتراض" in c3["summary"])
    # 5. the order: leads first, police last but still present
    s = c2["summary"]
    acts = c2["actions"]
    police = [i for i, a in enumerate(acts) if "police_report.md" in a]
    check("leads: the report opens with the first lead (before the summary), and the police step is last among the case steps but still there",
          s.index("## خيطك الأول") < s.index("## الخلاصة") and "الشرطة" not in acts[0] and police and police[0] > 0 and police[0] >= len(acts) - 3)
    check("leads: no lead tells the victim only to 'go to the police'", all("الشرطة" not in t + w for (t, w, d) in cb.leads(base, {}, "btc", {})[:1]))
    # 5b. the shape of a real report: a collection address that forwarded ~99% to ONE busy address, years ago, traced by address (not by outpoint)
    from datetime import datetime, timezone
    X2 = "1" + "X" * 33
    gr = dict(base, nodes={S: {"depth": 0}, SV: {"depth": 1, "note": "high activity (4200 txs), likely a service; not expanded"}, X2: {"depth": 1, "note": "high activity (900 txs), likely a service; not expanded"}},
              edges=[{"from": S, "to": SV, "txid": "t", "btc": 1.814}, {"from": S, "to": X2, "txid": "u", "btc": 0.0173}])
    groups_r = cb.classify(gr, {})
    last = int(datetime(2019, 12, 29, tzinfo=timezone.utc).timestamp())
    L = cb.leads(gr, groups_r, "btc", {}, {"last": last})
    rep = cb.build_case(gr, {}, {}, {}, {"last": last, "payers": 6, "payments": 6, "totals": {"BTC": 1.8335}, "first": last - 86400 * 30, "top": [], "labeled_payers": 0})["summary"]
    check("leads: an old case is told so plainly (years since the last payment) and that freezing should not be expected",
          "سنة على آخر دفعة" in L[0][0] and "لا تتوقع تجميدًا" in L[0][1])
    check("leads: when one busy address received ~99% of what the start address forwarded, that is THE lead, with the explorer link and how to tell a platform's hot wallet",
          any("99%" in t and "عنوان واحد كثير النشاط" in t and "آلاف المعاملات" in d and SV in d for t, w, d in L) and sum("كثير النشاط" in t for t, w, d in L) == 2)
    check("leads: a trace made by address (not by the payment outpoint) warns that large amounts may not be yours, at the top of the report",
          "تتبع بالعنوان وليس بالمخرج" in rep and rep.index("تتبع بالعنوان وليس بالمخرج") < rep.index("## الخلاصة"))
    gh = dict(gr, edges=gr["edges"], nodes=dict(gr["nodes"], **{M: {"depth": 1}}))
    gh["edges"] = gr["edges"] + [{"from": S, "to": M, "txid": "v", "btc": 0.0375}]
    held = cb.leads(gh, cb.classify(gh, {M: {"BTC": 0.0375}}), "btc", {})
    check("leads: a balance found by an address-level trace is offered with the warning that it may not be yours, not as the strongest lead",
          any("قد لا يكون مالك" in t for t, w, d in held) and not any("لم يتحرك بعد" in t for t, w, d in held))
    # 6. nothing found: honest 'not complete yet' lead plus the paid-from lead
    c6 = case({}, [])
    check("leads: with nothing found the report says the trail is incomplete and still offers the paid-from step", "الأثر لم يكتمل بعد" in c6["summary"] and "المنصة أو البنك الذي حوّلت منه" in c6["summary"])


def t_investigate():
    import acct_tracer as at
    import btc_tracer as b
    import case_builder as cb
    import identify as idf
    import investigate as inv
    import labels_tool as lt
    saved = (b.get, at.http, b.DELAY, at.DELAY, cb.DELAY, os.getcwd())
    B = 10**8
    S, M, EX, X = ["1" + c * 33 for c in "SMEX"]

    def vin(t, n, a, v):
        return {"txid": t, "vout": n, "prevout": {"scriptpubkey_address": a, "value": v, "scriptpubkey_type": "p2pkh"}}

    def vo(a, v):
        return {"scriptpubkey_address": a, "value": v, "scriptpubkey_type": "p2pkh"}

    def tx(i, vins, vouts):
        return {"txid": i, "version": 2, "locktime": 0, "status": {"confirmed": True, "block_time": 1577577600, "block_height": 100}, "vin": vins, "vout": vouts}
    DB = {S: [tx("t0", [vin("P", 0, X, 2 * B)], [vo(S, B * 19 // 10)]), tx("t1", [vin("t0", 0, S, B * 19 // 10)], [vo(EX, B * 18 // 10), vo(M, B // 20)])], M: [], EX: []}

    def get(p):
        a = p.split("/")[2]
        if p == "/address/" + a:
            return {"chain_stats": {"tx_count": len(DB[a]), "funded_txo_sum": 10**9, "spent_txo_sum": 10**9}, "mempool_stats": {"tx_count": 0}}
        return DB[a]
    TA, EA = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "0x" + "ab" * 20

    def fhttp(url, h=None):
        if "tronscanapi" in url:
            return {"name": "Demo Hot Wallet", "address": TA}
        if "trongrid" in url:
            return {"data": [{"balance": 5_000_000, "trc20": []}], "meta": {}} if "/v1/accounts/%s" % TA in url and "transactions" not in url else {"data": [], "meta": {}}
        if "internal-transactions" in url or "token-transfers" in url or url.endswith("/transactions"):
            return {"items": [], "next_page_params": None}
        if "token-balances" in url:
            return []
        return {"coin_balance": "0", "public_tags": [{"display_name": "Test Tag"}], "is_contract": False}
    try:
        b.get, at.http = get, fhttp
        b.DELAY = at.DELAY = cb.DELAY = 0
        with tempfile.TemporaryDirectory() as d:
            lp = os.path.join(d, "labels.json")
            L = {}
            lt.merge(L, EX, "Demo Exchange", "exchange", "OFAC SDN list", "high")
            lt.save(L, lp)
            os.chdir(d)
            open("graph.json", "w").write("PRECIOUS")
            r, text, folder = inv.run(inv.defaults(chain="btc", address=S, labels=lp, depth=3))
            check("investigate: the report goes to a NEW folder (never over files in the current folder) with the report, the JSON and the graph",
                  open("graph.json").read() == "PRECIOUS" and sorted(os.listdir(folder)) == ["graph.json", "investigation.json", "investigation.md"]
                  and json.load(open(os.path.join(folder, "investigation.json"), encoding="utf-8"))["address"] == S)
            check("investigate: it opens with the first leads and names the platform reached, then identity, research links, payers, links and the profile, with no 'platform you paid from' lead",
                  all(x in text for x in ("## خيطك الأول", "وصل المال إلى منصة معروفة: Demo Exchange", "## هوية العنوان والأدلة", "## روابط للتحقق اليدوي",
                                          "blockstream.info/address/" + S, "## من دفع إلى عنوان البداية؟", "## ملف سلوك المحفظة", "تتبع بالعنوان وليس بالمخرج"))
                  and "المنصة أو البنك الذي حوّلت منه" not in text)
            refused = 0
            for k in ({"address": "garbage"}, {"chain": "eth", "address": S}, {"depth": -1}):
                try:
                    inv.run(inv.defaults(**dict({"chain": "btc", "address": S, "labels": lp}, **k)))
                except ValueError:
                    refused += 1
            open(os.path.join(d, "bad.json"), "w").write("{not json")
            try:
                inv.run(inv.defaults(chain="btc", address=S, labels=os.path.join(d, "bad.json")))
            except ValueError:
                refused += 1
            check("investigate: a garbage address, an address of another network, a negative depth and an unreadable labels file are refused", refused == 4)

            def broken(p):
                if "/txs" in p:
                    raise RuntimeError("provider down")
                return get(p)
            b.get = broken
            r2, text2, _ = inv.run(inv.defaults(chain="btc", address=S, labels=lp, depth=1))
            b.get = get
            check("investigate: when a step fails the failure is listed in the report and the other sections still work",
                  r2["errors"] and "## ما تعذّر إكماله" in text2 and "provider down" in text2 and r2["identity"] is not None)
            rt, tt, _ = inv.run(inv.defaults(chain="tron", address=TA, labels=lp, live=True))
            re_, te, _ = inv.run(inv.defaults(chain="eth", address=EA.upper().replace("0X", "0x"), labels=lp, live=True))
            check("investigate: a TronScan name is low-confidence evidence, an Ethereum tag is evidence, and each network gets its own explorer links",
                  any(e["entity"] == "Demo Hot Wallet" and e["confidence"] == "low" for e in rt["identity"]["evidence"]) and "tronscan.org/#/address/" + TA in tt
                  and re_["identity"]["assessment"]["entity"]["name"] == "Test Tag" and "etherscan.io/address/" + EA in te and re_["address"] == EA)
            at.http = lambda url, h=None: {"name": "N", "address": "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t"}
            kinds = [e["kind"] for e in idf.p_tronscan(TA)]
            at.http = lambda url, h=None: {"isContract": True}
            check("identity: a TronScan answer for an address that differs only in letter case is NOT trusted (TRON addresses are case-sensitive), and a contract flag is respected",
                  kinds == ["tag", "technical"] and idf.p_tronscan(TA)[0]["category"] == "contract")
    finally:
        os.chdir(saved[5])
        b.get, at.http, b.DELAY, at.DELAY, cb.DELAY = saved[:5]


def diagnose_fixture(addr):
    return {"chain": "btc", "address": addr, "stats": {"txs": 1}, "signals": [], "scores": {"service": 0, "collection": 0},
            "verdict": "unclear", "confidence": "low", "counterparties": [], "link": "https://mempool.space/address/" + addr}


def t_languages():
    import re, i18n_build as ib, case_builder as cb, diagnose as dg, payments as pm
    html = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
    rows = ib.load_tsv()
    miss, unused, empty = ib.check(html, rows)
    check("languages: every Arabic phrase in the page has a translation row (run i18n_build.py --check)", not miss)
    check("languages: no translation cell is empty", not empty)
    m = re.search(r"/\*I18N-START\*/const I18N=(.*?);/\*I18N-END\*/", html, re.S)
    d = json.loads(m.group(1)) if m else {}
    check("languages: the page embeds the six dictionaries, in sync with translations.tsv", sorted(d) == sorted(ib.LANGS) and all(len(d[l]) == len(rows) for l in ib.LANGS))
    AR = re.compile("[\u0621-\u064A]")
    bad = [(l, k) for l in ("en", "es", "fr", "tr", "ru") for k, v in d.get(l, {}).items() if AR.search(v)]
    check("languages: no Arabic letters are left inside the en/es/fr/tr/ru translations", not bad)
    lost = [(l, k) for k in rows for l in ib.LANGS for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", k) if t not in d[l].get(k, "")]
    check("languages: technical tokens (txid, graph.json, python serve.py, CHAINABUSE_KEY...) survive every translation", not lost)
    nums = [(l, k) for k in rows for l in ib.LANGS if re.findall(r"\d+", k) != re.findall(r"\d+", d[l].get(k, "")) and not re.search(r"[\u06F0-\u06F9]", d[l].get(k, ""))]
    check("languages: numbers in a phrase are kept (2019-03-14, 4200, 10...)", not nums)
    check("languages: the page has the language selector and the RTL/LTR switch", 'id="lang"' in html and "h.dir=RTL.has(l)" in html)
    # English server texts: first lead, diagnosis and payments list contain no Arabic when an English-pivot language is asked for
    S, M = "1" + "S" * 33, "1" + "M" * 33
    g = {"start": S, "chain": "btc", "mode": "taint", "nodes": {S: {}, M: {}}, "edges": [], "unspent": [{"address": M, "value": 0.5, "taint": 0.1}]}
    for lang in ("en", "es", "fr", "tr", "ru"):
        lead = "\n".join(cb.lead_lines(g, {"HOLDING": [{"address": M, "balance": {"BTC": 0.5}, "amounts": {}}]}, "btc", {"lang": lang}))
        check("languages: the first lead in '%s' is in English with no Arabic" % lang, "Your first lead" in lead and "The money has not moved yet" in lead and not AR.search(lead))
    lead_ar = "\n".join(cb.lead_lines(g, {"HOLDING": [{"address": M, "balance": {"BTC": 0.5}, "amounts": {}}]}, "btc", {}))
    check("languages: Arabic stays the default for the first lead", "خيطك الأول" in lead_ar)
    d0 = diagnose_fixture(S)
    d0.update(signals=[{"side": "service", "points": 2, "text": "حوّل إلى 60 عنوانًا مختلفًا", "text_en": "Sent to 60 different addresses"}], stats={"txs": 6000},
              scores={"service": 2, "collection": 0}, verdict="service-possible", confidence="medium",
              counterparties=[{"address": M, "direction": "out", "btc": 1.5, "label": None, "link": "x"}])
    en = "\n".join(dg.lines_ar(d0, "en"))
    check("languages: the diagnosis in English has no Arabic and keeps the indicators", not AR.search(en) and "Sent to 60 different addresses" in en and "May be a platform" in en)
    check("languages: the diagnosis stays Arabic by default", "تشخيص العنوان" in "\n".join(dg.lines_ar(d0)))
    res = {"address": S, "chain": "btc", "count": 1, "warning": None, "payments": [{"time_str": "2019-03-14", "amount": 0.5, "asset": "BTC", "txid": "a" * 64, "vout": 0,
                                                                                    "rank": 1, "amount_match": True, "date_match": True}]}
    t_en = pm.format_list(res, "en")
    check("languages: the payments list in English", not AR.search(t_en) and "matches the amount and the date" in t_en)
    check("languages: the payments list stays Arabic by default", "تطابق" in pm.format_list(res))


def t_platform_mix():
    import re, platform_finder as pf, mix_check as mc, case_builder as cb
    AR = re.compile("[\u0621-\u064A]")
    S, H, E = "1" + "S" * 33, "1" + "H" * 33, "1" + "E" * 33
    D = ["1" + c * 33 for c in "ABC"]
    T0 = 1_700_000_000
    nodes = {S: {"depth": 0}, H: {"depth": 2, "note": "high activity (4200 txs), likely a service; not expanded"}}
    edges = []
    for i, d in enumerate(D):
        nodes[d] = {"depth": 1}
        edges.append({"from": S, "to": d, "txid": "s%d" % i, "btc": 1.0, "time": T0 + i})
        edges.append({"from": d, "to": H, "txid": "h%d" % i, "btc": 0.999, "time": T0 + 3600 * (i + 1)})
    g = {"start": S, "chain": "btc", "mode": "all", "nodes": nodes, "edges": edges, "clusters": []}
    c = pf.find(g)
    top = c[0] if c else {}
    check("platform_finder: three deposit addresses sweeping into one busy address make it the top candidate", top.get("address") == H and len(top.get("sweepers", [])) == 3 and top.get("tier") == "likely")
    check("platform_finder: with no label it never invents a name", top.get("name") is None)
    # a slow forwarder (months later) is not a sweep
    slow = json.loads(json.dumps(g))
    for e in slow["edges"]:
        if e["to"] == H:
            e["time"] += 90 * 86400
    check("platform_finder: forwarding months later is not treated as a sweep", not pf.find(slow) or not pf.find(slow)[0]["sweepers"])
    # a labelled platform is 'known' and ranks first
    g2 = json.loads(json.dumps(g))
    g2["nodes"][E] = {"depth": 1, "label": "Demo Exchange", "category": "exchange", "source": "OFAC", "confidence": "high"}
    g2["edges"].append({"from": S, "to": E, "txid": "e1", "btc": 2.0, "time": T0})
    c2 = pf.find(g2)
    check("platform_finder: a labelled exchange is 'known' and ranks first", c2[0]["address"] == E and c2[0]["tier"] == "known" and c2[0]["name"] == "Demo Exchange")
    g3 = json.loads(json.dumps(g))
    g3["nodes"][H].update(label="Scam X", category="scam")
    check("platform_finder: an address labelled as a scam is not offered as a platform", all(x["address"] != H for x in pf.find(g3)))
    en = "\n".join(pf.lines(c, "en"))
    check("platform_finder: English text has no Arabic and keeps the honesty line", not AR.search(en) and "not proof of ownership" in en)
    check("platform_finder: Arabic by default", "إلى أي منصة" in "\n".join(pf.lines(c)))
    # the case report carries the section, in both languages
    bal = {H: {"BTC": 0.0}}
    sa = cb.build_case(json.loads(json.dumps(g)), {}, bal, {})["summary"]
    se = cb.build_case(json.loads(json.dumps(g)), {}, bal, {"lang": "en"})["summary"]
    check("case report: the platform section is in the summary (Arabic and English)", "إلى أي منصة وصل المال" in sa and "Which platform did the money reach" in se)
    # mixing
    M = "coinjoin:" + "f" * 64
    gm = {"start": S, "chain": "btc", "nodes": {S: {}, M: {"label": "CoinJoin (محتمل)", "category": "coinjoin"}}, "edges": [{"from": S, "to": M, "txid": "m1", "btc": 1.0, "time": T0}]}
    ev = mc.detect(gm)
    check("mix_check: detects where the trace entered a CoinJoin and the last address before it", len(ev) == 1 and ev[0]["entries"][0][0] == S and ev[0]["kind"] == "coinjoin")
    check("mix_check: a trace with no mixer reports none", mc.detect(g) == [])
    tx = {"txid": "x", "vin": [{}] * 5, "vout": [{"value": 10_000_000, "scriptpubkey_address": "a%d" % i} for i in range(5)] + [{"value": 123, "scriptpubkey_address": "chg"}]}
    r = mc.coinjoin_outputs(tx)
    check("mix_check: five equal outputs means your money is one of five: the floor is 1/5, never better", r["count"] == 5 and abs(r["chance_floor"] - 0.2) < 1e-9 and r["denomination"] == 0.1)
    dep = {"amount": 1.0, "time": T0}
    pool = [{"to": "w1", "amount": 1.0, "time": T0 + 86400}, {"to": "w2", "amount": 1.001, "time": T0 + 5 * 86400}, {"to": "early", "amount": 1.0, "time": T0 - 10},
            {"to": "late", "amount": 1.0, "time": T0 + 60 * 86400}, {"to": "other", "amount": 5.0, "time": T0 + 86400}]
    m = mc.match_candidates(dep, pool)
    check("mix_check: the shortlist keeps only same-size, later, in-window withdrawals", [x["to"] for x in m["candidates"]] == ["w1", "w2"])
    check("mix_check: the shortlist is always 'very-low' confidence and carries the 1/N floor", m["confidence"] == "very-low" and abs(m["chance_floor"] - 0.5) < 1e-9)
    check("mix_check: English text has no Arabic and states the limit", not AR.search("\n".join(mc.lines(ev, "en"))) and "does NOT claim" in "\n".join(mc.lines(ev, "en")))
    sm = cb.build_case(json.loads(json.dumps(gm)), {}, {}, {})["summary"]
    check("case report: a trace through a CoinJoin gets the mixing section with the honest limit", "الخلط (Mixer / CoinJoin)" in sm and "لا تدّعي تتبع المال" in sm)


def t_server():
    import serve
    import btc_tracer
    import verify as v
    tmp = tempfile.mkdtemp()
    serve.HERE = tmp
    open(os.path.join(tmp, "index.html"), "w", encoding="utf-8").write("<html>SITE</html>")
    btc_tracer.trace = lambda a, d, m, b, l, **k: {"start": a, "nodes": {a: {"depth": 0}}, "edges": [], "clusters": []}
    seen = {}
    serve.wallet_profile.build = lambda chain, addr, labels, args: ("PROFILE-REPORT", {})
    serve.case_builder.run_case = lambda *a, **k: (seen.update(k), {"graph": {}, "summary": "S", "letters": {}, "folder": "f"})[1]
    serve.intake.find = lambda txid, chain="auto": {"chain": "btc", "txid": txid, "candidates": [], "senders": []}
    serve.site_scan.scan = lambda url, **k: {"report": "R", "tier": "LOW", "addresses": [], "domain": "x"}
    serve.operation.collect = lambda chain, addr, key: [
        {"dir": "in", "other": "P%d" % i, "asset": "BTC", "amount": 1.0, "txid": "t%d" % i, "ts": 1700000000 + i * 86400} for i in range(6)]
    serve.case_builder.fetch_balance = lambda chain, addr, key=None: {"BTC": 0.5}
    serve.watch.pending_btc = lambda addr, state, get=None: ["PENDING x"]
    srv = serve.ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def req(method, path, body=None, header=True, host=None, lang=None):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
        c.putrequest(method, path, skip_host=bool(host))
        if host:
            c.putheader("Host", host)
        data = json.dumps(body).encode() if body is not None else b""
        if header:
            c.putheader("X-Tracer", "1")
        if lang:
            c.putheader("X-Lang", lang)
        if body is not None:
            c.putheader("Content-Type", "application/json")
        c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    graph = {"start": "S", "nodes": {"S": {"depth": 0}, "A": {"depth": 1}},
             "edges": [{"from": "S", "to": "A", "txid": "t", "btc": 1.0, "time": 1700000000}], "clusters": []}
    check("server: the site (index.html) is served at /", req("GET", "/")[1] == b"<html>SITE</html>")
    check("server: ping answers without the guard header", req("GET", "/api/ping", header=False)[0] == 200)
    check("server: an /api call without the X-Tracer header is refused (cross-site protection)",
          req("GET", "/api/trace?chain=btc&address=" + btc, header=False)[0] == 403)
    check("server: a request with a foreign Host header is refused", req("GET", "/api/ping", host="evil.com")[0] == 403)
    check("server: trace accepts a valid address, rejects a wrong one",
          req("GET", "/api/trace?chain=btc&address=%s&depth=2" % btc)[0] == 200 and req("GET", "/api/trace?chain=eth&address=bad")[0] == 400)
    check("server: profile, intake and scan routes answer",
          req("GET", "/api/profile?chain=btc&address=" + btc)[1]["report"] == "PROFILE-REPORT"
          and req("GET", "/api/intake?txid=" + "a" * 64)[0] == 200 and req("GET", "/api/scan?url=https://x.example")[1]["tier"] == "LOW")
    st, out = req("GET", "/api/case?chain=btc&address=%s&victim=Test&contact=a@b.c&report_no=7&txid=T&vout=1&stolen=0.5" % btc)
    p = seen.get("params", {})
    check("server: the case route passes the victim's details and the payment outpoint",
          st == 200 and p.get("victim") == "Test" and p.get("report_no") == "7" and p.get("vout") == "1" and p.get("txid") == "T")
    st, out = req("GET", "/api/operation?chain=btc&address=" + btc)
    check("server: payer analysis route works", st == 200 and out["ops"]["payers"] == 6 and out["lines"])
    st, out = req("GET", "/api/balance?chain=btc&address=" + btc)
    check("server: balance route returns the balance and pending spends", st == 200 and out["balance"]["BTC"] == 0.5 and out["pending"] == ["PENDING x"])
    os.environ.pop("CHAINABUSE_KEY", None)
    check("server: public-report lookup without a key gives a clear error, not a crash", req("GET", "/api/reports?chain=btc&address=" + btc)[0] == 400)
    st, out = req("POST", "/api/label", {"address": btc, "label": "Demo Exchange", "category": "exchange", "confidence": "low"})
    st2, out2 = req("GET", "/api/lookup?address=" + btc)
    check("server: a label added from the site is saved and found by lookup",
          st == 200 and st2 == 200 and out2["label"]["label"] == "Demo Exchange" and req("GET", "/api/labels-stats")[1]["total"] == 1)
    check("server: label input is validated",
          req("POST", "/api/label", {"address": "bad", "label": "x", "category": "exchange", "confidence": "low"})[0] == 400
          and req("POST", "/api/label", {"address": btc, "label": "x", "category": "nonsense", "confidence": "low"})[0] == 400)
    st, out = req("POST", "/api/patterns", {"graph": graph})
    check("server: patterns route analyzes a posted graph", st == 200 and out["tier"] == "LOW")
    st, out = req("POST", "/api/verify", {"graph": graph, "no_network": True})
    check("server: verify route returns a verdict", st == 200 and "PASS" in out["verdict"])
    check("server: a malformed graph is refused",
          req("POST", "/api/patterns", {"graph": {"nodes": 1}})[0] == 400 and req("POST", "/api/verify", {})[0] == 400)
    check("server: a POST without the header or with an unknown route is refused",
          req("POST", "/api/patterns", {"graph": graph}, header=False)[0] == 403 and req("POST", "/api/nope", {})[0] == 404)
    v.Recorder(os.path.join(tmp, "evidence")).record("http://x", b"{}")
    check("server: evidence archive check works and refuses paths outside the tools folder",
          req("GET", "/api/archive-check?folder=evidence")[1]["ok"] is True
          and req("GET", "/api/archive-check?folder=../..")[0] == 400 and req("GET", "/api/archive-check?folder=missing")[0] == 400)
    today = __import__("datetime").date.today().isoformat()
    claim = {"case": "C1", "kind": "platform_registration", "subject": "Exchange X", "country": "MT", "source": "Registry extract",
             "source_type": "company_disclosure", "date": today, "method": "official extract"}
    st, out = req("POST", "/api/ledger/add", claim)
    check("server: an evidence claim is added to the ledger", st == 200 and out["id"] == 1)
    check("server: ledger input is validated (bad country, missing source)",
          req("POST", "/api/ledger/add", dict(claim, country="Malta"))[0] == 400 and req("POST", "/api/ledger/add", dict(claim, source=""))[0] == 400)
    st, out = req("GET", "/api/ledger?case=C1")
    check("server: the ledger returns the claims and an assessment where residence stays undetermined",
          st == 200 and len(out["claims"]) == 1 and out["assessment"]["residence"]["status"] == "undetermined" and out["chain_ok"])
    check("server: a ledger request without a case id is refused, and the case list works",
          req("GET", "/api/ledger")[0] == 400 and req("GET", "/api/ledger/cases")[1]["cases"][0]["case_id"] == "C1")
    check("server: ledger verification reports an intact chain with its head hash",
          req("GET", "/api/ledger/verify")[1]["ok"] is True and len(req("GET", "/api/ledger/verify")[1]["head"]) == 64)
    st, out = req("POST", "/api/ledger/add", dict(claim, case="GLOBAL", kind="platform_channel", subject="Demo Exchange", country="", value="legal@demo.example"))
    st2, out2 = req("POST", "/api/ledger/add", dict(claim, case="GLOBAL", subject="Demo Exchange", value="Demo Exchange Ltd"))
    st3, out3 = req("GET", "/api/ledger/platforms")
    check("server: the platform registry route lists entity, country and channel",
          st == 200 and st2 == 200 and st3 == 200 and out3["platforms"][0]["channels"][0]["value"] == "legal@demo.example"
          and out3["platforms"][0]["registration"][0]["entities"] == ["Demo Exchange Ltd"])
    check("server: a bad request channel is refused", req("POST", "/api/ledger/add", dict(claim, case="GLOBAL", kind="platform_channel", value="not a channel"))[0] == 400)
    os.makedirs(os.path.join(tmp, "cases", "C1"))
    json.dump({"start": "S", "chain": "btc", "nodes": {"S": {"depth": 0}, "E": {"depth": 1, "label": "Demo Exchange", "category": "exchange"}},
               "edges": [{"from": "S", "to": "E", "txid": "tx1", "btc": 1.0, "time": 1700000000}]}, open(os.path.join(tmp, "cases", "C1", "graph.json"), "w"))
    st, out = req("GET", "/api/brief?case=C1")
    check("server: the law-enforcement brief route builds and saves the brief", st == 200 and "ملف للجهات المختصة" in out["report"] and "legal@demo.example" in out["report"]
          and out["saved"] and os.path.exists(os.path.join(tmp, out["saved"])))
    check("server: a brief request with a path-traversal case id is refused", req("GET", "/api/brief?case=..%2Fx")[0] == 400)
    p2sh = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    st, out = req("GET", "/api/identify?chain=btc&address=" + btc)
    ent = out["result"]["assessment"]["entity"] if st == 200 else None
    check("server: the identity route reports the label added from the site, as a manual entry with its date and low confidence (weak support)",
          st == 200 and ent["name"] == "Demo Exchange" and out["result"]["assessment"]["status"] == "weak"
          and any(e["source_type"] == "user_statement" for e in out["result"]["evidence"]) and "هوية العنوان والأدلة" in out["report"])
    st, out = req("GET", "/api/identify?chain=btc&address=" + p2sh)
    check("server: an address nobody documented is 'unknown', honestly", st == 200 and out["result"]["assessment"]["status"] == "unknown")
    check("server: identity input is validated (wrong network, bad address)",
          req("GET", "/api/identify?chain=eth&address=" + btc)[0] == 400 and req("POST", "/api/identify", {"chain": "btc", "address": "bad"})[0] == 400)
    st, out = req("POST", "/api/identify", {"chain": "btc", "address": btc, "live": False, "external": False, "graph": graph})
    check("server: the identity route accepts the current graph (for inferences)", st == 200 and out["result"]["address"] == btc)
    st, out = req("POST", "/api/links", {"graph": graph, "address": "S"})
    check("server: the links route returns links and a report with the caveat; a malformed graph is refused",
          st == 200 and "الروابط بين المحافظ" in out["report"] and req("POST", "/api/links", {"graph": {"nodes": 1}})[0] == 400)
    rgraph = {"start": "S", "chain": "btc", "nodes": {"S": {"depth": 0}, p2sh: {"depth": 1, "note": "high activity (900 txs), likely a service; not expanded"}},
              "edges": [{"from": "S", "to": p2sh, "txid": "t1", "btc": 3.0}]}
    st, out = req("POST", "/api/review/enqueue", {"graph": rgraph, "case": "C1"})
    st2, q = req("GET", "/api/review/queue?limit=10")
    check("server: the review queue accepts a graph and lists its addresses with statistics",
          st == 200 and out["added"] == 1 and st2 == 200 and q["items"][0]["address"] == p2sh and q["stats"]["pending"] == 1)
    check("server: a review decision without a reviewer name or with a bad category is refused",
          req("POST", "/api/review/decide", {"address": p2sh, "action": "confirm", "label": "X", "category": "exchange", "confidence": "medium"})[0] == 400
          and req("POST", "/api/review/decide", {"address": p2sh, "action": "confirm", "reviewer": "Sami", "label": "X", "category": "nonsense", "confidence": "medium"})[0] == 400)
    st, out = req("POST", "/api/review/decide", {"address": p2sh, "action": "confirm", "reviewer": "Sami", "label": "Big Service", "category": "custodian", "confidence": "high", "evidence": "https://official.example/addresses"})
    st2, lk = req("GET", "/api/lookup?address=" + p2sh)
    check("server: a confirmed review writes the label (with reviewer) and the lookup route shows it",
          st == 200 and out["status"] == "confirmed" and out["remaining"] == 0 and lk["label"]["label"] == "Big Service" and lk["label"]["review"]["by"] == "Sami")
    stt = req("GET", "/api/review/stats")[1]
    check("server: review statistics report the counts and an intact history", stt["confirmed"] == 1 and stt["history_ok"] is True)
    offi = {"platform": "Demo Exchange", "category": "exchange", "source_url": "https://demo.example/proof", "date": today, "reviewer": "Sami", "text": btc + " " + "0x" + "cd" * 20}
    check("server: an official list import works over https and is refused over http",
          req("POST", "/api/review/import-official", offi)[1].get("addresses") == 2 and req("POST", "/api/review/import-official", dict(offi, source_url="http://demo.example"))[0] == 400)
    bundle = req("GET", "/api/review/bundle")[1]["bundle"]
    bad = json.loads(json.dumps(bundle))
    bad["labels"][p2sh]["label"] = "Tampered"
    check("server: the label bundle route exports a hashed bundle; importing a tampered one is refused",
          bundle["count"] >= 3 and len(bundle["sha256"]) == 64 and req("POST", "/api/review/bundle-import", {"bundle": bad, "name": "b.json", "reviewer": "Sami"})[0] == 400
          and req("POST", "/api/review/bundle-import", {"bundle": bundle, "name": "b.json", "reviewer": "Sami"})[0] == 200)
    st, out = req("POST", "/api/precheck", {"chain": "btc", "address": "", "url": "", "flags": ["withdrawal_fee"], "live": False})
    check("server: the pre-payment route returns STOP for a stop flag, with the report", st == 200 and out["result"]["verdict"] == "STOP" and "فحص قبل الدفع" in out["report"])
    st, out = req("POST", "/api/precheck", {"chain": "btc", "address": btc, "flags": []})
    check("server: the pre-payment route adds the address evidence (a platform label is informational, not a flag)",
          st == 200 and out["result"]["verdict"] == "NO_FLAGS" and any(x["level"] == "info" for x in out["result"]["reasons"]))
    check("server: the pre-payment route refuses unknown flags, non-list flags, an empty request, a wrong-network address and a bad link",
          req("POST", "/api/precheck", {"flags": ["nonsense"]})[0] == 400 and req("POST", "/api/precheck", {"flags": "urgency"})[0] == 400
          and req("POST", "/api/precheck", {})[0] == 400 and req("POST", "/api/precheck", {"chain": "eth", "address": btc})[0] == 400
          and req("POST", "/api/precheck", {"url": "ftp://x"})[0] == 400)
    serve.payments.list_payments = lambda chain, address, amount=None, date=None, window=None, pages=8, key=None: {
        "chain": chain, "address": address, "count": 1, "warning": None, "payments": [{"txid": "t", "vout": 0, "amount": amount, "asset": "BTC", "time_str": date or "", "rank": 0, "amount_match": False, "date_match": False}]}
    st, out = req("GET", "/api/payments?chain=btc&address=" + btc + "&amount=0.5&date=2019-03-14")
    check("server: the payments route passes amount and date and returns the list with its text", st == 200 and out["payments"][0]["amount"] == 0.5 and "المدفوعات الواردة" in out["text"])
    st, out = req("GET", "/api/payments?chain=btc&address=" + btc, lang="ru")
    check("server: X-Lang ru gets the English payments text, and an unknown language is ignored", st == 200 and "Incoming payments" in out["text"]
          and "المدفوعات الواردة" in req("GET", "/api/payments?chain=btc&address=" + btc, lang="xx")[1]["text"])
    check("server: a non-numeric amount is refused", req("GET", "/api/payments?chain=btc&address=" + btc + "&amount=abc")[0] == 400)
    serve.diagnose.diagnose = lambda chain, address, labels, key=None: diagnose_fixture(address)
    st, out = req("GET", "/api/diagnose?chain=btc&address=" + btc)
    check("server: the diagnose route returns the result and the explained lines", st == 200 and out["diagnosis"]["verdict"] == "unclear" and any("تشخيص" in x for x in out["lines"]))
    import sqlite3
    con = sqlite3.connect(os.path.join(tmp, "ledger.db"))
    con.execute("UPDATE claims SET country='CY' WHERE id=1")
    con.commit()
    con.close()
    check("server: tampering with the ledger file is detected through the API", req("GET", "/api/ledger/verify")[1]["ok"] is False)
    srv.shutdown()

def t_capture_payments_diagnose():
    import http.server
    import urllib.error
    import urllib.request
    import capture
    import payments
    import diagnose
    # ---- capture: record against a local server, replay with the server stopped
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if "missing" in self.path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"err":"nf"}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"p": self.path.split("?")[0]}).encode())

        def do_POST(self):
            b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"echo": b["method"]}).encode())
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    rec = os.path.join(tempfile.mkdtemp(), "rec")
    orig = urllib.request.urlopen
    with capture.Capture(rec, hosts={"127.0.0.1"}) as c:
        a1 = urllib.request.urlopen(base + "/a?apikey=SECRET&x=1").read()
        try:
            urllib.request.urlopen(base + "/missing")
            st404 = None
        except urllib.error.HTTPError as e:
            st404 = (e.code, e.read())
        urllib.request.urlopen(urllib.request.Request(base + "/rpc", data=json.dumps({"id": 1, "method": "m"}).encode(), method="POST")).read()
    blob = "".join(open(os.path.join(rec, f), encoding="utf-8").read() for f in os.listdir(rec))
    srv.shutdown()
    srv.server_close()
    check("capture: records the answers, a 404 with its body, and removes the API key from everything stored",
          json.loads(a1)["p"] == "/a" and st404 == (404, b'{"err":"nf"}') and "SECRET" not in blob and len(c.items) == 3)
    with capture.Replay(rec) as rp:
        r1 = urllib.request.urlopen(base + "/a?apikey=OTHERKEY&x=1").read()
        try:
            urllib.request.urlopen(base + "/missing")
            rc = None
        except urllib.error.HTTPError as e:
            rc = (e.code, e.read())
        r3 = urllib.request.urlopen(urllib.request.Request(base + "/rpc", data=json.dumps({"id": 77, "method": "m"}).encode(), method="POST")).read()
        try:
            urllib.request.urlopen(base + "/never")
            miss = False
        except urllib.error.URLError:
            miss = True
    check("capture: replay works offline, ignores the key and the JSON-RPC id, reproduces 404, and a request not recorded fails clearly",
          r1 == a1 and rc == (404, b'{"err":"nf"}') and b"echo" in r3 and miss and len(rp.misses) == 1 and urllib.request.urlopen is orig)
    host_seen = []
    cap2 = capture.Capture(os.path.join(tempfile.mkdtemp(), "r2"))  # default hosts: a local address is NOT recorded
    cap2.install()
    cap2._orig, real = (lambda *a, **k: host_seen.append(1) or (_ for _ in ()).throw(urllib.error.URLError("x"))), cap2._orig
    try:
        urllib.request.urlopen("http://127.0.0.1:9/x")
    except Exception:
        pass
    cap2._orig = real
    cap2.uninstall()
    check("capture: a host outside the public-provider list is passed through and never recorded", host_seen == [1] and not cap2.items)
    check("capture: inspect and pack describe and zip the recording", capture.inspect(rec)["count"] == 3 and capture.pack(rec).endswith(".zip"))

    # ---- payments: the address received two payments and spent once
    T = 1552521600  # 2019-03-14
    S = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    def tx(txid, ins, outs, ts):
        return {"txid": txid, "status": {"block_time": ts}, "vin": [{"prevout": {"scriptpubkey_address": a, "value": v}} for a, v in ins],
                "vout": [{"scriptpubkey_address": a, "value": v} for a, v in outs]}
    txs = [tx("b" * 64, [(S, 400000000)], [("1OUT", 399000000)], T + 9 * 86400),
           tx("a" * 64, [("1VICTIM1", 90000000)], [("1CHG", 29000000), (S, 60000000)], T),
           tx("c" * 64, [("1VICTIM2", 400000000)], [(S, 300000000)], T - 400 * 86400)]

    def get_p(path):
        if path == "/address/" + S:
            return {"chain_stats": {"tx_count": 3, "funded_txo_sum": 360000000, "spent_txo_sum": 400000000}, "mempool_stats": {"tx_count": 0}}
        if path == "/address/%s/txs" % S:
            return txs
        raise AssertionError(path)
    res = payments.list_payments("btc", S, amount=0.6, date="2019-03-14", get=get_p)
    p0 = res["payments"][0]
    check("payments: lists incoming outputs only (the spending tx is skipped), best match first with the exact vout",
          res["count"] == 2 and p0["txid"] == "a" * 64 and p0["vout"] == 1 and p0["amount"] == 0.6 and p0["amount_match"] and p0["date_match"]
          and res["payments"][1]["rank"] == 0 and not res["warning"])
    res2 = payments.list_payments("btc", S, date="2019-03-14", window_days=5, get=get_p)
    check("payments: a date window hides payments outside it", res2["count"] == 1 and res2["payments"][0]["txid"] == "a" * 64)
    try:
        payments.parse_date("14 march")
        bad = False
    except ValueError:
        bad = True
    check("payments: a bad date and a bad address are refused", bad and _raises(lambda: payments.list_payments("btc", "nope", get=get_p)))
    r3_ = payments.list_payments("eth", "0x" + "ab" * 20, 5, None, rows=[{"dir": "in", "other": "0xp", "asset": "USDT", "amount": 5.0, "txid": "0xt", "ts": T},
                                                                     {"dir": "out", "other": "0xq", "asset": "USDT", "amount": 5.0, "txid": "0xu", "ts": T}])
    check("payments: Ethereum/TRON list incoming transfers from the wallet rows", r3_["count"] == 1 and r3_["payments"][0]["amount_match"] and r3_["payments"][0]["vout"] is None)
    # ---- diagnose
    def fake_net(kind):
        def get_d(path):
            A = "1BUSY"
            if path.startswith("/address/") and "/txs" not in path:
                n = 400 if kind == "svc" else 30
                return {"chain_stats": {"tx_count": n, "funded_txo_sum": 10 * 10 ** 8, "spent_txo_sum": 10 * 10 ** 8}, "mempool_stats": {"tx_count": 0}}
            out = []
            for i in range(25 if "/chain/" not in path else 25):
                if kind == "svc":
                    out.append(tx("s%d_%s" % (i, path[-6:]), [(A, 10 ** 8)], [("1D%d_%d" % (i, j), 10 ** 6) for j in range(12)], T - i * 15 * 86400))
                else:
                    out.append(tx("c%d_%s" % (i, path[-6:]), [(A, 10 ** 8)], [("1COLLECT%d" % (i % 2), 10 ** 8)], T - i * 2 * 86400))
            return out if "/chain/" not in path else []
        return get_d
    ds = diagnose.analyze_btc("1BUSY", {}, fake_net("svc"))
    dc = diagnose.analyze_btc("1BUSY", {}, fake_net("col"))
    check("diagnose: batch payouts to many addresses over a long time read as platform-like, with the numbers behind each signal",
          ds["verdict"] == "service-likely" and any("دفعات جماعية" in x["text"] for x in ds["signals"]) and ds["counterparties"])
    check("diagnose: few destinations, small outputs, short period read as collection-like",
          dc["verdict"] == "collection-likely" and any("عنوانًا فقط" in x["text"] for x in dc["signals"]))
    txt = diagnose.report_text(ds)
    check("diagnose: the text never names a person, links the address, and says platform-like is not proof",
          "blockstream.info/address/1BUSY" in txt and "ليس إثباتًا" in txt and "يملك" in txt)
    dr = diagnose.analyze_rows("eth", "0x1", [{"dir": "out", "other": "0x%d" % (i % 3), "asset": "ETH", "amount": 1, "txid": "t%d" % i, "ts": T + i} for i in range(8)])
    check("diagnose: the light Ethereum/TRON version works from rows", dr["verdict"] == "collection-likely")
    import case_builder
    ex = case_builder.extra_lines({"diag": ds})
    check("report: a diagnosis is added to the case report lines", any("تشخيص العنوان" in x for x in ex))

def t_webapp():
    import hashlib
    import hmac as hm
    try:
        import webapp
    except ImportError:
        check("webapp: skipped (the free release does not include the paid-site files)", True)
        return
    tmp = tempfile.mkdtemp()
    webapp.CFG["data"] = tmp
    os.environ.pop("CHECKOUT_URL", None)
    os.environ.pop("WEBHOOK_SECRET", None)
    webapp.env_cfg()
    saved = (webapp.case_builder.run_case, webapp.serve.run_trace, webapp.intake.find, webapp.serve.g_payments, webapp.serve.g_diagnose)
    seen = {"case": 0, "trace": []}
    adr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    adr2 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    def fake_case(chain, addr, depth, stolen, labels, root, params=None, key=None, **k):
        seen["case"] += 1
        os.makedirs(root, exist_ok=True)
        open(os.path.join(root, "x.md"), "w").write("victim")
        return {"graph": {"start": addr, "nodes": {addr: {}}, "edges": []}, "summary": "SUMMARY " + addr, "letters": {"a.md": "L"}, "folder": root, "case_id": "c1"}
    webapp.case_builder.run_case = fake_case
    webapp.serve.run_trace = lambda chain, addr, depth, tokens, taint=False, stolen=None, save=True: (seen["trace"].append((depth, save)), {"start": addr, "nodes": {addr: {}}, "edges": []})[1]
    webapp.intake.find = lambda txid, chain="auto": {"chain": "btc", "txid": txid, "candidates": [], "senders": []}
    webapp.serve.g_payments = lambda q: {"payments": [], "count": 0}
    webapp.serve.g_diagnose = lambda q: {"lines": ["DIAG"], "diagnosis": {}}
    srv = webapp.ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def req(method, path, body=None, headers=None, raw=None, tracer=True):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        c.putrequest(method, path)
        if tracer:
            c.putheader("X-Tracer", "1")
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        b = r.read()
        try:
            return r.status, json.loads(b)
        except ValueError:
            return r.status, b
    check("webapp: ping says public and config shows the price and that selling is not configured yet",
          req("GET", "/api/ping", tracer=False)[1] == {"ok": True, "public": True} and req("GET", "/api/config", tracer=False)[1]["selling"] is False
          and req("GET", "/api/config", tracer=False)[1]["price"] == "60$")
    check("webapp: an /api call without the header, and an unknown or local-only route, are refused",
          req("GET", "/api/trace?address=x", tracer=False)[0] == 403 and req("GET", "/api/ledger")[0] == 404 and req("POST", "/api/label", {})[0] == 404
          and req("GET", "/api/scan?url=http://x")[0] == 404 and req("GET", "/api/profile?address=x")[0] == 404)
    st, out = req("GET", "/api/trace?chain=btc&address=%s&depth=5" % adr)
    check("webapp: the free trace is capped at depth 3 and never writes the shared graph file", st == 200 and seen["trace"][-1] == (3, False))
    check("webapp: the free reader and payments list work without a code", req("GET", "/api/intake?txid=" + "a" * 64)[0] == 200 and req("GET", "/api/payments?chain=btc&address=" + adr)[0] == 200)
    st, out = req("POST", "/api/precheck", {"url": "https://x.example"})
    check("webapp: the pre-payment check refuses link scanning in the public version", st == 400)
    q = "/api/case?chain=btc&address=" + adr + "&victim=Name"
    st, out = req("GET", q)
    check("webapp: the full case without a code asks for payment", st == 402 and out["pay"] is True and seen["case"] == 0)
    pend = webapp.create_order()
    st, out = req("GET", q, headers={"X-Order": pend})
    check("webapp: an unpaid code is refused as pending", st == 402 and out.get("pending") is True)
    check("webapp: a malformed code is treated as no code", req("GET", q, headers={"X-Order": "'; DROP TABLE orders;--"})[0] == 402)
    code = webapp.create_order(paid=True)
    st, out = req("GET", q, headers={"X-Order": code})
    check("webapp: a paid code builds the case once and returns the result without any server path",
          st == 200 and "SUMMARY" in out["summary"] and out["folder"] == "" and seen["case"] == 1)
    st2, out2 = req("GET", q, headers={"X-Order": code})
    check("webapp: asking again returns the saved case without rebuilding", st2 == 200 and out2["summary"] == out["summary"] and seen["case"] == 1)
    check("webapp: the working folder with the case text is deleted after the build", not os.path.exists(os.path.join(tmp, "work", code)))
    st, out = req("GET", "/api/case?chain=btc&address=" + adr2, headers={"X-Order": code})
    check("webapp: the same code cannot open a different address", st == 403 and seen["case"] == 1)
    st, out = req("GET", "/api/diagnose?chain=btc&address=" + adr, headers={"X-Order": code})
    check("webapp: the diagnosis works for the bound address with the code, and not without it or for another address",
          st == 200 and out["lines"] == ["DIAG"] and req("GET", "/api/diagnose?chain=btc&address=" + adr)[0] == 402
          and req("GET", "/api/diagnose?chain=btc&address=" + adr2, headers={"X-Order": code})[0] == 403)
    other = webapp.create_order(paid=True)
    check("webapp: extras need the case to be built first", req("GET", "/api/diagnose?chain=btc&address=" + adr, headers={"X-Order": other})[0] == 400)
    # ---- payments notice
    os.environ["WEBHOOK_SECRET"] = "s3cret"
    os.environ["CHECKOUT_URL"] = "https://shop.example/buy/abc"
    sec = "s3cret"

    def notice(code_, ref="900", status="paid", total=6000, test=False, event="order_created", secret=sec, sig=None):
        body = json.dumps({"meta": {"event_name": event, "custom_data": {"code": code_}}, "data": {"id": ref, "attributes": {"status": status, "total": total, "test_mode": test}}}).encode()
        s_ = sig if sig is not None else hm.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return req("POST", "/webhook/payment", raw=body, headers={"X-Signature": s_, "Content-Type": "application/json"}, tracer=False)
    c1 = webapp.create_order()
    check("webapp: a notice with a bad or missing signature is refused and pays nothing", notice(c1, sig="00")[0] == 401 and webapp.get_order(c1)["status"] == "pending")
    check("webapp: a signed paid notice marks the code paid", notice(c1)[0] == 200 and webapp.get_order(c1)["status"] == "paid")
    c2 = webapp.create_order()
    notice(c2, ref="900")
    check("webapp: a payment reference cannot be reused for a second code", webapp.get_order(c2)["status"] == "pending")
    c3 = webapp.create_order()
    notice(c3, ref="901", test=True)
    notice(c3, ref="902", total=100)
    notice(c3, ref="903", status="pending")
    check("webapp: test-mode, too-cheap and unpaid notices do not unlock", webapp.get_order(c3)["status"] == "pending")
    notice(c1, ref="900", event="order_refunded")
    check("webapp: a refund notice revokes the code", webapp.get_order(c1)["status"] == "refunded"
          and req("GET", "/api/case?chain=btc&address=" + adr2, headers={"X-Order": c1})[0] == 402)
    del os.environ["WEBHOOK_SECRET"]
    check("webapp: without a configured secret the notice endpoint is closed", notice(c3)[0] == 503)
    os.environ["WEBHOOK_SECRET"] = sec
    st, out = req("POST", "/api/order/new", {})
    check("webapp: a new order returns a code and a checkout link that carries it",
          st == 200 and webapp.CODE_RE.match(out["code"]) and "checkout[custom][code]=" + out["code"] in out["checkout_url"] and out["checkout_url"].startswith("https://shop.example/buy/abc?"))
    check("webapp: the status route reports the state of a code", req("GET", "/api/order/status?code=" + out["code"])[1]["status"] == "pending"
          and req("GET", "/api/order/status?code=bad")[1]["status"] == "unknown")
    # ---- expiry, limits, legal
    db = webapp.connect()
    db.execute("UPDATE orders SET paid_at=? WHERE code=?", (int(__import__("time").time()) - 40 * 86400, code))
    db.commit()
    db.close()
    webapp.purge()
    o = webapp.get_order(code)
    check("webapp: after the retention period the case text and address are deleted and the code expires", o["status"] == "expired" and o["case_json"] is None and o["address"] is None
          and req("GET", q, headers={"X-Order": code})[0] == 410)
    webapp.HITS.clear()
    check("webapp: the per-address rate limit stops a flood", all(webapp.rate_ok("trace", "9.9.9.9", now=1000.0 + i) for i in range(12)) and not webapp.rate_ok("trace", "9.9.9.9", now=1100.0))
    st, body = req("GET", "/terms", tracer=False)
    st2, body2 = req("GET", "/privacy", tracer=False)
    check("webapp: terms and privacy pages say it is not a recovery service and what is kept and for how long",
          st == 200 and "ليست خدمة استرداد" in body.decode() and st2 == 200 and "30 يومًا" in body2.decode())
    srv.shutdown()
    webapp.case_builder.run_case, webapp.serve.run_trace, webapp.intake.find, webapp.serve.g_payments, webapp.serve.g_diagnose = saved
    os.environ.pop("WEBHOOK_SECRET", None)
    os.environ.pop("CHECKOUT_URL", None)

def t_more_chains():
    import urllib.error
    import acct_tracer
    import btc_tracer
    import case_builder
    import chains
    import evm_api
    import intake
    import payments
    import diagnose
    import sol_api
    import utxo_shim
    import verify as v
    # ---- registry and address validation
    good = {"btc": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "ltc": "LbTjMGN7gELw4KbeyQf6cTCq859hD18guE", "doge": "D8mQ2sKYpLbFCrhjCpCz2kyFnGnQ7XSXnH",
            "bch": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "eth": "0x" + "ab" * 20, "bsc": "0x" + "AB" * 20, "polygon": "0x" + "cd" * 20,
            "arbitrum": "0x" + "ef" * 20, "base": "0x" + "12" * 20, "tron": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            "sol": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"}
    check("chains: every supported network accepts a valid address and normalises it (EVM lowercase)",
          all(case_builder.valid_address(c, a) for c, a in good.items()) and case_builder.valid_address("bsc", good["bsc"]) == good["bsc"].lower()
          and set(good) == set(chains.ORDER))
    check("chains: a wrong-network address and an unknown network are refused",
          _raises(lambda: case_builder.valid_address("ltc", good["eth"])) and _raises(lambda: case_builder.valid_address("bsc", good["tron"]))
          and _raises(lambda: case_builder.valid_address("xyz", "a")))
    check("chains: only Bitcoin, Ethereum and TRON are marked as designed against checked documentation",
          [c for c in chains.ORDER if chains.tested(c)] == ["btc", "eth", "tron"])
    # ---- EVM: another network through the same reader (Blockscout shape)
    A = "0x" + "11" * 20
    B = "0x" + "22" * 20
    USDT_BSC = "0x55d398326f99059ff775485246999027b3197955"
    calls = []

    def fake_http(url, headers=None):
        calls.append(url)
        if "bsc.blockscout.com" in url and url.split("?")[0].endswith("/transactions"):
            return {"items": [{"from": {"hash": A}, "to": {"hash": B}, "value": str(2 * 10 ** 18), "status": "ok", "hash": "0xh1", "timestamp": "2024-01-01T00:00:00.000000Z"}]}
        if "bsc.blockscout.com" in url and "token-transfers" in url:
            return {"items": [{"from": {"hash": A}, "to": {"hash": B}, "token": {"address_hash": USDT_BSC, "decimals": "18"},
                               "total": {"value": str(500 * 10 ** 18), "decimals": "18"}, "transaction_hash": "0xh2", "timestamp": "2024-01-01T00:00:00.000000Z"}]}
        raise AssertionError(url)
    keep = acct_tracer.http
    acct_tracer.http = fake_http
    evm_api.DELAY = 0
    out, busy = acct_tracer.eth_out(A, types.SimpleNamespace(api_key=None, max_pages=2, all_tokens=False, internal=False), "bsc")
    check("evm: BNB Chain transfers are read through its own provider, with BNB as the native coin and USDT at 18 decimals",
          sorted((t["asset"], t["amount"]) for t in out) == [("BNB", 2.0), ("USDT", 500.0)] and all("bsc.blockscout.com" in u for u in calls))

    # the first provider fails -> the Etherscan-style provider answers (needs a key), translated to the same shape
    def http2(url, headers=None):
        if "blockscout" in url or "routescan" in url:
            raise urllib.error.URLError("down")
        if "action=txlist" in url and "page=1" in url:
            return {"status": "1", "result": [{"hash": "0xh1", "from": A, "to": B, "value": "1000000000000000000", "isError": "0", "timeStamp": "1704067200"}]}
        if "action=tokentx" in url:
            return {"status": "0", "message": "No transactions found", "result": []}
        raise AssertionError(url)
    acct_tracer.http = http2
    os.environ["ETHERSCAN_API_KEY"] = "K"
    out2, _ = acct_tracer.eth_out(A, types.SimpleNamespace(api_key=None, max_pages=1, all_tokens=False, internal=False), "polygon")
    check("evm: when the first provider is down the second is used and translated (native coin POL)", len(out2) == 1 and out2[0]["asset"] == "POL" and out2[0]["amount"] == 1.0 and out2[0]["txid"] == "0xh1")
    del os.environ["ETHERSCAN_API_KEY"]
    check("evm: with no provider reachable and no key the error says so in plain words", _raises(lambda: acct_tracer.eth_out(A, types.SimpleNamespace(api_key=None, max_pages=1, all_tokens=False, internal=False), "base")))
    acct_tracer.http = keep
    # intake of a BNB Chain USDT payment (18 decimals)
    topic = v.TRANSFER_TOPIC

    def rpc(method, params):
        if method == "eth_getTransactionByHash":
            return {"from": A, "to": USDT_BSC, "value": "0x0"}
        if method == "eth_getTransactionReceipt":
            return {"status": "0x1", "blockNumber": "0x10", "logs": [{"address": USDT_BSC, "topics": [topic, "0x" + "0" * 24 + "11" * 20, "0x" + "0" * 24 + "22" * 20], "data": hex(250 * 10 ** 18)}]}
        return {"timestamp": "0x65920080"}
    r = intake.find("0x" + "a" * 64, "bsc", call=rpc)
    check("intake: a BNB Chain USDT payment is decoded with 18 decimals and the right network", r["chain"] == "bsc" and r["candidates"][0]["amount"] == 250.0 and r["candidates"][0]["asset"] == "USDT")
    check("intake: a hash is matched to every plausible network (0x -> all EVM, 64 hex -> UTXO chains and TRON, long base58 -> Solana)",
          intake.detect_chains("0x" + "a" * 64)[0] == "eth" and "bsc" in intake.detect_chains("0x" + "a" * 64) and intake.detect_chains("a" * 64)[:2] == ["btc", "tron"]
          and "ltc" in intake.detect_chains("a" * 64) and intake.detect_chains("5" * 88) == ["sol"])
    # EVM balance on another network via the second reader
    keep_a, keep_t = evm_api.address_info, evm_api.token_balances
    evm_api.address_info = lambda ch, a_, k=None: {"coin_balance": str(3 * 10 ** 18)}
    evm_api.token_balances = lambda ch, a_, k=None: [{"token": {"address_hash": USDT_BSC, "decimals": "18"}, "value": str(40 * 10 ** 18)}]
    bal = case_builder.fetch_balance("bsc", A)
    evm_api.address_info, evm_api.token_balances = keep_a, keep_t
    check("evm: the balance on BNB Chain is BNB plus the supported stablecoin", bal == {"BNB": 3.0, "USDT": 40.0})
    # second-source verification of an EVM edge on another network
    edge = {"from": A, "to": B, "txid": "0xh2", "asset": "USDT", "amount": 250.0}

    def rpc2(method, params):
        if method == "eth_getTransactionByHash":
            return {"from": A, "to": USDT_BSC, "value": "0x0"}
        if method == "eth_getTransactionReceipt":
            return {"status": "0x1", "blockNumber": "0x10", "logs": [{"address": USDT_BSC, "topics": [topic, "0x" + "0" * 24 + "11" * 20, "0x" + "0" * 24 + "22" * 20], "data": hex(250 * 10 ** 18)}]}
        return "0x1000"
    check("verify: a BNB Chain stablecoin transfer is confirmed with the right decimals", v.verify_eth_edge(edge, rpc2, "bsc")[0] == "ok")
    # ---- Bitcoin-like: Litecoin through the same code with a different provider, symbol on every edge
    seen_urls = []
    real_open = btc_tracer.urllib.request.urlopen

    class R:
        def __init__(self, d):
            self.d = d

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return json.dumps(self.d).encode()
    btc_tracer.urllib.request.urlopen = lambda req, timeout=0: (seen_urls.append(req.full_url), R(7))[1]
    import importlib.util
    spec = importlib.util.spec_from_file_location("btc_tracer_fresh", os.path.join(HERE, "btc_tracer.py"))
    fresh = importlib.util.module_from_spec(spec)  # earlier tests replace btc_tracer.get: test an untouched copy
    spec.loader.exec_module(fresh)
    with fresh.use_chain("ltc"):
        h = fresh.get("/blocks/tip/height")
    with fresh.use_chain("btc"):
        fresh.get("/blocks/tip/height")
    btc_tracer.urllib.request.urlopen = real_open
    check("utxo: Litecoin reads go to its own provider and Bitcoin reads still go to Bitcoin's", h == 7 and "litecoinspace.org" in seen_urls[0] and seen_urls[1].startswith("https://blockstream.info/api"))
    L1, L2 = good["ltc"], "LNNJmnsF1XnJmD8GeBTJYXGq6qixzHm6dQ"

    def fake_get(path):
        if path == "/address/" + L1:
            return {"chain_stats": {"tx_count": 1, "funded_txo_sum": 10 ** 8, "spent_txo_sum": 10 ** 8}, "mempool_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0}}
        if path.startswith("/address/" + L1 + "/txs"):
            return [{"txid": "t" * 64, "status": {"block_time": 1700000000, "confirmed": True}, "vin": [{"prevout": {"scriptpubkey_address": L1, "value": 10 ** 8}}],
                     "vout": [{"scriptpubkey_address": L2, "value": 10 ** 8 - 1000}]}]
        if path.startswith("/address/" + L2):
            return {"chain_stats": {"tx_count": 1, "funded_txo_sum": 10 ** 8, "spent_txo_sum": 0}, "mempool_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0}} if path == "/address/" + L2 else []
        raise AssertionError(path)
    keep_get = btc_tracer.get
    btc_tracer.get = fake_get
    btc_tracer.DELAY = 0
    g = case_builder.trace_chain("ltc", L1, 1, None, {})
    bal = case_builder.fetch_balance("ltc", L1)
    btc_tracer.get = keep_get
    check("utxo: a Litecoin trace says LTC on the graph and on every edge, and the balance is in LTC",
          g["chain"] == "ltc" and g["edges"] and all(e["asset"] == "LTC" for e in g["edges"]) and list(bal) == ["LTC"])
    check("utxo: the payment list and the behaviour diagnosis name the right coin",
          payments.list_payments("ltc", L1, get=lambda p: fake_get(p) if "/txs" in p or p == "/address/" + L1 else {})["chain"] == "ltc"
          and diagnose.EXPLORER["ltc"].startswith("https://litecoinspace.org"))
    # ---- Dogecoin / Bitcoin Cash through the Blockchair adapter
    def fake_call(chain, path, params=None):
        if path.startswith("/dashboards/address/"):
            a_ = path.rsplit("/", 1)[1]
            return {a_: {"address": {"transaction_count": 2, "received": 500, "spent": 100}, "transactions": ["h1", "h2"]}}
        if path.startswith("/dashboards/transactions/"):
            return {h_: {"transaction": {"hash": h_, "block_id": 100, "time": "2024-01-01 00:00:00"},
                         "inputs": [{"recipient": "DIN", "value": 1000, "transaction_hash": "p", "index": 0}],
                         "outputs": [{"recipient": "DOUT", "value": 900, "is_spent": True, "spending_transaction_id": "s1"}, {"recipient": "", "type": "nulldata", "value": 0}]} for h_ in path.rsplit("/", 1)[1].split(",")}
        if path.startswith("/dashboards/transaction/"):
            h_ = path.rsplit("/", 1)[1]
            return {h_: {"transaction": {"hash": h_, "block_id": 100, "time": "2024-01-01 00:00:00"}, "inputs": [{"recipient": "DIN", "value": 1000}],
                         "outputs": [{"recipient": "DOUT", "value": 900, "is_spent": True, "spending_transaction_id": "s1"}]}}
        if path == "/stats":
            return {"blocks": 5000001}
    keep_call = utxo_shim._call
    utxo_shim._call = fake_call
    info = utxo_shim.get("doge", "/address/DIN")
    txs = utxo_shim.get("doge", "/address/DIN/txs")
    one = utxo_shim.get("doge", "/tx/h1")
    osp = utxo_shim.get("doge", "/tx/h1/outspends")
    tip = utxo_shim.get("doge", "/blocks/tip/height")
    utxo_shim._call = keep_call
    check("utxo: the Blockchair adapter returns the Esplora shape the Bitcoin tools read (stats, paged transactions, one transaction, outspends, tip)",
          info["chain_stats"]["tx_count"] == 2 and len(txs) == 2 and txs[0]["vin"][0]["prevout"]["scriptpubkey_address"] == "DIN" and txs[0]["vout"][0]["value"] == 900
          and txs[0]["vout"][1]["scriptpubkey_address"] is None and one["status"]["block_time"] == 1704067200 and osp[0] == {"spent": True, "txid": "s1", "vin": None, "status": {"confirmed": True}}
          and tip == 5000000)
    # ---- Solana from balance changes
    S1, S2, S3 = good["sol"], "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", "7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj"
    USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

    def stx(err=None):
        return {"blockTime": 1704067200, "meta": {"err": err, "fee": 5000, "preBalances": [3 * 10 ** 9, 10 ** 9, 0], "postBalances": [3 * 10 ** 9 - 5000 - 10 ** 9, 2 * 10 ** 9, 0],
                "preTokenBalances": [{"accountIndex": 0, "mint": USDC, "owner": S1, "uiTokenAmount": {"amount": "250000000", "decimals": 6}}],
                "postTokenBalances": [{"accountIndex": 0, "mint": USDC, "owner": S1, "uiTokenAmount": {"amount": "50000000", "decimals": 6}},
                                      {"accountIndex": 2, "mint": USDC, "owner": S3, "uiTokenAmount": {"amount": "200000000", "decimals": 6}}]},
                "transaction": {"message": {"accountKeys": [{"pubkey": S1}, {"pubkey": S2}, {"pubkey": S3}]}}}
    tr = sorted((t["asset"], t["to"], round(t["amount"], 6)) for t in sol_api.transfers(stx(), "sig1"))
    check("solana: SOL and USDC transfers are read from balance changes (the fee is not counted as a payment)",
          tr == [("SOL", S2, 1.0), ("USDC", S3, 200.0)] and all(t["frm"] == S1 for t in sol_api.transfers(stx(), "sig1")) and sol_api.transfers(stx({"x": 1}), "s") == [])

    def srpc(method, params):
        if method == "getTransaction":
            return stx()
        if method == "getSignaturesForAddress":
            return [{"signature": "sig1", "err": None}, {"signature": "sigbad", "err": {"x": 1}}]
        if method == "getBalance":
            return {"value": 2 * 10 ** 9}
        if method == "getTokenAccountsByOwner":
            return {"value": [{"account": {"data": {"parsed": {"info": {"mint": USDC, "tokenAmount": {"uiAmount": 12.5}}}}}}]}
    keep_rpc = sol_api.rpc
    sol_api.rpc = srpc
    ns = types.SimpleNamespace(max_pages=1, all_tokens=False, api_key=None)
    out, busy = sol_api.sol_out(S1, ns)
    rows, _, _ = sol_api.collect_sol(S3, ns)
    ri = intake.find("5" * 88, "sol")
    bal = sol_api.fetch_balance(S1)
    g = acct_tracer.trace("sol", S1, types.SimpleNamespace(depth=1, min_stable=10, min_native=None, max_pages=1, max_fanout=30, all_tokens=False, api_key=None), {})
    sol_api.rpc = keep_rpc
    check("solana: outgoing transfers, wallet rows, intake, balance and the trace all work from the same reader",
          len(out) == 2 and not busy and rows[0]["dir"] == "in" and rows[0]["asset"] == "USDC" and ri["chain"] == "sol" and ri["candidates"][0]["asset"] == "USDC"
          and bal == {"SOL": 2.0, "USDC": 12.5} and g["edges"] and g["nodes"][S3]["depth"] == 1)
    check("solana: a failed or empty transaction is refused clearly", _raises(lambda: (setattr(sol_api, "rpc", lambda m, p: stx({"e": 1})), sol_api.intake_sol("x"))[1]))
    sol_api.rpc = keep_rpc
    evm_api.DELAY = 0.4
    btc_tracer.DELAY = 0.4


def t_label_addresses():
    import labels_tool as L
    txt = "pay 3HfJ6brzer2fZob1ZZCyeUUUTD6vzXWdJv or bc1qpy4jwethqenp4r7hqls660wy8287vw0my32lmy; typo 3HfJ6brzer2fZob1ZZCyeUUUTD6vzXWdJX and 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    check("labels: addresses are pulled out of free text and a mistyped one (bad checksum) or a hash is ignored",
          L.extract_addresses(txt) == ["3HfJ6brzer2fZob1ZZCyeUUUTD6vzXWdJv", "bc1qpy4jwethqenp4r7hqls660wy8287vw0my32lmy"])
    ok = [("LZ6PMnHdPFRcfPhZCHBCEvEVmLeMhE2HW8", "LZ6PMnHdPFRcfPhZCHBCEvEVmLeMhE2HW8"), ("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"),
          ("9wzG7dqz5nDMqWbpP5C1wR1xqZGZ3q8pJrMGsxn2vJzG", "9wzG7dqz5nDMqWbpP5C1wR1xqZGZ3q8pJrMGsxn2vJzG"),
          ("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")]
    check("labels: Litecoin, Dogecoin, Solana and Bitcoin Cash addresses are accepted (they used to be dropped silently)", all(L.norm(a) == b for a, b in ok))
    check("labels: garbage and short text are still refused", L.norm("garbage") is None and L.norm("0x123") is None and L.norm("") is None)


for fn in (t_label_addresses, t_bitcoin, t_labels, t_account_chains, t_profile, t_verify, t_case, t_sites, t_intake_and_inference, t_advanced, t_utxo, t_deep_bitcoin, t_ledger, t_brief, t_live_check, t_identity, t_review, t_precheck, t_leads, t_investigate, t_capture_payments_diagnose, t_more_chains, t_languages, t_platform_mix, t_webapp, t_server):
    section(fn)
print("\n%s" % ("ALL CHECKS PASSED: the files are intact." if not FAILS else "FAILED: %s" % ", ".join(FAILS)))
sys.exit(1 if FAILS else 0)
