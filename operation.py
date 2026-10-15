#!/usr/bin/env python3
"""
operation.py - is this wallet one victim's story, or an operation with many payers? Python 3.8+.
Also holds the local graph store (SQLite) that links your cases together.

    python operation.py btc ADDRESS              who paid into this wallet, how much, over what period
    python operation.py shared [--db cases/cases.db]     addresses that appear in more than one case

Many distinct payers sending to one wallet over days or weeks is how scam collection wallets look,
and it turns a single complaint into an organized pattern. Payers are only POSSIBLE victims: they can
also be exchanges, refunds or unrelated customers. Say so when you report it.
"""
import argparse
import json
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone

import acct_tracer
import chains
import wallet_profile


# ---------------- who paid in ----------------
def analyze(rows, labels):
    ins = [r for r in rows if r["dir"] == "in"]
    by = defaultdict(lambda: {"n": 0, "total": defaultdict(float)})
    for r in ins:
        by[r["other"]]["n"] += 1
        by[r["other"]]["total"][r["asset"]] += r["amount"]
    totals = defaultdict(float)
    for r in ins:
        totals[r["asset"]] += r["amount"]
    ts = [r["ts"] for r in ins if r["ts"]]
    top = sorted(by.items(), key=lambda kv: -sum(kv[1]["total"].values()))[:5]
    labeled = [a for a in by if acct_tracer.label_info(labels, a)]
    return {"payers": len(by), "payments": len(ins), "totals": dict(totals),
            "first": min(ts) if ts else None, "last": max(ts) if ts else None,
            "top": [(a, v["n"], dict(v["total"])) for a, v in top], "labeled_payers": len(labeled)}


def lines_ar(ops):
    when = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d")
    tot = ", ".join("%.4f %s" % (v, k) for k, v in ops["totals"].items()) or "-"
    L = ["- عدد الجهات التي دفعت إلى هذا العنوان: %d (%d دفعة، الإجمالي %s)" % (ops["payers"], ops["payments"], tot)]
    if ops["first"]:
        L.append("- الفترة: من %s إلى %s" % (when(ops["first"]), when(ops["last"])))
    if ops["payers"] >= 5:
        L.append("- كثرة الدافعين تشير إلى عنوان تجميع وليس حالة فردية، لكنهم قد يضمّون غير الضحايا (منصات، استردادات، أو محافظ يملكها صاحب الحساب نفسه). "
                 "يُذكر في البلاغ على أنهم ضحايا محتملون.")
    if ops["labeled_payers"]:
        L.append("- منهم %d جهة معروفة في قاعدة التصنيفات (غالبًا دفعوا من حسابات بورصات)." % ops["labeled_payers"])
    return L


def collect(chain, addr, key=None):
    import types
    args = types.SimpleNamespace(max_txs=500, max_pages=6, all_tokens=False, api_key=key)
    rows, info, trunc = wallet_profile.collect(chain, addr.lower() if chains.is_evm(chain) else addr, args)
    return rows


# ---------------- local graph store ----------------
SCHEMA = """CREATE TABLE IF NOT EXISTS cases(name TEXT PRIMARY KEY, chain TEXT, start TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS nodes(case_name TEXT, address TEXT, label TEXT, category TEXT, taint REAL);
CREATE TABLE IF NOT EXISTS edges(case_name TEXT, src TEXT, dst TEXT, txid TEXT, asset TEXT, amount REAL);
CREATE INDEX IF NOT EXISTS nodes_addr ON nodes(address);"""


def connect(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def add_case(path, name, g):
    db = connect(path)
    with db:
        db.execute("INSERT OR REPLACE INTO cases VALUES(?,?,?,?)", (name, g.get("chain", "btc"), g["start"],
                                                                    datetime.now(timezone.utc).isoformat()))
        db.execute("DELETE FROM nodes WHERE case_name=?", (name,))
        db.execute("DELETE FROM edges WHERE case_name=?", (name,))
        db.executemany("INSERT INTO nodes VALUES(?,?,?,?,?)", [(name, a, n.get("label"), n.get("category"), n.get("taint"))
                                                             for a, n in g["nodes"].items()])
        db.executemany("INSERT INTO edges VALUES(?,?,?,?,?,?)", [
            (name, e["from"], e["to"], e["txid"], e.get("asset", "BTC"),
             e["taint"] if e.get("taint") is not None else e.get("amount", e.get("btc", 0))) for e in g["edges"]])
    db.close()


def seen_before(path, addresses):
    if not os.path.exists(path):
        return {}
    db = connect(path)
    out = defaultdict(list)
    for i in range(0, len(addresses), 500):
        chunk = addresses[i:i + 500]
        q = "SELECT address, case_name FROM nodes WHERE address IN (%s)" % ",".join("?" * len(chunk))
        for a, c in db.execute(q, chunk):
            out[a].append(c)
    db.close()
    return dict(out)


def shared(path):
    db = connect(path)
    rows = db.execute("SELECT address, COUNT(DISTINCT case_name), GROUP_CONCAT(DISTINCT case_name) FROM nodes "
                      "GROUP BY address HAVING COUNT(DISTINCT case_name) >= 2 ORDER BY 2 DESC").fetchall()
    db.close()
    return rows


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in chains.ORDER:
        sub.add_parser(c).add_argument("address")
    p = sub.add_parser("shared")
    p.add_argument("--db", default="cases/cases.db")
    a = ap.parse_args()
    if a.cmd == "shared":
        for addr, n, cases in shared(a.db):
            print("%s appears in %d cases: %s" % (addr, n, cases))
        return
    labels = json.load(open("labels.json", encoding="utf-8")) if os.path.exists("labels.json") else {}
    ops = analyze(collect(a.cmd, a.address, os.environ.get("TRACER_API_KEY")), labels)
    print("\n".join(lines_ar(ops)))
    for addr, n, tot in ops["top"]:
        print("  %s: %d دفعة %s" % (addr, n, tot))


if __name__ == "__main__":
    main()
