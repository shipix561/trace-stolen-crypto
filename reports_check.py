#!/usr/bin/env python3
"""
reports_check.py - has this address been reported as a scam? (Chainabuse public reports). Python 3.8+.

    export CHAINABUSE_KEY=your_key            (Windows: set CHAINABUSE_KEY=your_key)
    python reports_check.py check ADDRESS [--chain btc|eth|tron] [--refresh]
    python reports_check.py check-graph graph.json [--max 3] [--dry-run]
    python reports_check.py usage

API (from the provider's documentation): GET https://api.chainabuse.com/v0/reports?address=...&chain=...
with HTTP Basic authentication, the API key used as both username and password. A standard key has a
usage limit of 10 calls per month (one call returns up to 50 reports), so this tool:
  - caches every answer (reports_cache.json) and never re-asks unless you pass --refresh;
  - counts calls per month (reports_usage.json) and refuses to exceed --limit (default 10);
  - check-graph spends calls only on the few addresses that matter most (--max).
No key? Search the address on the Chainabuse website for free, one at a time.

How to read the result:
  - Reports are written by users. Chainabuse labels some as trusted contributor or checked by moderators.
  - One unchecked report is an allegation, not a fact. Only addresses with 2+ reports of which at least
    one is checked/trusted are labeled "scam" (medium confidence); anything else is labeled "reported" (low).
  - Contact details the reporters list about the accused (names, handles) are NOT copied by this tool:
    read them on the Chainabuse report itself (IDs are shown), and give them to law enforcement.
  - Please also REPORT your own case there: the provider says linking several victims' reports of the
    same scam raises the chance that funds are recovered.
"""
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone

import labels_tool

API = "https://api.chainabuse.com/v0"
CHAIN = {"btc": "BTC", "eth": "ETH", "tron": "TRON"}  # networks Chainabuse lookups are written for; others are skipped
CACHE_FILE, USAGE_FILE = "reports_cache.json", "reports_usage.json"


def _load(path):
    return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}


def _save(path, data):
    json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def month():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def calls_used(base_dir="."):
    return _load(os.path.join(base_dir, USAGE_FILE)).get(month(), 0)


def fetch(url, key):
    tok = base64.b64encode(("%s:%s" % (key, key)).encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + tok, "Accept": "application/json",
                                               "User-Agent": "reports-check/0.1"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)


def summarize(d):
    reps = d.get("reports", [])
    losses = defaultdict(float)
    for r in reps:
        for l in r.get("losses") or []:
            losses[l.get("asset", "?")] += l.get("amount", 0)
    dates = sorted(r["createdAt"][:10] for r in reps if r.get("createdAt"))
    return {"count": d.get("count", len(reps)), "returned": len(reps),
            "checked": sum(1 for r in reps if r.get("checked")), "trusted": sum(1 for r in reps if r.get("trusted")),
            "categories": dict(Counter((r.get("scamCategory") or "UNSPECIFIED") for r in reps)),
            "losses": dict(losses),
            "domains": sorted({a["domain"] for r in reps for a in r.get("addresses", []) if a.get("domain")})[:10],
            "first": dates[0] if dates else None, "last": dates[-1] if dates else None,
            "ids": [r["id"] for r in reps[:5] if r.get("id")],
            "contacts_listed": sum(len(s.get("info", [])) for r in reps for s in (r.get("accusedScammers") or []))}


def lookup(address, chain="btc", key=None, limit=10, base_dir=".", refresh=False, fetch_fn=None):
    cache_path = os.path.join(base_dir, CACHE_FILE)
    cache, ck = _load(cache_path), "%s:%s" % (chain, address)
    if ck in cache and not refresh:
        return dict(cache[ck], cached=True)
    if chain not in CHAIN:
        raise RuntimeError("Chainabuse lookup is not wired for this network yet; search the address on their website.")
    if not key:
        raise RuntimeError("No Chainabuse API key (set CHAINABUSE_KEY). You can search the address on the Chainabuse website instead.")
    usage_path = os.path.join(base_dir, USAGE_FILE)
    usage = _load(usage_path)
    if usage.get(month(), 0) >= limit:
        raise RuntimeError("Monthly call limit reached (%d). Raise --limit only if your key allows it." % limit)
    url = "%s/reports?%s" % (API, urllib.parse.urlencode({"address": address, "chain": CHAIN[chain], "perPage": 50}))
    try:
        d = (fetch_fn or fetch)(url, key)
    except urllib.error.HTTPError as e:
        raise RuntimeError("Chainabuse refused the request (HTTP %d): check the key and the address." % e.code)
    usage[month()] = usage.get(month(), 0) + 1
    _save(usage_path, usage)
    s = summarize(d)
    s["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cache[ck] = s
    _save(cache_path, cache)
    return s


def label_from(s):
    if not s["count"]:
        return None
    if s["count"] >= 2 and (s["checked"] or s["trusted"]):
        return ("Reported scam (Chainabuse, %d reports)" % s["count"], "scam", "medium")
    return ("Reported on Chainabuse (%d report%s)" % (s["count"], "" if s["count"] == 1 else "s"), "reported", "low")


def lines_ar(s, address=None):
    if not s["count"]:
        return ["- لا بلاغات علنية على Chainabuse لهذا العنوان (لا يعني أنه سليم)."]
    L = ["- %d بلاغًا علنيًا%s (منها %d متحقَّق منها من المشرفين، %d من مساهمين موثوقين)" % (
        s["count"], " على %s" % address if address else "", s["checked"], s["trusted"])]
    if s["categories"]:
        L.append("- الفئات: " + ", ".join("%s (%d)" % kv for kv in s["categories"].items()))
    if s["losses"]:
        L.append("- الخسائر المبلَّغ عنها: " + ", ".join("%.2f %s" % (v, k) for k, v in s["losses"].items()))
    if s["first"]:
        L.append("- الفترة: من %s إلى %s" % (s["first"], s["last"]))
    if s["domains"]:
        L.append("- نطاقات وردت في البلاغات (افحصها بـ site_scan.py): " + ", ".join(s["domains"]))
    if s["ids"]:
        L.append("- معرّفات للاطلاع عليها في الموقع: " + ", ".join(s["ids"]))
    if s["contacts_listed"]:
        L.append("- ذكر المبلّغون %d معرّف تواصل للمتهم: اقرأها في البلاغ نفسه وسلّمها للشرطة (لا تُنسخ هنا ولا تُعدّ إثباتًا)." % s["contacts_listed"])
    L.append("- البلاغات من مستخدمين: ادعاءات لم تتحقق منها هذه الأداة.")
    return L


def pick(g, n):
    inflow = defaultdict(float)
    for e in g["edges"]:
        inflow[e["to"]] += e.get("taint") if e.get("taint") is not None else (e.get("btc") or e.get("amount") or 0)
    pool = [a for a, x in g["nodes"].items() if not x.get("label") and not a.startswith("coinjoin:")]
    pool.sort(key=lambda a: (a != g["start"], -inflow.get(a, 0)))
    return pool[:n]


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check")
    p.add_argument("address")
    p.add_argument("--chain", choices=list(CHAIN), default="btc")
    p.add_argument("--refresh", action="store_true")
    p = sub.add_parser("check-graph")
    p.add_argument("graph")
    p.add_argument("--max", type=int, default=3)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--labels", default="labels.json")
    sub.add_parser("usage")
    for sp in sub.choices.values():
        sp.add_argument("--key", default=os.environ.get("CHAINABUSE_KEY"))
        sp.add_argument("--limit", type=int, default=10)
    a = ap.parse_args()
    if a.cmd == "usage":
        print("calls used this month: %d of %d" % (calls_used(), a.limit))
        return
    try:
        if a.cmd == "check":
            s = lookup(a.address, a.chain, a.key, a.limit, refresh=a.refresh)
            print("\n".join(lines_ar(s, a.address)))
            return
        g = json.load(open(a.graph, encoding="utf-8"))
        db = labels_tool.load(a.labels)
        for addr in pick(g, a.max):
            s = lookup(addr, g.get("chain", "btc"), a.key, a.limit)
            print(addr + (" (cached)" if s.get("cached") else ""))
            print("\n".join("  " + l for l in lines_ar(s)))
            lab = label_from(s)
            if lab and not a.dry_run:
                labels_tool.merge(db, addr, lab[0], lab[1], "Chainabuse reports", lab[2])
        if not a.dry_run:
            labels_tool.save(db, a.labels)
    except RuntimeError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
