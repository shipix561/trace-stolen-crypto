#!/usr/bin/env python3
"""
enrich.py - ask an external label provider who owns the unlabeled addresses of a trace. Python 3.8+.

    pip install satoshidata                         (optional third-party provider, Bitcoin only)
    python enrich.py graph.json [--max 25] [--dry-run]

It picks the addresses most likely to be exchanges or services (flagged high-activity addresses first,
then the largest inflows), asks the provider, and writes any answer to labels.json with LOW confidence
and the source name, so every later report shows it as "needs confirmation".

Read this before trusting a result:
  - The provider is a third party. I could not verify its accuracy, terms or free-tier limits.
  - Sending an address to it tells the provider you are investigating that address.
  - Confirm every name in a public explorer, then contact the platform. Never accuse based on one label.
  - After enriching, rebuild the case:  python case_builder.py btc ADDRESS --graph graph.json
"""
import argparse
import json
import os
import re
import sys
import time

import labels_tool

SOURCE = "satoshidata (third-party, unverified)"


def parse_headline(h):
    """'Verified Binance (exchange)' -> ('Binance', 'exchange')."""
    m = re.match(r"^(?:Verified\s+)?(.+?)\s*\(([^)]+)\)\s*$", (h or "").strip())
    if not m:
        return None
    label, cat = m.group(1).strip(), m.group(2).strip().lower()
    return label, ("exchange" if "exchange" in cat else cat)


def provider_satoshidata():
    from satoshidata import SatoshiDataClient  # noqa: pip install satoshidata
    client = SatoshiDataClient()

    def look(addr):
        data = client.trust_safety(addr)
        return parse_headline(((data or {}).get("assessment") or {}).get("headline"))
    return look


def pick_candidates(g, limit):
    inflow = {}
    for e in g["edges"]:
        inflow[e["to"]] = inflow.get(e["to"], 0) + (e.get("btc") or e.get("amount") or 0)
    pool = [a for a, n in g["nodes"].items()
            if a != g["start"] and not n.get("label") and not a.startswith("coinjoin:")]
    pool.sort(key=lambda a: (not g["nodes"][a].get("note"), -inflow.get(a, 0)))
    return pool[:limit]


def enrich(g, look, db, limit=25, delay=0.5, dry=False):
    found = []
    for a in pick_candidates(g, limit):
        try:
            res = look(a)
        except Exception as e:
            print("  %s: lookup failed (%s)" % (a, str(e)[:60]))
            continue
        time.sleep(delay)
        if not res:
            continue
        label, cat = res
        found.append((a, label, cat))
        if not dry:
            labels_tool.merge(db, a, label, cat, SOURCE, "low")
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("graph")
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--max", type=int, default=25)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    g = json.load(open(a.graph, encoding="utf-8"))
    if g.get("chain", "btc") != "btc":
        sys.exit("This provider covers Bitcoin only.")
    try:
        look = provider_satoshidata()
    except ImportError:
        sys.exit("Install the provider first:  pip install satoshidata")
    db = labels_tool.load(a.labels)
    found = enrich(g, look, db, a.max, dry=a.dry_run)
    if not a.dry_run:
        labels_tool.save(db, a.labels)
    for addr, label, cat in found:
        print("%s -> %s (%s) [low confidence, confirm manually]" % (addr, label, cat))
    print("\n%d address(es) identified out of %d checked." % (len(found), min(a.max, len(g["nodes"]))))


if __name__ == "__main__":
    main()
