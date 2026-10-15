#!/usr/bin/env python3
"""
watch.py - alert when money moves out of (or into) watched addresses. Python 3.8+.

    python watch.py btc  ADDRESS [ADDRESS ...] [--interval 300] [--ntfy my-secret-topic]
    python watch.py eth  0xADDRESS ...
    python watch.py tron TADDRESS ...
    python watch.py btc  ADDRESS --once          (one check, for cron / scheduled tasks)

First run records the current balances. After that, any change prints an ALERT, appends it to
alerts.log, and (optional) sends a phone notification through ntfy.sh: install the ntfy app,
subscribe to a long random topic name, and pass it as --ntfy.
When an alert fires: run `python case_builder.py ... --graph graph.json` again or trace the
destination, then send the exchange notice immediately. Speed is what makes freezing possible.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

import btc_tracer
import case_builder
import chains

STATE = "watch_state.json"


def compare(old, new):
    msgs = []
    for asset in sorted(set(old) | set(new)):
        a, b = old.get(asset, 0.0), new.get(asset, 0.0)
        if abs(a - b) > 1e-9:
            msgs.append("%s: %.8g -> %.8g (%s)" % (asset, a, b, "MOVED OUT" if b < a else "received"))
    return msgs


def pending_btc(addr, state, get=None):
    # unconfirmed (mempool) spends: the earliest warning that money is leaving, with its destinations
    get = get or btc_tracer.get
    seen, alerts = state.setdefault("_pending", []), []
    for tx in get("/address/%s/txs/mempool" % addr):
        if tx["txid"] in seen:
            continue
        ins = {(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx.get("vin", [])}
        if addr not in ins:
            continue
        outs = ["%s %.8g BTC" % (o["scriptpubkey_address"], o["value"] / 1e8) for o in tx["vout"]
                if o.get("scriptpubkey_address") and o["scriptpubkey_address"] not in ins]
        seen.append(tx["txid"])
        alerts.append("PENDING (unconfirmed) spend from %s | tx %s | to: %s" % (addr, tx["txid"], "; ".join(outs)))
    return alerts


def notify(topic, text):
    try:
        req = urllib.request.Request("https://ntfy.sh/" + topic, data=text.encode("utf-8"), method="POST")
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as e:
        print("(notification failed: %s)" % e)


def check(chain, addrs, state, key=None, topic=None, fetch=None, get=None):
    fetch = fetch or case_builder.fetch_balance
    alerts = []
    for a in addrs:
        k = "%s:%s" % (chain, a)
        try:
            bal = fetch(chain, a, key)
        except Exception as e:
            print("could not read %s: %s" % (a, e))
            continue
        if k in state:
            for m in compare(state[k], bal):
                alerts.append("ALERT %s %s | %s" % (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), a, m))
        else:
            print("baseline recorded for %s: %s" % (a, case_builder.fmt(bal)))
        state[k] = bal
    if chain == "btc":
        for a in addrs:
            try:
                alerts += ["ALERT %s | %s" % (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), m)
                           for m in pending_btc(a, state, get)]
            except Exception:
                pass
    for t in alerts:
        print(t)
        open("alerts.log", "a", encoding="utf-8").write(t + "\n")
        if topic:
            notify(topic, t)
    return alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=chains.ORDER)
    ap.add_argument("addresses", nargs="+")
    ap.add_argument("--interval", type=int, default=300, help="seconds between checks")
    ap.add_argument("--ntfy", default=None, help="ntfy.sh topic for phone notifications")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    a = ap.parse_args()
    addrs = [case_builder.valid_address(a.chain, x) for x in a.addresses]
    state = json.load(open(STATE, encoding="utf-8")) if os.path.exists(STATE) else {}
    print("Watching %d address(es). Ctrl+C to stop." % len(addrs))
    try:
        while True:
            check(a.chain, addrs, state, a.api_key, a.ntfy)
            json.dump(state, open(STATE, "w", encoding="utf-8"), indent=1)
            if a.once:
                break
            time.sleep(max(60, a.interval))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
