#!/usr/bin/env python3
"""
wallet_profile.py - wallet profile and evidence report (Bitcoin, Ethereum, TRON). Python 3.8+.

    python wallet_profile.py btc  ADDRESS [--out profile.md] [--json profile.json]
    python wallet_profile.py eth  0xADDRESS
    python wallet_profile.py tron TADDRESS

Uses only public on-chain data plus public tags that the data providers already
publish (e.g. an ENS name). It builds an analytical profile of how the wallet
behaves, where its money came from, where it went, and which known services
(exchanges) it touched. It does NOT name a person: the real-world identity of an
account holder exists only at the exchange (KYC) and is obtained by law
enforcement through a formal request. The report ends with an annex listing exactly
what to hand to the police or the exchange's compliance team.

Keep btc_tracer.py, acct_tracer.py and (optionally) labels.json in the same folder.
All findings are probabilistic. Never present them as proof of identity.
"""
import argparse
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

import acct_tracer
import btc_tracer
import chains
import evm_api

RISK = btc_tracer.RISK
DAY = 86400
WD = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def iso_ts(s):
    try:
        return int(datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()) if s else None
    except ValueError:
        return None


def ms(t):
    return int(t) // 1000 if t else None


def when(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "unknown"


def row(d, other, asset, amount, txid, ts):
    return dict(dir=d, other=other, asset=asset, amount=amount, txid=txid, ts=ts)


# ---------------- data collection ----------------
def collect_btc(addr, a, chain="btc"):
    sym = chains.native(chain)
    txs, total = btc_tracer.address_txs(addr, a.max_txs)
    if txs is None:
        raise RuntimeError("This address has %d transactions (limit %d). Raise --max-txs." % (total, a.max_txs))
    rows, fp = [], []
    for tx in txs:
        ts = tx["status"].get("block_time")
        ins = {}
        for v in tx["vin"]:
            pv = v.get("prevout") or {}
            if pv.get("scriptpubkey_address"):
                ins[pv["scriptpubkey_address"]] = ins.get(pv["scriptpubkey_address"], 0) + pv["value"]
        if addr in ins:
            for o in tx["vout"]:
                b = o.get("scriptpubkey_address")
                if b and b not in ins:
                    rows.append(row("out", b, sym, o["value"] / 1e8, tx["txid"], ts))
            fp.append(dict(version=tx.get("version"), locktime=tx.get("locktime", 0),
                           rbf=any(v.get("sequence", 0xffffffff) < 0xfffffffe for v in tx["vin"]),
                           types=sorted({o.get("scriptpubkey_type") for o in tx["vout"]
                                         if o.get("scriptpubkey_type")})))
        else:
            main = max(ins, key=ins.get) if ins else "coinbase/unknown"
            for o in tx["vout"]:
                if o.get("scriptpubkey_address") == addr:
                    rows.append(row("in", main, sym, o["value"] / 1e8, tx["txid"], ts))
    return rows, {"btc_fp": fp}, False


def collect_eth(addr, a, chain="eth"):
    rows, nat = [], acct_tracer.NATIVE[chain]
    kw = {} if chain == "eth" else {"chain": chain}
    txs, t1 = acct_tracer.eth_pages("/addresses/%s/transactions" % addr, {}, a.api_key, a.max_pages, **kw)
    for t in txs:
        f = ((t.get("from") or {}).get("hash") or "").lower()
        to = ((t.get("to") or {}).get("hash") or "").lower()
        v = int(t.get("value") or 0)
        if not v or t.get("status") not in (None, "ok"):
            continue
        ts = iso_ts(t.get("timestamp"))
        if f == addr and to:
            rows.append(row("out", to, nat, v / 1e18, t["hash"], ts))
        elif to == addr and f:
            rows.append(row("in", f, nat, v / 1e18, t["hash"], ts))
    trs, t2 = acct_tracer.eth_pages("/addresses/%s/token-transfers" % addr, {"type": "ERC-20"},
                                    a.api_key, a.max_pages, **kw)
    for t in trs:
        f = ((t.get("from") or {}).get("hash") or "").lower()
        to = ((t.get("to") or {}).get("hash") or "").lower()
        tok = t.get("token") or {}
        ca = (tok.get("address_hash") or "").lower()
        if not a.all_tokens and ca not in acct_tracer.STABLES[chain]:
            continue
        tot = t.get("total") or {}
        amt = int(tot.get("value") or 0) / 10 ** int(tot.get("decimals") or tok.get("decimals") or 18)
        sym = acct_tracer.STABLES[chain].get(ca) or tok.get("symbol") or "?"
        ts = iso_ts(t.get("timestamp"))
        if f == addr and to:
            rows.append(row("out", to, sym, amt, t["transaction_hash"], ts))
        elif to == addr and f:
            rows.append(row("in", f, sym, amt, t["transaction_hash"], ts))
    info = {}
    try:
        d = evm_api.address_info(chain, addr, a.api_key) if chain != "eth" else acct_tracer.http(
            acct_tracer.ETH_BASE + "/addresses/" + addr + ("?apikey=" + a.api_key if a.api_key else ""))
        tags = [x.get("display_name") or x.get("label") for x in (d.get("public_tags") or [])
                if isinstance(x, dict)]
        info = {"ens": d.get("ens_domain_name"), "name": d.get("name"), "tags": [x for x in tags if x],
                "is_contract": d.get("is_contract"), "is_scam": d.get("is_scam")}
    except Exception:
        pass
    return rows, info, t1 or t2


def collect_tron(addr, a):
    rows, key = [], a.api_key
    params = {} if a.all_tokens else {"contract_address": next(iter(acct_tracer.STABLES["tron"]))}
    trs, b1 = acct_tracer.tron_pages("/v1/accounts/%s/transactions/trc20" % addr, params, key, a.max_pages)
    for t in trs:
        ti = t.get("token_info") or {}
        amt = int(t.get("value") or 0) / 10 ** int(ti.get("decimals") or 6)
        sym, ts = ti.get("symbol") or "?", ms(t.get("block_timestamp"))
        if t.get("from") == addr and t.get("to"):
            rows.append(row("out", t["to"], sym, amt, t["transaction_id"], ts))
        elif t.get("to") == addr and t.get("from"):
            rows.append(row("in", t["from"], sym, amt, t["transaction_id"], ts))
    nat, b2 = acct_tracer.tron_pages("/v1/accounts/%s/transactions" % addr, {}, key, a.max_pages)
    for t in nat:
        c = ((t.get("raw_data") or {}).get("contract") or [{}])[0]
        ret = (t.get("ret") or [{}])[0].get("contractRet")
        v = (c.get("parameter") or {}).get("value") or {}
        if c.get("type") != "TransferContract" or (ret and ret != "SUCCESS") or not v.get("amount"):
            continue
        o, d = acct_tracer.hex_to_tron(v["owner_address"]), acct_tracer.hex_to_tron(v["to_address"])
        ts = ms(t.get("block_timestamp"))
        if o == addr:
            rows.append(row("out", d, "TRX", v["amount"] / 1e6, t["txID"], ts))
        elif d == addr:
            rows.append(row("in", o, "TRX", v["amount"] / 1e6, t["txID"], ts))
    info = {}
    try:
        d = acct_tracer.http(acct_tracer.TRON_BASE + "/v1/accounts/" + addr,
                             {"TRON-PRO-API-KEY": key} if key else None)
        if d.get("data"):
            info["created"] = ms(d["data"][0].get("create_time"))
    except Exception:
        pass
    return rows, info, b1 or b2


# ---------------- analysis ----------------
def analyze(rows, labels, truncated=False):
    li = lambda a: acct_tracer.label_info(labels, a)
    timed = sorted((r for r in rows if r["ts"]), key=lambda r: r["ts"])
    m = {"transfers": len(rows), "incoming": sum(r["dir"] == "in" for r in rows),
         "outgoing": sum(r["dir"] == "out" for r in rows), "truncated": truncated}
    if timed:
        m.update(first_seen=timed[0]["ts"], last_seen=timed[-1]["ts"],
                 active_days=len({r["ts"] // DAY for r in timed}))
    tot = defaultdict(lambda: {"in": 0.0, "out": 0.0})
    for r in rows:
        tot[r["asset"]][r["dir"]] += r["amount"]
    m["totals"] = dict(tot)

    hours, wd, heat = [0] * 24, [0] * 7, [[0] * 24 for _ in range(7)]
    for r in timed:
        dt = datetime.fromtimestamp(r["ts"], tz=timezone.utc)
        hours[dt.hour] += 1
        wd[dt.weekday()] += 1
        heat[dt.weekday()][dt.hour] += 1
    m["hours_utc"], m["weekdays"], m["heatmap"] = hours, wd, heat
    n, m["tz"] = len(timed), None
    if n >= 30:
        x = sum(math.cos(2 * math.pi * (h + .5) / 24) * c for h, c in enumerate(hours)) / n
        y = sum(math.sin(2 * math.pi * (h + .5) / 24) * c for h, c in enumerate(hours)) / n
        R, mean_h = math.hypot(x, y), (math.atan2(y, x) * 24 / (2 * math.pi)) % 24
        m["tz"] = {"concentration": round(R, 2), "mean_hour_utc": round(mean_h, 1),
                   "utc_offset_guess": int((14 - mean_h + 12) % 24 - 12), "reliable": R >= 0.3}

    q, holds = deque(), []
    for r in timed:
        if r["dir"] == "in":
            q.append(r["ts"])
        elif q:
            holds.append(max(0, r["ts"] - q.popleft()))
    m["median_hold_s"] = statistics.median(holds) if holds else None
    m["pass_through"] = (len(holds) >= 3 and m["median_hold_s"] < DAY
                         and any(v["in"] > 0 and v["out"] / v["in"] >= .9 for v in tot.values()))

    cnt = Counter(r["other"] for r in rows)
    m["unique_counterparties"] = len(cnt)
    m["top_counterparties"] = [{"address": a, "transfers": c, "label": (li(a) or {}).get("label")}
                               for a, c in cnt.most_common(8)]
    ent, ex_rows, risk = {}, [], []
    for r in rows:
        info = li(r["other"])
        if not info:
            continue
        e = ent.setdefault((r["dir"], info["label"]), {"count": 0, "category": info.get("category"),
                                                      "first_tx": r["txid"]})
        e["count"] += 1
        if info.get("category") == "exchange":
            ex_rows.append(dict(r, label=info["label"]))
        if info.get("category") in RISK:
            risk.append(dict(r, label=info["label"], category=info["category"]))
    m["labeled"] = [dict(dir=k[0], label=k[1], **v) for k, v in ent.items()]
    m["exchange_touchpoints"], m["risk_contacts"] = ex_rows[:20], risk[:20]
    first_in = next((r for r in timed if r["dir"] == "in"), None)
    m["funding_source"] = dict(first_in, label=(li(first_in["other"]) or {}).get("label")) if first_in else None
    return m


# ---------------- report ----------------
def duration(s):
    return "%.1f hours" % (s / 3600) if s < DAY else "%.1f days" % (s / DAY)


def build_report(chain, addr, m, info, now=None):
    L = ["# Wallet profile: %s" % addr, "",
         "Network: %s | Generated: %s" % (chain, when(int(now or datetime.now(timezone.utc).timestamp()))),
         "", "> Analytical profile from public on-chain data. Findings are probabilistic and are not "
         "proof of identity. The account holder's name exists only at the exchange (KYC); see the annex."]
    if m["truncated"]:
        L += ["", "**Warning:** history was truncated (very active address). First-seen date and "
              "funding source below may be wrong."]
    pub = [("ENS name", info.get("ens")), ("Provider name", info.get("name")),
           ("Public tags", ", ".join(info.get("tags") or [])),
           ("Flagged as scam by provider", "yes" if info.get("is_scam") else None),
           ("Account created", when(info["created"]) if info.get("created") else None)]
    pub = [(k, v) for k, v in pub if v]
    if pub:
        L += ["", "## Public identifiers"] + ["- %s: %s" % kv for kv in pub]
    L += ["", "## Activity",
          "- Transfers: %d (%d in, %d out); counterparties: %d" % (
              m["transfers"], m["incoming"], m["outgoing"], m["unique_counterparties"])]
    if m.get("first_seen"):
        L.append("- First seen: %s | last seen: %s | active days: %d" % (
            when(m["first_seen"]), when(m["last_seen"]), m["active_days"]))
    for asset, v in m["totals"].items():
        L.append("- %s: received %.4f, sent %.4f" % (asset, v["in"], v["out"]))

    L += ["", "## Behavior"]
    tz = m["tz"]
    if tz and tz["reliable"]:
        L.append("- Activity clusters around %02d:00 UTC. If this is one person with normal waking hours, "
                 "local time is roughly UTC%+d (error of about 3 hours). Weak signal: automation, VPN-free "
                 "habits and shared wallets all distort it." % (round(tz["mean_hour_utc"]), tz["utc_offset_guess"]))
    elif tz:
        L.append("- No clear daily rhythm (concentration %.2f): possibly automated or shared use." % tz["concentration"])
    else:
        L.append("- Too few timestamped transfers (under 30) for a time-of-day pattern.")
    if sum(m["weekdays"]):
        L.append("- Busiest weekday: %s" % WD[max(range(7), key=lambda i: m["weekdays"][i])])
    if sum(map(sum, m.get("heatmap") or [[0]])) >= 10:
        mx = max(max(r) for r in m["heatmap"]) or 1
        L += ["- Activity heatmap (UTC; rows = weekday, columns = hour 00-23; ' .:+#' = none to busiest):",
              "        " + "".join("|" if h % 6 == 0 else " " for h in range(24)) + "   (| = 00, 06, 12, 18)"]
        L += ["    %s %s" % (d, "".join(" .:+#"[min(4, int(4 * c / mx + 0.999)) if c else 0] for c in row))
              for d, row in zip(WD, m["heatmap"])]
        L.append("  Block times are not the moment the user pressed send; use this as a hint, never as proof of location.")
    if m["median_hold_s"] is not None:
        L.append("- Median time funds stay before moving on: %s%s" % (
            duration(m["median_hold_s"]), " (pass-through wallet: typical of layering or mule accounts)"
            if m["pass_through"] else ""))
    fp = info.get("btc_fp") or []
    if fp:
        k = len(fp)
        L.append("- Wallet software hints (%d outgoing txs): %d%% signal RBF, %d%% use a locktime, "
                 "versions %s, output types %s" % (
                     k, 100 * sum(f["rbf"] for f in fp) // k, 100 * sum(bool(f["locktime"]) for f in fp) // k,
                     dict(Counter(f["version"] for f in fp)),
                     dict(Counter(t for f in fp for t in f["types"]))))

    L += ["", "## Money origin and destinations"]
    fs = m["funding_source"]
    if fs:
        L.append("- First incoming transfer: %.4f %s from %s%s on %s (tx %s)" % (
            fs["amount"], fs["asset"], fs["other"], " [%s]" % fs["label"] if fs["label"] else "",
            when(fs["ts"]), fs["txid"]))
    L.append("- Most frequent counterparties:")
    L += ["  - %s%s: %d transfers" % (c["address"], " [%s]" % c["label"] if c["label"] else "", c["transfers"])
          for c in m["top_counterparties"]]
    if m["labeled"]:
        L.append("- Known entities touched:")
        L += ["  - %s %s%s (%d transfers)" % ("to" if e["dir"] == "out" else "from", e["label"],
                                              " (%s)" % e["category"] if e["category"] else "", e["count"])
              for e in m["labeled"]]
    else:
        L.append("- No counterparty matched labels.json (build it with labels_tool.py).")
    if m["risk_contacts"]:
        L.append("- **High-risk contacts:** " + "; ".join(
            "%s (%s) tx %s" % (r["label"], r["category"], r["txid"]) for r in m["risk_contacts"][:5]))

    L += ["", "## Annex: route to the account holder",
          "Exchanges hold identity records for the accounts below. Only law enforcement (or a court order) "
          "can obtain them. Hand this table to the police or to the exchange's compliance team with your report."]
    ex = m["exchange_touchpoints"]
    if ex:
        L += ["", "| Exchange | Direction | Time | Amount | Transaction |", "|---|---|---|---|---|"]
        L += ["| %s | %s | %s | %.4f %s | %s |" % (
            r["label"], "sent to" if r["dir"] == "out" else "received from", when(r["ts"]),
            r["amount"], r["asset"], r["txid"]) for r in ex]
        L += ["", "Requested records: account-holder identification (KYC), registration and login data, "
              "and withdrawal/deposit history for the accounts that controlled the exchange addresses above."]
    else:
        L += ["", "No labeled exchange address was found in this wallet's direct history. Extend the trace "
              "(depth 3-4) with `serve.py` and look for flows into exchange-labeled addresses."]
    return "\n".join(L)


def collect(chain, addr, a):
    if chains.is_utxo(chain):
        with btc_tracer.use_chain(chain):
            return collect_btc(addr, a, chain)
    if chains.is_evm(chain):
        return collect_eth(addr.lower(), a, chain)
    if chain == "sol":
        import sol_api
        return sol_api.collect_sol(addr, a)
    return collect_tron(addr, a)


def build(chain, addr, labels, a):
    if chains.is_evm(chain):
        addr = addr.lower()
        labels = {(k.lower() if k.startswith("0x") else k): v for k, v in labels.items()}
    rows, info, trunc = collect(chain, addr, a)
    m = analyze(rows, labels, trunc)
    return build_report(chain, addr, m, info), dict(m, info=info)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=chains.ORDER)
    ap.add_argument("address")
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--out", default="profile.md")
    ap.add_argument("--json", default=None)
    ap.add_argument("--max-txs", type=int, default=500)
    ap.add_argument("--max-pages", type=int, default=6)
    ap.add_argument("--all-tokens", action="store_true")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    a = ap.parse_args()
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    text, m = build(a.chain, a.address.strip(), labels, a)
    open(a.out, "w", encoding="utf-8").write(text)
    if a.json:
        json.dump(m, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(text)
    print("\nSaved to", a.out, file=sys.stderr)


if __name__ == "__main__":
    main()
