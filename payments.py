#!/usr/bin/env python3
"""
payments.py - "I don't have my transaction hash": list what the scammer's address RECEIVED, pick your payment. Python 3.8+.

    python payments.py btc ADDRESS --amount 0.5 --date 2019-03-14       list incoming payments, best matches first
    python payments.py btc ADDRESS --amount 0.5 --pick 2                 build the case from payment no. 2 (exact output)

Why it matters: tracing from an ADDRESS mixes in every other person's money that went through it. Tracing from the one
output you sent follows only your money. Choosing your payment from this list gives the tool that exact output.
Matching is by amount (within 2%) and date (within 3 days); both are optional. The list is a help to find your payment:
you confirm it, the tool does not decide for you.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

import btc_tracer
import case_builder
import chains

BUSY = 1000      # transactions: beyond this the list may not reach old payments
PAGE = 25


def parse_date(s):
    if not s:
        return None
    s = str(s).strip()
    for f in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%d %H:%M"):
        try:
            return int(datetime.strptime(s, f).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    raise ValueError("التاريخ غير مفهوم: اكتبه هكذا 2019-03-14")


def _match(p, amount, date):
    """Explainable closeness flags, no hidden score."""
    p["amount_match"] = bool(amount) and abs(p["amount"] - amount) <= 0.02 * amount
    p["date_match"] = bool(date and p.get("time")) and abs(p["time"] - date) <= 3 * 86400
    p["rank"] = (2 if p["amount_match"] else 0) + (1 if p["date_match"] else 0)
    return p


def btc_payments(addr, since=None, until=None, max_pages=8, get=None, sym="BTC"):
    get = get or btc_tracer.get
    info = get("/address/" + addr)
    total = (info.get("chain_stats") or {}).get("tx_count", 0) + (info.get("mempool_stats") or {}).get("tx_count", 0)
    out, last, pages, reached_end, warn = [], None, 0, False, None
    while pages < max_pages:
        page = get("/address/%s/txs" % addr if last is None else "/address/%s/txs/chain/%s" % (addr, last))
        pages += 1
        if not page:
            reached_end = True
            break
        for tx in page:
            ts = (tx.get("status") or {}).get("block_time")
            if ts and until and ts > until:
                continue
            if ts and since and ts < since:
                continue
            senders = sorted({(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx["vin"]
                              if (v.get("prevout") or {}).get("scriptpubkey_address")})
            if addr in senders:
                continue  # the address spent in this tx: not a payment to it
            for i, o in enumerate(tx["vout"]):
                if o.get("scriptpubkey_address") == addr:
                    out.append({"txid": tx["txid"], "vout": i, "amount": o["value"] / 1e8, "asset": sym, "time": ts,
                                "time_str": case_builder.fmt_time(ts) if ts else "غير مؤكدة بعد", "senders": senders[:6]})
        last = page[-1]["txid"]
        oldest = (page[-1].get("status") or {}).get("block_time")
        if len(page) < PAGE:
            reached_end = True
            break
        if since and oldest and oldest < since:
            reached_end = True  # everything older is outside the wanted window
            break
    if not reached_end:
        warn = ("العنوان فيه %d معاملة وقرأت %d صفحة فقط؛ قد تكون دفعتك أقدم من القائمة. حدّد التاريخ لتضييق البحث "
                "أو ارفع الحد." % (total, pages))
    elif total >= BUSY:
        warn = "العنوان مزدحم (%d معاملة): غالبًا منصة أو عنوان تجميع، وليس عنوان شخص." % total
    return out, total, warn


def other_payments(chain, addr, key=None, rows=None, since=None, until=None):
    import operation
    rows = rows if rows is not None else operation.collect(chain, addr, key)
    out = []
    for r in rows:
        if r.get("dir") != "in":
            continue
        ts = r.get("ts")
        ts = (ts // 1000 if ts and ts > 1e11 else ts)
        if ts and ((since and ts < since) or (until and ts > until)):
            continue
        out.append({"txid": r["txid"], "vout": None, "amount": r["amount"], "asset": r["asset"], "time": ts,
                    "time_str": case_builder.fmt_time(ts) if ts else "", "senders": [r["other"]] if r.get("other") else []})
    return out, len(rows), None


def list_payments(chain, address, amount=None, date=None, window_days=None, max_pages=8, key=None, get=None, rows=None):
    """Incoming payments of `address`, best matches first. date: 'YYYY-MM-DD' or unix seconds."""
    if chain not in chains.CHAINS:
        raise ValueError("الشبكة غير مدعومة: " + str(chain))
    d = date if isinstance(date, (int, float)) else parse_date(date)
    since = until = None
    if d and window_days:
        since, until = d - window_days * 86400, d + window_days * 86400
    address = case_builder.valid_address(chain, address)
    if chains.is_utxo(chain):
        with btc_tracer.use_chain(chain):
            pays, total, warn = btc_payments(address, since, until, max_pages, get, chains.native(chain))
    else:
        pays, total, warn = other_payments(chain, address, key, rows, since, until)
    for p in pays:
        _match(p, amount, d)
    pays.sort(key=lambda p: (-p["rank"], -(p["time"] or 0)))
    return {"chain": chain, "address": address, "total_txs": total, "payments": pays[:200], "count": len(pays),
            "warning": warn, "note": "القائمة مساعدة لإيجاد دفعتك: أنت تؤكد أيها دفعتك."}


def format_list(res, lang="ar"):
    en = lang in ("en", "es", "fr", "tr", "ru")
    if en:
        L = ["Incoming payments to %s (%s): %d payment(s)" % (res["address"], res["chain"].upper(), res["count"])]
        if res.get("warning"):
            L.append("Note: " + res["warning"])
    else:
        L = ["المدفوعات الواردة إلى %s (%s) — %d دفعة" % (res["address"], res["chain"].upper(), res["count"])]
        if res.get("warning"):
            L.append("تنبيه: " + res["warning"])
    for i, p in enumerate(res["payments"][:40], 1):
        if en:
            mark = " ◀ matches " + ("the amount " if p["amount_match"] else "") + ("and the date" if p["date_match"] else "") if p["rank"] else ""
        else:
            mark = " ◀ تطابق " + ("المبلغ " if p["amount_match"] else "") + ("والتاريخ" if p["date_match"] else "") if p["rank"] else ""
        L.append("  %d) %s | %s %s | tx %s%s%s" % (i, p["time_str"] or "-", p["amount"], p["asset"], p["txid"][:16] + "…",
                                                 (" #%d" % p["vout"]) if p["vout"] is not None else "", mark.rstrip()))
    if not res["payments"]:
        L.append("  No payments match the date window. Try without a date." if en else "  لا توجد مدفوعات مطابقة لنافذة التاريخ. جرّب بلا تاريخ.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=chains.ORDER)
    ap.add_argument("address")
    ap.add_argument("--amount", type=float)
    ap.add_argument("--date", help="YYYY-MM-DD")
    ap.add_argument("--window", type=int, default=None, help="days around --date to show (default: show all, best first)")
    ap.add_argument("--max-pages", type=int, default=8)
    ap.add_argument("--pick", type=int)
    ap.add_argument("--depth", type=int)
    ap.add_argument("--victim")
    ap.add_argument("--contact")
    ap.add_argument("--report-no")
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--out", default="cases")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    a = ap.parse_args()
    try:
        res = list_payments(a.chain, a.address, a.amount, a.date, a.window, a.max_pages, a.api_key)
    except (ValueError, RuntimeError) as e:
        sys.exit(str(e))
    print(format_list(res))
    if not a.pick:
        print("\nلبناء القضية من دفعتك: أعد التشغيل مع --pick رقم_الدفعة")
        return
    p = res["payments"][a.pick - 1]
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    params = {"victim": a.victim, "contact": a.contact, "report_no": a.report_no, "txid": p["txid"], "stolen": p["amount"],
              "asset": p["asset"], "incident": p["time_str"] or None, "vout": p["vout"]}
    out = case_builder.run_case(a.chain, res["address"], a.depth or (6 if chains.is_utxo(a.chain) else 3),
                                p["amount"] if chains.is_utxo(a.chain) else None, labels, a.out, params, a.api_key)
    print("\n" + out["summary"] + "\n\nSaved to " + out["folder"])


if __name__ == "__main__":
    main()
