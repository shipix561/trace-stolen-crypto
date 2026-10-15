#!/usr/bin/env python3
"""
diagnose.py - is this busy address a PLATFORM wallet or a collection address of a scam? Python 3.8+.

    python diagnose.py btc ADDRESS            explained signals, verdict, top counterparties, links
    python diagnose.py eth ADDRESS            lighter check from its transfers
    python diagnose.py tron ADDRESS

Every signal is shown with the number behind it; the verdict is only the sum of those signals. It is a LEAD about how the
address behaves, never an identification: it does not name a person, and "looks like a platform" is not proof of a platform.
How to use it: if it says platform-like, the useful next step is a request to that platform (see the letters of the case);
if it says collection-like, the useful next step is following the onward destinations listed here.
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

import btc_tracer
import case_builder
import chains

SAMPLE_PAGES = 8   # 25 transactions per page -> up to 200 recent transactions
EXPLORER = {k: chains.get(k)["addr_url"] for k in chains.ORDER}


def _info(get, a):
    try:
        i = get("/address/" + a)
    except Exception:
        return None
    cs, ms = i.get("chain_stats") or {}, i.get("mempool_stats") or {}
    rec = cs.get("funded_txo_sum", 0) + ms.get("funded_txo_sum", 0)
    spent = cs.get("spent_txo_sum", 0) + ms.get("spent_txo_sum", 0)
    return {"txs": cs.get("tx_count", 0) + ms.get("tx_count", 0), "received": rec / 1e8, "balance": (rec - spent) / 1e8}


def sample_txs(get, addr, pages=SAMPLE_PAGES):
    txs, last = [], None
    for _ in range(pages):
        page = get("/address/%s/txs" % addr if last is None else "/address/%s/txs/chain/%s" % (addr, last))
        if not page:
            break
        txs += page
        last = page[-1]["txid"]
        if len(page) < 25:
            break
    return txs


def analyze_btc(addr, labels=None, get=None, deep=5, chain="btc"):
    if get is None and chain != "btc":
        with btc_tracer.use_chain(chain):
            return analyze_btc(addr, labels, btc_tracer.get, deep, chain)
    labels = labels or {}
    get = get or btc_tracer.get
    sym = chains.native(chain)
    st = _info(get, addr)
    if st is None:
        raise RuntimeError("تعذّر قراءة العنوان.")
    txs = sample_txs(get, addr)
    inc_senders, out_dest, out_n, inc_n = Counter(), defaultdict(float), 0, 0
    batch = consol = small_out = 0
    times = []
    for tx in txs:
        ts = (tx.get("status") or {}).get("block_time")
        if ts:
            times.append(ts)
        ins = {}
        for v in tx["vin"]:
            pv = v.get("prevout") or {}
            if pv.get("scriptpubkey_address"):
                ins[pv["scriptpubkey_address"]] = ins.get(pv["scriptpubkey_address"], 0) + pv["value"]
        if addr in ins:
            out_n += 1
            outs = [o for o in tx["vout"] if o.get("scriptpubkey_address")]
            if len(outs) >= 10:
                batch += 1
            if len(tx["vin"]) >= 10:
                consol += 1
            if len(outs) <= 2:
                small_out += 1
            for o in outs:
                if o["scriptpubkey_address"] not in ins:
                    out_dest[o["scriptpubkey_address"]] += o["value"] / 1e8
        else:
            inc_n += 1
            for s in ins:
                inc_senders[s] += 1
    span = (max(times) - min(times)) / 86400 if len(times) > 1 else 0
    passthru = 1 - st["balance"] / st["received"] if st["received"] > 0 else 0
    uniq_dest = len(out_dest)
    sig = []  # (side, points, text)

    def add(side, pts, text, en=None):
        sig.append({"side": side, "points": pts, "text": text, "text_en": en or text})
    if st["txs"] >= 5000:
        add("service", 1, "عدد المعاملات كبير جدًا (%d)" % st["txs"], "Very large number of transactions (%d)" % st["txs"])
    if out_n and batch / out_n >= 0.15:
        add("service", 2, "دفعات جماعية (10 مخرجات أو أكثر) في %d من %d معاملة صادرة: نمط سحوبات منصة" % (batch, out_n), "Batch payments (10+ outputs) in %d of %d outgoing transactions: a platform-withdrawal pattern" % (batch, out_n))
    if uniq_dest >= 50:
        add("service", 2, "حوّل إلى %d عنوانًا مختلفًا في العيّنة" % uniq_dest, "Sent to %d different addresses in the sample" % uniq_dest)
    if span >= 365:
        add("service", 1, "نشاط ممتد %d يومًا في العيّنة" % span, "Activity spread over %d days in the sample" % span)
    if inc_n >= 20 and len(inc_senders) / max(inc_n, 1) >= 0.7:
        add("both", 0, "معظم الواردات من مرسلين مختلفين (%d مرسل من %d معاملة): يناسب منصة أو عنوان تجميع ضحايا" % (len(inc_senders), inc_n), "Most incoming payments come from different senders (%d senders in %d transactions): fits a platform or a victim-collection address" % (len(inc_senders), inc_n))
    if out_n >= 5 and small_out / out_n >= 0.8 and batch == 0:
        add("collection", 1, "الصادر كله تقريبًا بمخرجين أو أقل، بلا دفعات جماعية", "Almost all outgoing transactions have two outputs or fewer, with no batch payments")
    if 0 < uniq_dest <= 5 and out_n >= 5:
        add("collection", 2, "الصادر يذهب إلى %d عنوانًا فقط: تجميع ثم تمرير" % uniq_dest, "Outgoing goes to only %d addresses: collect then pass on" % uniq_dest)
    if consol:
        add("both", 0, "%d معاملة تجمّع 10 مدخلات أو أكثر (تحدث في الحالتين)" % consol, "%d transactions merge 10+ inputs (happens in both cases)" % consol)
    if passthru >= 0.95 and st["received"] > 0:
        add("both", 0, "العنوان يمرّر تقريبًا كل ما يصله (رصيده الحالي %.4f من %.4f)" % (st["balance"], st["received"]), "The address passes on almost everything it receives (current balance %.4f of %.4f)" % (st["balance"], st["received"]))
    if span and span < 120 and st["txs"] >= 30:
        add("collection", 1, "كل النشاط في فترة قصيرة (%d يومًا)" % span, "All activity within a short period (%d days)" % span)
    # counterparties
    def top(d, n=8):
        return sorted(d.items(), key=lambda kv: -kv[1])[:n]
    cps, hit = [], 0
    for rank, (a, v) in enumerate(top(out_dest)):
        lab = btc_tracer.label_info(labels, a)
        row = {"address": a, "direction": "out", "btc": round(v, 8), "label": (lab or {}).get("label"),
               "category": (lab or {}).get("category"), "link": EXPLORER[chain] % a}
        if rank < deep:
            s = _info(get, a)
            if s:
                row["txs"] = s["txs"]
        cps.append(row)
        if lab and lab.get("category") in ("exchange", "service", "platform"):
            hit += 1
    for a, n in inc_senders.most_common(5):
        lab = btc_tracer.label_info(labels, a)
        cps.append({"address": a, "direction": "in", "tx_count": n, "label": (lab or {}).get("label"),
                    "category": (lab or {}).get("category"), "link": EXPLORER[chain] % a})
    if hit:
        add("service", 2, "%d من أهم الوجهات موسومة في labels.json كمنصة" % hit, "%d of the top destinations are tagged as a platform in labels.json" % hit)
    own = btc_tracer.label_info(labels, addr)
    if own:
        add("service", 0, "العنوان نفسه موسوم عندك: %s" % own.get("label"), "The address itself is labelled in your database: %s" % own.get("label"))
    s_pts = sum(x["points"] for x in sig if x["side"] == "service")
    c_pts = sum(x["points"] for x in sig if x["side"] == "collection")
    if s_pts - c_pts >= 3:
        verdict, conf = "service-likely", "medium"
    elif s_pts - c_pts >= 1:
        verdict, conf = "service-possible", "low"
    elif c_pts - s_pts >= 2:
        verdict, conf = "collection-likely", "low"
    else:
        verdict, conf = "unclear", "low"
    return {"chain": chain, "address": addr, "stats": {**st, "sampled": len(txs), "span_days": round(span),
            "incoming_senders": len(inc_senders), "outgoing_tx": out_n, "incoming_tx": inc_n},
            "signals": sig, "scores": {"service": s_pts, "collection": c_pts}, "verdict": verdict, "confidence": conf,
            "counterparties": cps, "link": EXPLORER[chain] % addr, "symbol": sym}


def analyze_rows(chain, addr, rows, labels=None):
    """ETH/TRON: lighter version from wallet rows (dir/other/asset/amount/txid/ts)."""
    labels = labels or {}
    ins = [r for r in rows if r["dir"] == "in"]
    outs = [r for r in rows if r["dir"] == "out"]
    senders, dests = Counter(r["other"] for r in ins if r.get("other")), Counter(r["other"] for r in outs if r.get("other"))
    ts = [r["ts"] for r in rows if r.get("ts")]
    span = (max(ts) - min(ts)) / 86400 if len(ts) > 1 else 0
    sig = []
    if len(dests) >= 50:
        sig.append({"side": "service", "points": 2, "text": "حوّل إلى %d عنوانًا مختلفًا" % len(dests), "text_en": "Sent to %d different addresses" % len(dests)})
    if len(rows) >= 400:
        sig.append({"side": "service", "points": 1, "text": "عدد التحويلات كبير (%d)" % len(rows), "text_en": "Large number of transfers (%d)" % len(rows)})
    if span >= 365:
        sig.append({"side": "service", "points": 1, "text": "نشاط ممتد %d يومًا" % span, "text_en": "Activity spread over %d days" % span})
    if 0 < len(dests) <= 5 and len(outs) >= 5:
        sig.append({"side": "collection", "points": 2, "text": "الصادر يذهب إلى %d عنوانًا فقط" % len(dests), "text_en": "Outgoing goes to only %d addresses" % len(dests)})
    if len(ins) >= 20 and len(senders) / len(ins) >= 0.7:
        sig.append({"side": "both", "points": 0, "text": "مرسلون كثيرون مختلفون (%d)" % len(senders), "text_en": "Many different senders (%d)" % len(senders)})
    s = sum(x["points"] for x in sig if x["side"] == "service")
    c = sum(x["points"] for x in sig if x["side"] == "collection")
    verdict, conf = (("service-likely", "low") if s - c >= 3 else ("service-possible", "low") if s - c >= 1 else
                     ("collection-likely", "low") if c - s >= 2 else ("unclear", "low"))
    cps = [{"address": a, "direction": "out", "tx_count": n, "label": (btc_tracer.label_info(labels, a) or {}).get("label"),
            "link": EXPLORER[chain] % a} for a, n in dests.most_common(8)]
    return {"chain": chain, "address": addr, "stats": {"rows": len(rows), "span_days": round(span), "incoming_senders": len(senders)},
            "signals": sig, "scores": {"service": s, "collection": c}, "verdict": verdict, "confidence": conf,
            "counterparties": cps, "link": EXPLORER[chain] % addr}


def diagnose(chain, addr, labels=None, key=None, get=None, rows=None):
    addr = case_builder.valid_address(chain, addr)
    if chains.is_utxo(chain):
        return analyze_btc(addr, labels, get, chain=chain)
    import operation
    return analyze_rows(chain, addr, rows if rows is not None else operation.collect(chain, addr, key), labels)


VERDICT_AR = {"service-likely": "يشبه محفظة منصة/خدمة", "service-possible": "قد يكون محفظة منصة/خدمة",
              "collection-likely": "يشبه عنوان تجميع", "unclear": "غير واضح"}
NEXT_AR = {
    "service-likely": "الخطوة المفيدة: طلب رسمي لهذه المنصة (رسالة الكيان في ملف القضية) مع رقم معاملتك. اطلب بيانات الحساب الذي استلم دفعتك.",
    "service-possible": "تحقق أولًا من هوية الوجهات الكبيرة أدناه؛ إن ظهرت منصة معروفة فاطلب منها رسميًا.",
    "collection-likely": "تتبّع الوجهات التالية بالترتيب؛ العنوان هنا محطة وليس النهاية.",
    "unclear": "لا يكفي السلوك للحكم. افتح الوجهات الكبيرة في المستكشف وابحث عن أي منها يحمل وسمًا معلنًا."}


VERDICT_EN = {"service-likely": "Looks like a platform/service wallet", "service-possible": "May be a platform/service wallet",
              "collection-likely": "Looks like a collection address", "unclear": "Unclear"}
NEXT_EN = {
    "service-likely": "Useful step: an official request to this platform (the entity letter in the case file) with your transaction ID. Ask for the details of the account that received your payment.",
    "service-possible": "First verify the identity of the large destinations below; if a known platform appears, make an official request to it.",
    "collection-likely": "Follow the destinations below in order; this address is a stop, not the end.",
    "unclear": "Behaviour is not enough to decide. Open the large destinations in the explorer and look for any that carries a public label."}


def lines_ar(d, lang="ar"):
    if lang_en(lang):
        return lines_en(d)
    st = d["stats"]
    L = ["## تشخيص العنوان المزدحم (مؤشرات سلوك، ليس تعريفًا بشخص)",
         "الحكم: %s (ثقة %s)  |  نقاط منصة %d مقابل تجميع %d" % (VERDICT_AR[d["verdict"]], "متوسطة" if d["confidence"] == "medium" else "منخفضة",
                                                           d["scores"]["service"], d["scores"]["collection"])]
    L += ["المؤشرات:"] + ["  - %s" % x["text"] for x in d["signals"]] if d["signals"] else ["المؤشرات: لا مؤشر واضح."]
    L.append("الحجم: " + "، ".join("%s=%s" % (k, v) for k, v in st.items()))
    cps = d["counterparties"]
    if cps:
        L.append("أهم الأطراف:")
        for c in cps:
            extra = " | معاملاته %s" % c["txs"] if c.get("txs") else ""
            amt = (" | %s %s" % (c["btc"], d.get("symbol", "BTC"))) if c.get("btc") else (" | %s معاملة" % c["tx_count"] if c.get("tx_count") else "")
            L.append("  - %s %s%s%s%s  %s" % ("→" if c["direction"] == "out" else "←", c["address"], amt, extra,
                                              (" | " + c["label"]) if c.get("label") else "", c["link"]))
    L += [NEXT_AR[d["verdict"]], "للتعرّف على صاحب وسم: ابحث عن العنوان في المستكشف وفي arkm.com (بحث يدوي)؛ الوسم المعلن يحتاج مراجعة قبل اعتماده.",
          "العنوان: " + d["link"], "لا يقول هذا التقرير من يملك العنوان، وسلوك يشبه منصة ليس إثباتًا أنه منصة."]
    return L


def lang_en(lang):
    """Server-side texts exist in Arabic (source) and English (pivot for en/es/fr/tr/ru)."""
    return lang in ("en", "es", "fr", "tr", "ru")


def lines_en(d):
    st = d["stats"]
    L = ["## Busy-address diagnosis (behaviour indicators, not an identification of any person)",
         "Verdict: %s (confidence %s)  |  platform points %d vs collection %d" % (VERDICT_EN[d["verdict"]], "medium" if d["confidence"] == "medium" else "low",
                                                                              d["scores"]["service"], d["scores"]["collection"])]
    L += ["Indicators:"] + ["  - %s" % x.get("text_en", x["text"]) for x in d["signals"]] if d["signals"] else ["Indicators: none clear."]
    L.append("Size: " + ", ".join("%s=%s" % (k, v) for k, v in st.items()))
    cps = d["counterparties"]
    if cps:
        L.append("Main counterparties:")
        for c in cps:
            extra = " | its transactions %s" % c["txs"] if c.get("txs") else ""
            amt = (" | %s %s" % (c["btc"], d.get("symbol", "BTC"))) if c.get("btc") else (" | %s transactions" % c["tx_count"] if c.get("tx_count") else "")
            L.append("  - %s %s%s%s%s  %s" % ("→" if c["direction"] == "out" else "←", c["address"], amt, extra,
                                              (" | " + c["label"]) if c.get("label") else "", c["link"]))
    L += [NEXT_EN[d["verdict"]], "To learn who owns a tag: search the address in the explorer and on arkm.com (manual search); a public tag needs review before it is relied on.",
          "Address: " + d["link"], "This report does not say who owns the address, and behaviour that resembles a platform is not proof that it is one."]
    return L


def report_text(d, lang="ar"):
    return "\n".join(lines_ar(d, lang))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=chains.ORDER)
    ap.add_argument("address")
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    try:
        d = diagnose(a.chain, a.address, labels, a.api_key)
    except (ValueError, RuntimeError) as e:
        sys.exit(str(e))
    print(json.dumps(d, ensure_ascii=False, indent=1) if a.json else report_text(d))


if __name__ == "__main__":
    main()
