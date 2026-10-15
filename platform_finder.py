#!/usr/bin/env python3
"""
platform_finder.py - "which platform did the money reach?" Python 3.8+.

Reads a finished trace (graph.json) and ranks the addresses that look like a platform's wallet. It answers only
WHERE the money entered a service, never what happened inside it, and it never names a person.

Signals (each is explained in the report, none is proof):
  known      the address carries a label from a source you imported or confirmed (exchange/custodian/...)
  inferred   the label was inferred (same wallet cluster, deposit pattern): low confidence
  sweep      one or more traced addresses forward (almost) all they received to this single address, quickly:
             the typical shape of a platform's deposit addresses sweeping into its hot wallet
  funnel     several different traced addresses end up at the same address
  activity   the tracer flagged it as a very busy address (thousands of transactions)
  diagnosis  the behaviour diagnosis (diagnose.py) says "looks like a platform wallet"

Tiers: known > inferred > likely (score >= 4) > possible. Addresses labelled as mixers/scams/sanctioned are not
platform candidates; the mixing module handles them.

    python platform_finder.py graph.json
"""
import json
import sys
from collections import defaultdict

import taxonomy

SWEEP_SHARE = 0.9          # a sweeper forwards at least this share of what it received
SWEEP_WINDOW = 7 * 86400   # ... within this many seconds of the last payment it received
START_SHARE = 0.8          # the start address: this share of its outflow to one address


def _amt(e):
    for k in ("btc", "amount", "taint"):
        if isinstance(e.get(k), (int, float)):
            return float(e[k])
    return 0.0


def _real_label(n):
    return n.get("label") and n.get("category") != "coinjoin"


def sweepers(g):
    """{destination: [(sweeper, share, seconds_or_None)]}"""
    ins, outs = defaultdict(list), defaultdict(list)
    for e in g["edges"]:
        if e["from"] == e["to"]:
            continue
        outs[e["from"]].append(e)
        ins[e["to"]].append(e)
    res = defaultdict(list)
    for a, oe in outs.items():
        by_dest = defaultdict(float)
        for e in oe:
            by_dest[e["to"]] += _amt(e)
        tot_out = sum(by_dest.values())
        if not tot_out:
            continue
        dest, v = max(by_dest.items(), key=lambda kv: kv[1])
        if a == g["start"]:
            if v / tot_out >= START_SHARE and len(by_dest) <= 3:
                res[dest].append((a, v / tot_out, None))
            continue
        tot_in = sum(_amt(e) for e in ins.get(a, []))
        if not tot_in or len(by_dest) != 1 or tot_out < SWEEP_SHARE * tot_in * 0.98:
            continue
        t_in = max((e.get("time") or 0 for e in ins.get(a, [])), default=0)
        t_out = min((e.get("time") or 0 for e in oe if e["to"] == dest), default=0)
        gap = (t_out - t_in) if (t_in and t_out) else None
        if gap is not None and (gap < 0 or gap > SWEEP_WINDOW):
            continue
        res[dest].append((a, min(1.0, tot_out / tot_in), gap))
    return res


def find(g, diag=None):
    nodes = g["nodes"]
    sw = sweepers(g)
    senders = defaultdict(set)
    for e in g["edges"]:
        if e["from"] != e["to"]:
            senders[e["to"]].add(e["from"])
    cands = []
    for a, n in nodes.items():
        if a == g["start"] or a.startswith("coinjoin:"):
            continue
        cat = taxonomy.canon(n.get("category"))
        if cat in taxonomy.RISK or cat == "coinjoin":
            continue
        lab = n.get("label") if _real_label(n) else None
        inferred = bool(n.get("inferred"))
        sws = sw.get(a, [])
        busy = "high activity" in (n.get("note") or "") or "collection point" in (n.get("note") or "")
        funnel = len(senders[a]) >= 3
        dg = diag if diag and diag.get("address") == a else None
        dg_service = bool(dg and dg.get("verdict") in ("service-likely", "service-possible"))
        if not (lab or sws or busy or funnel or dg_service):
            continue
        score, why = 0, []
        if lab and not inferred and (taxonomy.is_platform(cat) or cat in (None, "other")):
            score += 6
            why.append(("موسوم عندك باسم «%s» (المصدر: %s، الثقة: %s)" % (lab, n.get("source") or "-", n.get("confidence") or "-"),
                        "Labelled '%s' in your database (source: %s, confidence: %s)" % (lab, n.get("source") or "-", n.get("confidence") or "-")))
        elif lab and inferred:
            score += 3
            why.append(("اسم مستنتج «%s» (%s): ثقة منخفضة" % (lab, n.get("inferred")), "Inferred name '%s' (%s): low confidence" % (lab, n.get("inferred"))))
        if sws:
            score += 2 + min(3, len(sws) - 1)
            fast = [s for s in sws if s[2] is not None]
            why.append(("%d عنوانًا حوّل كل ما استلمه تقريبًا إلى هذا العنوان وحده%s: نمط عناوين إيداع تُجمَّع في محفظة المنصة"
                        % (len(sws), " وبسرعة (خلال أيام)" if fast else ""),
                        "%d address(es) forwarded almost everything they received to this single address%s: the shape of deposit addresses being swept into a platform wallet"
                        % (len(sws), " and quickly (within days)" if fast else "")))
        if funnel:
            score += 1
            why.append(("يصله المال من %d عناوين مختلفة في التتبع" % len(senders[a]), "Receives from %d different traced addresses" % len(senders[a])))
        if busy:
            score += 2
            why.append(("عنوان كثير النشاط (آلاف المعاملات)", "Very busy address (thousands of transactions)"))
        if dg_service:
            score += 2
            why.append(("فحص السلوك يقول إنه يشبه محفظة منصة", "The behaviour check says it looks like a platform wallet"))
        tier = "known" if lab and not inferred and score >= 6 else "inferred" if lab and inferred else "likely" if score >= 4 else "possible"
        cands.append({"address": a, "name": lab, "category": cat, "tier": tier, "score": score,
                      "sweepers": [s[0] for s in sws], "reasons": why})
    order = {"known": 0, "inferred": 1, "likely": 2, "possible": 3}
    cands.sort(key=lambda c: (order[c["tier"]], -c["score"]))
    return cands[:6]


TIER = {"known": ("معروفة (موسومة)", "Known (labelled)"), "inferred": ("اسم مستنتج", "Inferred name"),
        "likely": ("مرجّحة", "Likely"), "possible": ("محتملة", "Possible")}
NEXT = {
    "known": ("أرسل الإشعار الجاهز لهذه المنصة اليوم مع رقم المعاملة.", "Send the ready notice to this platform today with the transaction ID."),
    "inferred": ("لا تراسل المنصة قبل تأكيد الاسم من مصدر ثانٍ (لسان «مراجعة التصنيفات»).", "Do not write to the platform before confirming the name from a second source (the Label review tab)."),
    "likely": ("اعرف اسم المنصة: افتح العنوان في المستكشف، وابحث عنه بين علامتي تنصيص، وقارنه بعناوين المنصات المنشورة رسميًا (إثبات الاحتياطيات).",
               "Find the platform's name: open the address in the explorer, search it in quotation marks, and compare it with addresses platforms publish officially (proof of reserves)."),
    "possible": ("إشارة ضعيفة: تحقق قبل البناء عليها.", "Weak signal: verify before building on it.")}


def lines(cands, lang="ar", explorer=""):
    en = lang in ("en", "es", "fr", "tr", "ru")
    i = 1 if en else 0
    L = ["## Which platform did the money reach? (where it entered, not what happened inside)" if en else
         "## إلى أي منصة وصل المال؟ (أين دخل، لا ما جرى داخلها)"]
    if not cands:
        L.append("- No address in the trace looks like a platform wallet yet. Widen the depth." if en else "- لا يوجد في التتبع عنوان يشبه محفظة منصة بعد. وسّع العمق.")
        return L
    for n, c in enumerate(cands, 1):
        name = c["name"] or ("unnamed address" if en else "عنوان بلا اسم")
        L.append("%d. **%s** — %s (%s %d)" % (n, name, TIER[c["tier"]][i], "score" if en else "نقاط", c["score"]))
        L.append("   - %s: %s%s" % ("Address" if en else "العنوان", c["address"], (" " + explorer + c["address"]) if explorer else ""))
        for r in c["reasons"]:
            L.append("   - " + r[i])
        L.append("   - %s %s" % ("Next:" if en else "الخطوة:", NEXT[c["tier"]][i]))
    L.append("- This ranks addresses by signals; it is not proof of ownership, and it does not say what happened to the money inside the platform." if en else
             "- هذا ترتيب بالمؤشرات وليس إثبات ملكية، ولا يقول ما جرى للمال داخل المنصة.")
    return L


if __name__ == "__main__":
    g = json.load(open(sys.argv[1], encoding="utf-8"))
    print("\n".join(lines(find(g))))
