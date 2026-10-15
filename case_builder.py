#!/usr/bin/env python3
"""
case_builder.py - turn a trace into a recovery case. Python 3.8+.

    python case_builder.py btc ADDRESS --stolen 0.6 --victim "Name" --report-no 123/2026
    python case_builder.py eth 0xADDRESS --depth 3
    python case_builder.py btc ADDRESS --graph graph.json      (reuse an existing trace)

What it produces, in a new folder under cases/:
  summary.md                 plain-language "truth report": where the money is NOW and what to do first
  freeze_targets.csv         every address with its status, amounts and current balance
  exchange_notice_<name>.md  one ready letter per exchange the funds reached
  tether_freeze_request.md   if USDT is still sitting in wallets (Ethereum / TRON)
  police_report.md           incident report with the evidence tables
  graph.json                 the trace itself

The first hours matter: exchanges and Tether can only restrict funds that have not moved yet.
Nothing here names a person. Account-holder identity is released by the exchange to
law enforcement through formal process. Findings are probabilistic; read the limits in summary.md.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import types
from collections import defaultdict
from datetime import datetime, timezone

import acct_tracer
import btc_tracer
import clusters
import ledger
import operation
import patterns
import review
import reports_check
import utxo_trace
import chains
import evm_api
import verify

RISK = btc_tracer.RISK
DELAY = 0.3
DUST = {"BTC": 0.0005, "LTC": 0.005, "DOGE": 5, "BCH": 0.0005, "ETH": 0.01, "BNB": 0.01, "POL": 10, "SOL": 0.05, "TRX": 100, "USDT": 10, "USDC": 10, "DAI": 10}
BTC_RE = re.compile(r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,87})$")
STATUS_AR = {
    "EXCHANGE": "وصلت إلى جهة معروفة (بورصة أو خدمة): يمكن مخاطبتها الآن",
    "RISK": "وصلت إلى جهة عالية الخطورة (احتيال أو عقوبات أو خلط)",
    "SERVICE": "خدمة غير مصنّفة كثيرة النشاط (غالبًا بورصة تحتاج تأكيدًا)",
    "HOLDING": "ما زالت في محفظة غير معروفة (يجب مراقبتها)",
    "MIXED": "اختفى أثرها داخل خدمة خلط (CoinJoin)",
    "PASSED_ON": "مرّت من هذه المحافظ وانتقلت",
    "MOVED_ON_UNTRACED": "فرغت المحفظة ولم نصل لوجهة الأموال (وسّع التتبع)",
    "UNEXPLORED": "لم تُفحص بعد (وسّع التتبع)",
}


# ---------------- helpers ----------------
def valid_address(chain, addr):
    try:
        return chains.normalize(chain, addr)
    except ValueError as e:
        if chain not in chains.CHAINS:
            raise ValueError("Unknown network.")
        raise ValueError("Address does not match the selected network. " + str(e))


def fmt(d):
    return ", ".join("%.4f %s" % (v, k) for k, v in d.items() if v) or "-"


def fmt_bal(d):
    # unlike fmt(), keeps zero balances visible ("0.0000 BTC") so an empty wallet is not shown as "-"
    return ", ".join("%.4f %s" % (v, k) for k, v in d.items()) or "-"


def fmt_time(t):
    if isinstance(t, (int, float)):
        t = t / 1000 if t > 1e11 else t
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(t) if t else "unknown"


def slug(s):
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_") or "entity"


def table(head, rows):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
                     + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


# ---------------- balances: where is the money NOW ----------------
def fetch_balance(chain, addr, key=None):
    if chains.is_utxo(chain):
        with btc_tracer.use_chain(chain):
            d = btc_tracer.get("/address/" + addr)
        c, m = d["chain_stats"], d.get("mempool_stats") or {}
        net = (c["funded_txo_sum"] - c["spent_txo_sum"]) + (m.get("funded_txo_sum", 0) - m.get("spent_txo_sum", 0))
        return {chains.native(chain): net / 1e8}
    if chains.is_evm(chain):
        nat = chains.native(chain)
        if chain == "eth":
            q = "?apikey=" + key if key else ""
            d = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/" + addr + q)
            tb = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/" + addr + "/token-balances" + q)
            tb = tb if isinstance(tb, list) else tb.get("items", [])
        else:
            d, tb = evm_api.address_info(chain, addr, key), evm_api.token_balances(chain, addr, key)
        out = {nat: int(d.get("coin_balance") or 0) / 1e18}
        for t in tb:
            tok = t.get("token") or {}
            ca = (tok.get("address_hash") or tok.get("address") or "").lower()
            sym = acct_tracer.STABLES[chain].get(ca)
            if sym:
                out[sym] = int(t.get("value") or 0) / 10 ** int(tok.get("decimals") or chains.stable_decimals(chain, ca, 18))
        return out
    if chain == "sol":
        import sol_api
        return sol_api.fetch_balance(addr)
    d = acct_tracer.http(acct_tracer.TRON_BASE + "/v1/accounts/" + addr, {"TRON-PRO-API-KEY": key} if key else None)
    acc = (d.get("data") or [{}])[0]
    out = {"TRX": (acc.get("balance") or 0) / 1e6}
    for item in acc.get("trc20") or []:
        for contract, val in item.items():
            if contract in acct_tracer.STABLES["tron"]:
                out["USDT"] = int(val) / 1e6
    return out


def incoming(g):
    inc = defaultdict(lambda: defaultdict(float))
    for e in g["edges"]:
        inc[e["to"]][e.get("asset", "BTC")] += e["taint"] if e.get("taint") is not None else verify.amount(e)
    return inc


def collect_balances(g, chain, key=None, limit=60):
    inc = incoming(g)
    cands = [a for a, n in g["nodes"].items()
             if a != g["start"] and not n.get("label") and not n.get("note") and not a.startswith("coinjoin:")]
    cands.sort(key=lambda a: -sum(inc[a].values()))
    out = {}
    for a in cands[:limit]:
        try:
            out[a] = fetch_balance(chain, a, key)
        except Exception:
            out[a] = None
        time.sleep(DELAY)
    return out


def infer_labels(g):
    # Conservative label inference, always marked "inferred" with LOW confidence:
    #  1) addresses in the same Bitcoin cluster as one labeled address;
    #  2) the deposit pattern: an unlabeled address that sends ALL its funds to one labeled exchange
    #     wallet is most likely a deposit address of that exchange (that is where the victim's money entered).
    nodes, n = g["nodes"], 0
    out = defaultdict(set)
    for e in g["edges"]:
        out[e["from"]].add(e["to"])
    real = lambda a: nodes.get(a, {}).get("label") and nodes[a].get("category") != "coinjoin" and not nodes[a].get("inferred")
    for c in g.get("clusters", []):
        src = [a for a in c if real(a)]
        if src and len({nodes[a]["label"] for a in src}) == 1:
            for a in c:
                if a in nodes and not nodes[a].get("label") and not nodes[a].get("review_rejected"):
                    nodes[a].update(label=nodes[src[0]]["label"], category=nodes[src[0]].get("category"),
                                    source="cluster inference", confidence="low",
                                    inferred="same wallet cluster as %s" % src[0])
                    n += 1
    for a, tos in list(out.items()):
        if a == g["start"] or nodes.get(a, {}).get("label") or nodes.get(a, {}).get("review_rejected") or len(tos) != 1:
            continue
        t = next(iter(tos))
        if real(t) and nodes[t].get("category") == "exchange":
            nodes[a].update(label=nodes[t]["label"], category="exchange", source="deposit pattern",
                            confidence="low", inferred="sends all its funds to %s" % t)
            n += 1
    return n


# ---------------- classification ----------------
def classify(g, balances):
    nodes, outs, inc = g["nodes"], {e["from"] for e in g["edges"]}, incoming(g)
    groups = defaultdict(list)
    for a, n in nodes.items():
        if a == g["start"]:
            continue
        cat, note, bal = n.get("category"), n.get("note") or "", balances.get(a)
        if cat == "coinjoin":
            st = "MIXED"
        elif n.get("label") and cat in RISK:
            st = "RISK"
        elif n.get("label"):
            st = "EXCHANGE"
        elif "collection point" in note or "high activity" in note:
            st = "SERVICE"
        elif bal and any(v > DUST.get(k, 0) for k, v in bal.items()):
            st = "HOLDING"
        elif a in outs:
            st = "PASSED_ON"
        elif bal is None:
            st = "UNEXPLORED"
        else:
            st = "MOVED_ON_UNTRACED"
        groups[st].append({"address": a, "label": n.get("label"), "category": cat, "depth": n.get("depth"),
                           "amounts": dict(inc[a]), "balance": bal, "taint": n.get("taint"), "taint_max": n.get("taint_max"), "inferred": n.get("inferred")})
    for lst in groups.values():
        lst.sort(key=lambda x: -sum(x["amounts"].values()))
    return groups


def totals(items):
    t = defaultdict(float)
    for it in items:
        for k, v in it["amounts"].items():
            t[k] += v
    return dict(t)


def balance_totals(items):
    t = defaultdict(float)
    for i in items:
        for k, v in (i["balance"] or {}).items():
            t[k] += v
    return dict(t)


# ---------------- letters ----------------
def party(p):
    return (p.get("victim") or "[YOUR FULL NAME]", p.get("contact") or "[EMAIL / PHONE]",
            p.get("report_no") or "[POLICE REPORT NUMBER, if filed]")


def exchange_letter(name, items, g, p, ref):
    victim, contact, report = party(p)
    addrs = {i["address"] for i in items}
    rows = [(e["txid"], fmt_time(e.get("time")), "%.8g %s%s" % (verify.amount(e), e.get("asset", "BTC"),
            (" (tainted: %.6f proportional estimate" % e["taint"] + (", up to %.6f upper bound)" % e["taint_max"] if e.get("taint_max") else ")")) if e.get("taint") else "")) for e in g["edges"] if e["to"] in addrs]
    stolen = ("%s %s" % (p["stolen"], p.get("asset", "")) if p.get("stolen") is not None else "[AMOUNT]")
    return "\n".join([
        "Subject: URGENT - request to preserve and restrict account(s) that received stolen crypto-assets - %s" % ref,
        "", "To: Compliance / Legal Department, %s" % name, "Date: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "", "I am the victim of a fraud. Crypto-assets taken from me were traced on the public %s blockchain to "
        "deposit address(es) that, according to published address attribution, belong to %s." % (g.get("chain", "btc").upper(), name),
        "", "## Summary", "- Origin of the loss (address): %s" % g["start"], "- Amount lost: %s" % stolen, "- My payment transaction: %s" % (p.get("txid") or "[TX HASH]"),
        "- Address(es) at %s:" % name] + ["  - %s%s" % (i["address"], "  [inferred, please confirm: %s]" % i["inferred"] if i.get("inferred") else "") for i in sorted(items, key=lambda i: i["address"])] + [
        "", "## Transactions", table(["Transaction hash", "Time", "Amount"], rows), "",
        "## Requests", "1. Preserve all records for the account(s) that controlled the address(es) above: registration and "
        "identification (KYC) data, login/IP logs, deposit and withdrawal history.",
        "2. Temporarily restrict withdrawals from those account(s), to the extent your policy and the law allow, while law "
        "enforcement is engaged.", "3. Reply with your law-enforcement contact and procedure. A police report is reference: %s." % report,
        "", "I am not asking you to disclose personal data to me. I understand it is released to the authorities through formal "
        "process. The attribution of the address to your platform comes from public labels and may need your confirmation.",
        "", "Evidence package available on request (verification report, SHA-256 evidence archive).",
        "", "Regards,", victim, contact])


def tether_letter(items, g, p, ref):
    victim, contact, report = party(p)
    rows = [(i["address"], fmt({k: v for k, v in (i["balance"] or {}).items() if k in ("USDT", "USDC")}),
             fmt(i["amounts"])) for i in items]
    return "\n".join([
        "Subject: Request to freeze USDT linked to fraud - %s" % ref, "",
        "To: Tether Operations Limited (law-enforcement liaison). Sent by the victim and to be supported by law enforcement.",
        "", "Funds stolen from me were traced on the public %s blockchain to the addresses below, which still hold USDT "
        "(balances read at the time of this letter)." % chains.get(g.get("chain", "eth"))["name_en"],
        "", table(["Address", "Current balance", "Traced inflow"], rows), "",
        "Origin of the loss: %s | Police report: %s" % (g["start"], report), "",
        "Request: freeze the listed addresses to prevent further movement, pending law-enforcement process. "
        "I can provide the transaction hashes and the verification report.", "", victim, contact])


def police_report(g, groups, p, ref):
    victim, contact, report = party(p)
    L = ["# بلاغ احتيال بأصول رقمية - %s" % ref, "",
         "المبلّغ: %s | وسيلة التواصل: %s" % (victim, contact),
         "تاريخ الحادثة: %s | المبلغ المفقود: %s %s" % (p.get("incident") or "[التاريخ]",
                                                      p["stolen"] if p.get("stolen") is not None else "[المبلغ]", p.get("asset", "")),
         "الشبكة: %s | عنوان بداية الأثر: %s | معاملة الدفع: %s" % (g.get("chain", "btc").upper(), g["start"], p.get("txid") or "[رقم المعاملة]"), "",
         "## الوقائع", p.get("story") or "[اكتب هنا باختصار كيف تعرّفت على المحتال وكيف أرسلت الأموال، مع التواريخ وأي محادثات محفوظة]",
         "", "## ما رُصد على السلسلة العلنية",
         "- عدد العناوين المتتبَّعة: %d | عدد التحويلات: %d" % (len(g["nodes"]), len(g["edges"]))]
    ex = groups.get("EXCHANGE", [])
    if ex:
        L += ["", "### أموال وصلت إلى جهات معروفة (المطلوب: حفظ البيانات وتقييد الحسابات، وتزويد الشرطة بهوية أصحابها)"]
        rows = []
        for i in ex:
            for e in g["edges"]:
                if e["to"] == i["address"]:
                    rows.append((i["label"], i["address"], e["txid"], fmt_time(e.get("time")),
                                 "%.8g %s" % (verify.amount(e), e.get("asset", "BTC"))))
        L.append(table(["الجهة", "العنوان", "المعاملة", "الوقت", "المبلغ"], rows))
    hold = groups.get("HOLDING", [])
    if hold:
        L += ["", "### أموال ما زالت في محافظ غير معروفة (يُطلب تتبّعها والتحفظ عليها)"]
        L.append(table(["العنوان", "الرصيد الحالي", "المحوَّل إليها"], [(i["address"], fmt(i["balance"] or {}), fmt(i["amounts"])) for i in hold]))
    L += ["", "## الطلب", "1. فتح تحقيق في الواقعة.",
          "2. مخاطبة الجهات المذكورة أعلاه رسميًا لحفظ بيانات الحسابات وتقييدها وتزويد الجهات المختصة بهوية أصحابها.",
          "3. طلب تجميد أي رصيد USDT عبر قناة Tether الرسمية للجهات الأمنية إن وُجد.",
          "", "المرفقات: ملف graph.json، تقرير التحقق (verification_report.md)، أرشيف الأدلة (evidence/) إن وُجد.",
          "تنبيه: العناوين المنسوبة للجهات مصدرها تصنيفات عامة وتحتاج تأكيد الجهة نفسها."]
    return "\n".join(L)


# ---------------- truth report ----------------
def actions_for(groups, g, chain, ref, p=None):
    A = ["تواصل اليوم مع المنصة أو البنك الذي حوّلت منه (التفاصيل في «خيطك الأول» أعلاه): هو يعرف حسابك وعمليتك، ولا تكلّفك الخطوة شيئًا."]
    names = sorted({i["label"] for i in groups.get("EXCHANGE", [])})
    for n in names:
        A.append("أرسل الإشعار الجاهز إلى %s (exchange_notice_%s.md) عبر قسم الامتثال لديهم، وأخبر الشرطة بنفس الخطوة." % (n, slug(n)))
    hold = groups.get("HOLDING", [])
    usdt = [i for i in hold if (i["balance"] or {}).get("USDT", 0) > DUST["USDT"]]
    if chains.is_account(chain) and usdt:
        A.append("يوجد USDT لم يتحرك بعد في %d محفظة: اطلب تجميده (tether_freeze_request.md) عبر الشرطة وأرسل الإشعار مباشرة أيضًا." % len(usdt))
    if hold:
        A.append("فعّل المراقبة على المحافظ التي ما زالت تحمل المال: python watch.py %s %s" % (
            chain, " ".join(i["address"] for i in hold[:5])))
    if groups.get("UNEXPLORED") or groups.get("MOVED_ON_UNTRACED") or groups.get("SERVICE"):
        A.append("وسّع التتبع بعمق أكبر وراجع العناوين الكثيرة النشاط يدويًا، فقد تكشف بورصة جديدة.")
    held = {i["address"] for i in hold}
    un = [u for u in (g.get("unspent") or []) if u["address"] not in held]
    if un:
        A.append("يوجد مال ملوّث لم يُنفق بعد في %d عنوان: بلّغ فورًا وفعّل المراقبة: python watch.py %s %s" % (
            len(un), chain, " ".join(sorted({u["address"] for u in un})[:5])))
    urls = sorted({u for m_ in g.get("messages", []) for u in m_.get("urls", [])})
    if urls:
        A.append("وردت روابط داخل المعاملات (OP_RETURN): افحصها بـ python site_scan.py scan %s" % urls[0])
    A.append("ثم قدّم بلاغًا للشرطة وأرفق police_report.md وملف الجهات المختصة (brief.py): هي وحدها تطلب بيانات الحساب من المنصة بطريق رسمي، ولا يغني عنها شيء مما سبق، لكنها ليست الخطوة الأولى. كل يوم تأخير يزيد احتمال تحرك الأموال.")
    A.append("سجّل بلاغك أيضًا على منصة Chainabuse العلنية: تربط بين بلاغات ضحايا العملية نفسها وترفع فرص الاسترداد.")
    A.append("تجاهل أي جهة تعرض عليك استرداد الأموال مقابل رسوم مسبقة: أغلبها احتيال ثانٍ.")
    return A


def extra_lines(extra):
    L, extra = [], extra or {}
    pat, ops, seen = extra.get("pat"), extra.get("ops"), extra.get("seen")
    if pat and pat["findings"]:
        L += ["", "## أنماط سلوكية رُصدت (مؤشرات للمراجعة وليست حكمًا)",
              "التقييم: %s (%d نقطة) - %s" % (pat["tier"], pat["score"], pat["tier_text"])]
        L += ["- %s" % f["text"] for f in pat["findings"][:8]]
    if ops:
        L += ["", "## من دفع إلى عنوان البداية؟"] + operation.lines_ar(ops)
    if extra.get("diag"):
        import diagnose
        L += [""] + diagnose.lines_ar(extra["diag"])
    gg = extra.get("g")
    if gg and gg.get("cluster_info"):
        L += ["", "## تجميع المحافظ (احتمالي وليس يقينًا)"]
        for c_ in gg["cluster_info"][:5]:
            L.append("- %d عنوانًا | الثقة: %s | %s. %s" % (len(c_["members"]), clusters.CONF_AR[c_["confidence"]],
                                                          clusters.TYPE_AR[c_["type"]], "؛ ".join(c_["reasons"][:3])))
        if gg.get("cluster_skipped"):
            L.append("- استُبعدت %d معاملة كثيرة المدخلات من التجميع (غالبًا تجميع خدمة)." % gg["cluster_skipped"])
    if gg and gg.get("messages"):
        L += ["", "## بيانات مضمّنة في المعاملات (OP_RETURN)"]
        for m_ in gg["messages"][:8]:
            if m_.get("protocol") == "omni":
                o_ = m_.get("omni") or {}
                L.append("- %s: تحويل Omni (%s %s): القيمة الفعلية بالرمز وليست بالعملة الأصلية" % (m_["txid"][:12], o_.get("amount", "?"), o_.get("token", "")))
            elif m_.get("protocol") == "runes":
                L.append("- %s: معاملة Runes" % m_["txid"][:12])
            else:
                L.append("- %s: %s" % (m_["txid"][:12], m_.get("text") or "بيانات ثنائية: " + m_["hex"][:40]))
            for k_, t_ in (("urls", "رابط"), ("emails", "بريد"), ("telegram", "حساب تلغرام")):
                for v_ in m_.get(k_, []):
                    L.append("  %s: %s" % (t_, v_))
    if extra.get("reports") is not None:
        L += ["", "## بلاغات علنية عن عنوان البداية (Chainabuse)"] + reports_check.lines_ar(extra["reports"])
    if gg and str(gg.get("model", "")).startswith("utxo"):
        L += ["", "## تتبّع العملات بدقة (UTXO)",
              "- يُتتبَّع المخرج المحدد الذي دفعته (%s:%d) وليس العنوان كله، فلا تختلط أموال الآخرين." % tuple(gg["start_outpoint"]),
              "- الملوّث يُعرض كمدى: تقدير نسبي (haircut) وحد أقصى (poison). اذكر أيهما تستشهد به."]
        for a_, n_ in gg["nodes"].items():
            if n_.get("label") and n_.get("category") != "coinjoin" and n_.get("taint"):
                if n_.get("inferred"):  # already counted inside the exchange total: do not present it as a second arrival
                    L.append("  ↳ منه عبر عنوان إيداع مستنتج %s: %.4f BTC (جزء من الإجمالي أعلاه، يحتاج تأكيدًا)" % (a_, n_["taint"]))
                else:
                    L.append("- وصل إلى %s (%s): ملوّث %.4f BTC (حد أقصى %.4f)" % (n_["label"], a_, n_["taint"], n_.get("taint_max", 0)))
        un = gg.get("unspent") or []
        if un:
            L.append("- لم يُنفق بعد (ما زال في مكانه): %.6f BTC ملوّث في %d مخرج" % (sum(u["taint"] for u in un), len(un)))
        low = [e for e in gg["edges"] if gg["nodes"].get(e["to"], {}).get("label") and e.get("confs", 99) < 6]
        if low:
            L.append("- تحذير: %d تحويل إلى جهات معروفة بأقل من 6 تأكيدات (خطر إعادة تنظيم الكتل)." % len(low))
        if gg.get("coinjoins"):
            L.append("- توقف التتبع عند %d معاملة CoinJoin محتملة." % gg["coinjoins"])
        if gg.get("beyond_depth"):
            L.append("- %d مخرجًا أُنفق خلف حد العمق: زد --depth." % len(gg["beyond_depth"]))
        if gg.get("gaps"):
            L.append("- %d مخرجًا بلا عنوان قياسي لم يُتتبَّع." % len(gg["gaps"]))
        if gg.get("truncated"):
            L.append("- توقف عند حد عدد المعاملات: ارفع --max-tx.")
    if seen:
        L += ["", "## ربط القضايا", "- %d عنوانًا ظهر في قضايا سابقة لديك (شغّل: python operation.py shared)." % len(seen)]
    return L


EXPLORER = {k: chains.get(k)["addr_url"].replace("%s", "") for k in chains.ORDER}


def dominant_forward(g):
    """(address, amount, share) when ONE destination received at least 70% of what the start address sent onward."""
    tot = defaultdict(float)
    for e in g["edges"]:
        if e["from"] == g["start"]:
            tot[e["to"]] += e["taint"] if e.get("taint") is not None else verify.amount(e)
    whole = sum(tot.values())
    if not whole:
        return None
    a, v = max(tot.items(), key=lambda kv: kv[1])
    return (a, v, v / whole) if v / whole >= 0.7 else None


def leads(g, groups, chain, p, ops=None):
    """The few leads this case actually offers, in plain language: (title, why, what to do). Police is deliberately not one of
    them: it is the last step, not the thread."""
    out, p = [], p or {}  # (priority, title, why, do)
    en = p.get("lang") in ("en", "es", "fr", "tr", "ru")   # English is the server-side pivot for these UI languages

    def S(ar, e):
        return e if en else ar
    taint_mode = g.get("mode") == "taint"
    un = g.get("unspent") or []
    hold = groups.get("HOLDING", [])
    ex = groups.get("EXCHANGE", [])
    svc = {i["address"]: i for i in groups.get("SERVICE", [])}
    explorer = EXPLORER.get(chain, "")
    if ops and ops.get("last"):
        years = (time.time() - ops["last"]) / (365.25 * 86400)
        if years >= 2:
            out.append((0, S("مرّت نحو %.1f سنة على آخر دفعة وصلت إلى هذا العنوان", "About %.1f years have passed since the last payment reached this address") % years,
                        S("الأثر قديم: المال تحرك على الأرجح منذ زمن، فلا تتوقع تجميدًا.", "The trail is old: the money has most likely moved long ago, so do not expect a freeze."),
                        S("ما يبقى مفيدًا: معرفة المنصة التي استلمت المال لتدعم بلاغك وتربطه بضحايا آخرين. واسأل الشرطة أو محاميًا عن المدد النظامية في بلدك قبل أن تعوّل على أي مسار.",
                          "What remains useful: learning which platform received the money, to support your report and link it to other victims. Ask the police or a lawyer about the legal time limits in your country before relying on any route.")))
    dom = dominant_forward(g)
    if dom and dom[0] in svc:
        addr, _v, share = dom
        out.append((1, S("العنوان الذي بدأت منه أرسل %d%% مما استلمه إلى عنوان واحد كثير النشاط", "The address you started from sent %d%% of what it received to one very busy address") % round(share * 100),
                    S("هذا أوضح مسار في قضيتك: ما تحتاجه هو معرفة من يملك ذلك العنوان. قد يكون محفظة ساخنة لمنصة (فيكون عنوانك عنوان إيداع فيها)، وقد يكون عنوان تجميع للمحتال نفسه.",
                      "This is the clearest path in your case: what you need is to know who owns that address. It may be a platform's hot wallet (making yours a deposit address there), or the scammer's own collection address."),
                    S("1) افتحه في المستكشف: %s%s وانظر معاملاته الواردة. 2) إن رأيت آلاف المعاملات الواردة من عناوين مختلفة، كل منها يرسل رصيده كله إليه، فهو غالبًا محفظة منصة. "
                      "3) ابحث عنه بين علامتي تنصيص في محرك بحث وفي مواقع تصنيف العناوين العامة. 4) إن عرفت اسم المنصة فسجّله في لسان «مراجعة التصنيفات» (باسمك ودليلك) "
                      "وأعد بناء القضية: تتولد لك الرسالة الجاهزة لتلك المنصة.",
                      "1) Open it in the explorer: %s%s and look at its incoming transactions. 2) If you see thousands of incoming transactions from different addresses, each sending its whole balance to it, it is probably a platform wallet. "
                      "3) Search for it between quotation marks in a search engine and on public address-labelling sites. 4) If you learn the platform's name, record it in the \"Label review\" tab (with your name and evidence) "
                      "and rebuild the case: the ready-made message for that platform is generated for you.") % (explorer, addr)))
        dg = p.get("diag")
        if dg and dg.get("address") == addr:
            import diagnose
            out[-1] = (out[-1][0], out[-1][1], out[-1][2] + (" Automatic behaviour check result: %s. %s" % (diagnose.VERDICT_EN[dg["verdict"]], diagnose.NEXT_EN[dg["verdict"]]) if en else
                                      " نتيجة الفحص الآلي لسلوكه: %s. %s" % (diagnose.VERDICT_AR[dg["verdict"]], diagnose.NEXT_AR[dg["verdict"]])),
                       out[-1][3])
        svc.pop(addr)
    if un or hold:
        addrs = sorted({u["address"] for u in un} | {i["address"] for i in hold})
        amount = "%.6f BTC" % sum(u["value"] for u in un) if un else fmt(balance_totals(hold))
        do = S("بلّغ المنصة التي حوّلت منها اليوم، وشغّل المراقبة لتعرف لحظة تحرك المال: python watch.py %s %s",
               "Notify the platform you transferred from today, and run monitoring to know the moment the money moves: python watch.py %s %s") % (chain, " ".join(addrs[:3]))
        if chains.is_account(chain) and any((i["balance"] or {}).get("USDT", 0) > DUST["USDT"] for i in hold):
            do += S(". والمال USDT: أرسل الإشعار الجاهز tether_freeze_request.md إلى Tether (يُفضَّل عبر الشرطة أيضًا) فقد تجمّده.",
                    ". The funds are USDT: send the ready notice tether_freeze_request.md to Tether (preferably through the police too); it may freeze them.")
        if taint_mode:
            out.append((1, S("المال لم يتحرك بعد (%s)", "The money has not moved yet (%s)") % amount,
                        S("ما لم يتحرك يمكن التحفظ عليه، ولهذا هو أقوى خيط تملكه الآن. وبعد أن يتحرك يصعب كل شيء.",
                          "Money that has not moved can be held, which is why this is the strongest lead you have now. Once it moves, everything gets harder."), do))
        else:
            out.append((3, S("عنوان ما زال فيه رصيد (%s)، لكنه قد لا يكون مالك", "An address still holds a balance (%s), but it may not be your money") % amount,
                        S("التتبع هنا بالعنوان لا بالمخرج الذي دفعته، فلا نستطيع الجزم أن هذا الرصيد من مالك.",
                          "Tracing here is by address, not by the output you paid, so we cannot be sure this balance is yours."),
                        S("تأكد أولًا بالتتبع من رقم معاملتك (لسان «ابدأ من هنا») قبل أن تبني عليه. ويمكنك مراقبته: ",
                          "First confirm by tracing from your transaction ID (the \"Start here\" tab) before building on it. You can monitor it: ") + do.split(": ", 1)[-1]))
    if ex:
        names = sorted({i["label"] for i in ex})
        out.append((2, S("وصل المال إلى منصة معروفة: %s", "The money reached a known platform: %s") % (", " if en else "، ").join(names),
                    S("المنصات تحتفظ بسجل من استلم المال وتستجيب للجهات الرسمية، وتستطيع تقييد الحساب أحيانًا إن وصلها بلاغ مبكر.",
                      "Platforms keep a record of who received the money and respond to official bodies, and can sometimes restrict the account if an early report reaches them."),
                    S("أرسل اليوم الإشعار الجاهز (exchange_notice_*.md) إلى قسم الامتثال في المنصة مع رقم المعاملة. لا تنتظر الشرطة لتفعل ذلك، أرسله بالتوازي معها.",
                      "Today, send the ready notice (exchange_notice_*.md) to the platform's compliance department with the transaction ID. Do not wait for the police to do it; send it in parallel.")))
    if svc:
        top = next(iter(svc.values()))
        out.append((4, S("وصل المال إلى عنوان كثير النشاط لم تُعرف جهته (%s)", "The money reached a very busy address whose owner is unknown (%s)") % fmt(top["amounts"]),
                    S("هذا غالبًا حساب إيداع في بورصة أو خدمة. اسم تلك المنصة هو الخيط الذي ينقصك، وتستطيع الوصول إليه بنفسك.",
                      "This is usually a deposit account at an exchange or service. That platform's name is the missing thread, and you can reach it yourself."),
                    S("1) افتح العنوان في المستكشف: %s%s وانظر عدد معاملاته: الآلاف تعني خدمة. 2) انسخ العنوان وابحث عنه في محرك بحث بين علامتي تنصيص، وفي مواقع تصنيف العناوين العامة. "
                      "3) إن ظهر اسم منصة فسجّله في لسان «مراجعة التصنيفات» (باسمك ودليلك) وأعد بناء القضية: تتولد لك الرسالة الجاهزة لتلك المنصة.",
                      "1) Open the address in the explorer: %s%s and check how many transactions it has: thousands mean a service. 2) Copy the address and search for it between quotation marks in a search engine and on public address-labelling sites. "
                      "3) If a platform's name appears, record it in the \"Label review\" tab (with your name and evidence) and rebuild the case: the ready-made message for that platform is generated for you.") % (explorer, top["address"])))
    txid = p.get("txid")
    if not p.get("investigation"):  # a plain wallet investigation has no "platform you paid from"
        out.append((9, S("المنصة أو البنك الذي حوّلت منه", "The platform or bank you transferred from"),
                    S("هي تعرف حسابك وعمليتك، وتستطيع حفظ السجلات وفتح بلاغ داخلي والتواصل مع المنصة المستلمة. وإن كان الدفع ببطاقة أو تحويل بنكي فقد يمكن إلغاؤه أو الاعتراض عليه.",
                      "It knows your account and your operation, can preserve records, open an internal report and contact the receiving platform. If you paid by card or bank transfer, it may be possible to cancel or dispute it."),
                    S("اتصل بالدعم الرسمي داخل تطبيقها اليوم%s، وقل صراحة إنها عملية احتيال وتطلب حفظ السجلات وفتح بلاغ داخلي. وإن دفعت ببطاقة أو حوالة بنكية فاطلب من البنك إلغاء العملية أو الاعتراض عليها فورًا. لا شيء مضمون، لكنها خطوة بلا تكلفة.",
                      "Contact official support inside its app today%s, and say plainly that this is fraud and ask it to preserve records and open an internal report. If you paid by card or bank wire, ask the bank to cancel or dispute the operation immediately. Nothing is guaranteed, but this step costs nothing.") % (
                        S(" وأعطهم رقم المعاملة %s", " and give them transaction ID %s") % txid if txid else "")))
    if (len(out) == 1 and not p.get("investigation")) or not out:
        out.insert(0, (0, S("الأثر لم يكتمل بعد", "The trail is not complete yet"),
                   S("لم يصل المال إلى منصة معروفة ولا وجدنا مالًا لم يتحرك ضمن العمق المفحوص.", "The money has not reached a known platform and we found no unmoved funds within the depth examined."),
                   S("وسّع العمق، وراجع العناوين الكثيرة النشاط، ثم أعد بناء القضية.", "Increase the depth, review the very busy addresses, then rebuild the case.")))
    return [(t, w, d) for _, t, w, d in sorted(out, key=lambda x: x[0])][:4]


def lead_lines(g, groups, chain, p, ops=None):
    en = (p or {}).get("lang") in ("en", "es", "fr", "tr", "ru")
    L = ["## Your first lead (start here)" if en else "## خيطك الأول (ابدأ من هنا)"]
    if g.get("mode") != "taint":
        L.append("> Note: this traces by address, not by the output you paid, so large amounts on the map may belong to others. For accuracy start from your transaction ID in the \"Start here\" tab." if en else
                 "> تنبيه: هذا تتبع بالعنوان وليس بالمخرج الذي دفعته، فالمبالغ الكبيرة في الخريطة قد تعود لغيرك. للدقة ابدأ من رقم معاملتك في لسان «ابدأ من هنا».")
    for i, (title, why, do) in enumerate(leads(g, groups, chain, p, ops), 1):
        L += ["%d. **%s**" % (i, title), ("   - Why: " if en else "   - لماذا: ") + why, ("   - Do: " if en else "   - افعل: ") + do]
    return L + [""]


def summary_ar(g, groups, actions, p, bal_ok, audit, extra=None):
    chain, mode = g.get("chain", "btc"), g.get("mode", "all")
    L = ["# تقرير الحقيقة: أين ذهبت الأموال؟", "",
         "الشبكة: %s | نقطة البداية: %s" % (chain.upper(), g["start"]),
         "تاريخ التقرير: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
         "عدد العناوين: %d | التحويلات: %d" % (len(g["nodes"]), len(g["edges"])), ""]
    L += lead_lines(g, groups, chain, p, (extra or {}).get("ops"))
    try:
        import platform_finder
        L += platform_finder.lines(platform_finder.find(g, p.get("diag")), p.get("lang") or "ar", EXPLORER.get(chain, "")) + [""]
        if groups.get("MIXED") or any(n.get("category") in ("mixer", "coinjoin") for n in g["nodes"].values()):
            import mix_check
            L += mix_check.lines(mix_check.detect(g), p.get("lang") or "ar") + [""]
    except Exception as e_:  # an extra section must never break the case
        L.append("> platform section unavailable: %s" % type(e_).__name__)
    L.append("## الخلاصة")
    ex, hold, mix = groups.get("EXCHANGE", []), groups.get("HOLDING", []), groups.get("MIXED", [])
    L.append("- وصلت إلى جهات معروفة: %s" % (fmt(totals(ex)) + " في %d عنوان" % len(ex) if ex else "لا شيء حتى الآن"))
    inf = [i for i in ex if i.get("inferred")]
    if inf:
        L.append("- منها %d عنوان إيداع مستنتج بالنمط (وليس مسجّلًا): يحتاج تأكيدًا قبل مراسلة المنصة." % len(inf))
    L.append("- ما زالت في محافظ غير معروفة: %s" % (fmt(balance_totals(hold)) if hold else "لا شيء في العناوين التي قُرئت أرصدتها"))
    unexp = groups.get("UNEXPLORED", [])
    if unexp:
        L.append("- تنبيه: لم يُقرأ رصيد %d عنوانًا (تجاوزت حد القراءة أو تعذّرت)، فقد يكون فيها مال." % len(unexp))
    L.append("- اختفى أثرها في خلط: %s" % (fmt(totals(mix)) if mix else "لا شيء"))
    if mode != "taint":
        L.append("- تنبيه: لم يُستعمل نموذج التلوث، فالمبالغ أعلاه هي إجمالي التحويلات وليست بالضرورة الأموال المسروقة وحدها."
                 + (" (تتبّع المسروق متاح للبيتكوين بإدخال المبلغ.)" if chain != "btc" else ""))
    if ex:
        L.append("- أفضل فرصة: الأموال وصلت إلى جهة تخضع للقانون ويمكن مخاطبتها بسرعة. القرار بيد الجهة والسلطات ولا شيء مضمون.")
    elif hold:
        L.append("- الأموال لم تخرج من محفظة خاصة بعد: الأولوية للمراقبة والتحفظ قبل أن تتحرك.")
    else:
        L.append("- الأثر لم يكتمل بعد: وسّع التتبع وراجع الجهات الكثيرة النشاط.")
    L += ["", "## الخطوات مرتبة حسب العجلة"] + ["%d. %s" % (i + 1, a) for i, a in enumerate(actions)]
    L += extra_lines(extra)
    L += ["", "## التفاصيل"]
    for st, title in STATUS_AR.items():
        items = groups.get(st)
        if not items:
            continue
        L += ["", "### %s (%d)" % (title, len(items))]
        for i in items[:8]:
            L.append("- %s%s: وصل %s%s" % (i["address"], " [%s%s]" % (i["label"], "، استنتاج: " + i["inferred"] if i.get("inferred") else "") if i["label"] else "", fmt(i["amounts"]),
                                           "، الرصيد الآن %s" % fmt_bal(i["balance"]) if i["balance"] else ""))
    c = defaultdict(int)
    for lvl, _ in audit:
        c[lvl] += 1
    L += ["", "## مستوى اليقين",
          "- التدقيق الداخلي: %d فشل، %d تحذير. %s" % (c["FAIL"], c["WARN"],
                                                       "راجع الأخطاء قبل الاعتماد على النتيجة." if c["FAIL"] else ""),
          "- لم يُجرَ تحقق من مصدر ثانٍ في هذا التقرير: شغّل verify.py audit graph.json قبل تقديم أي شيء.",
          "- الأرصدة الحالية %s" % ("قُرئت من الشبكة." if bal_ok else "لم تُقرأ (تعذّر الاتصال)، فتصنيف 'ما زالت في محفظة' غير متاح."),
          "", "## حدود",
          "- التجميع والتلوث والتصنيفات احتمالية. العناوين المنسوبة لبورصة تحتاج تأكيدًا من البورصة نفسها.",
          "- التقرير لا يحدد هوية أحد. الهوية تُطلب عبر الشرطة من البورصة.",
          "- لا تتواصل مع صاحب المحفظة ولا تتهمه. راجع محاميًا أو الشرطة قبل أي خطوة."]
    return "\n".join(L)


# ---------------- assembly ----------------
def build_case(g, labels, balances, p, ops=None, seen=None, reports=None):
    chain = g.get("chain", "btc")
    ref = p.get("ref") or "CASE-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    for a_, n_ in g["nodes"].items():  # a label a reviewer rejected must not come back through inference
        v_ = (labels or {}).get(a_)
        if isinstance(v_, dict) and (v_.get("review") or {}).get("status") == "rejected":
            n_["review_rejected"] = True
    infer_labels(g)
    groups = classify(g, balances)
    actions = actions_for(groups, g, chain, ref, p)
    audit = verify.audit_graph(g, labels)
    pat = patterns.analyze(g)
    extra = {"pat": pat, "ops": ops, "seen": seen, "g": g, "reports": reports, "diag": p.get("diag")}
    letters = {}
    by_label = defaultdict(list)
    for i in groups.get("EXCHANGE", []):
        by_label[i["label"]].append(i)
    for name, items in by_label.items():
        letters["exchange_notice_%s.md" % slug(name)] = exchange_letter(name, items, g, p, ref)
    usdt = [i for i in groups.get("HOLDING", []) if (i["balance"] or {}).get("USDT", 0) > DUST["USDT"]]
    if chains.is_account(chain) and usdt:
        letters["tether_freeze_request.md"] = tether_letter(usdt, g, p, ref)
    letters["police_report.md"] = police_report(g, groups, p, ref) + "\n" + "\n".join(extra_lines(extra))
    summary = summary_ar(g, groups, actions, p, any(v for v in balances.values()), audit, extra)
    return {"ref": ref, "summary": summary, "letters": letters, "groups": groups, "actions": actions}


def save_case(folder, case, g):
    os.makedirs(folder, exist_ok=True)
    open(os.path.join(folder, "summary.md"), "w", encoding="utf-8").write(case["summary"])
    for name, text in case["letters"].items():
        open(os.path.join(folder, name), "w", encoding="utf-8").write(text)
    json.dump(g, open(os.path.join(folder, "graph.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    with open(os.path.join(folder, "freeze_targets.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["status", "address", "label", "category", "traced_inflow", "current_balance"])
        for st, items in case["groups"].items():
            for i in items:
                w.writerow([st, i["address"], i["label"] or "", i["category"] or "", fmt(i["amounts"]), fmt_bal(i["balance"] or {})])
    return folder


def trace_chain(chain, addr, depth, stolen, labels, key=None, outpoint=None):
    if chains.is_utxo(chain):
        with btc_tracer.use_chain(chain):
            if outpoint:
                return utxo_trace.trace_outpoint(outpoint[0], outpoint[1], depth, labels, stolen)
            g = btc_tracer.trace(addr, depth, 200, chains.DEFAULT_MIN_NATIVE[chains.native(chain)], labels, taint=stolen is not None, stolen=stolen)
            g["chain"] = chain
            return g
    args = types.SimpleNamespace(depth=depth, min_stable=10, min_native=None, max_pages=4, max_fanout=30,
                                 all_tokens=False, api_key=key, internal=True)
    return acct_tracer.trace(chain, addr, args, labels)


def run_case(chain, addr, depth, stolen, labels, root, params=None, key=None, graph=None, network=True):
    p = dict(params or {})
    if stolen is not None:
        p["stolen"] = stolen
    p.setdefault("stolen", None)
    p.setdefault("asset", chains.native(chain) if chains.is_utxo(chain) else "")
    outpoint = (p["txid"], int(p["vout"])) if chains.is_utxo(chain) and p.get("txid") and p.get("vout") is not None else None
    eff = min(max(depth, 6), 8) if outpoint else max(1, min(depth, 5))
    g = graph or trace_chain(chain, valid_address(chain, addr), eff, stolen, labels, key, outpoint)
    g.setdefault("chain", chain)
    balances = collect_balances(g, chain, key) if network else {}
    held = defaultdict(float)  # exact: unspent outputs found by the UTXO trace
    for u in g.get("unspent") or []:
        held[u["address"]] += u["value"]
    for a_, v_ in held.items():
        balances[a_] = {chains.native(chain): v_}
    ops = None
    if network:
        try:
            ops = operation.analyze(operation.collect(chain, g["start"], key), labels)
        except Exception:
            ops = None  # payer analysis is optional: the case still builds without it
    if network and chains.is_utxo(chain):
        dom_ = dominant_forward(g)
        if dom_:
            try:  # behaviour check of the busy address the funds went to (platform wallet or collection address)
                import diagnose
                p["diag"] = diagnose.diagnose(chain, dom_[0], labels)
            except Exception:
                pass  # optional
    db_path = os.path.join(root, "cases.db")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    seen = operation.seen_before(db_path, list(g["nodes"]))
    reports = None
    key_ = os.environ.get("CHAINABUSE_KEY")
    if network and key_:
        try:
            reports = reports_check.lookup(g["start"], chain, key_, base_dir=root)
        except Exception:
            reports = None  # public-report lookup is optional (needs a key and monthly quota)
    case = build_case(g, labels, balances, p, ops, seen, reports)
    folder = save_case(os.path.join(root, stamp), case, g)
    operation.add_case(db_path, stamp, g)
    try:  # which known platforms the funds reached becomes (low-reliability) claims in the evidence ledger
        led = os.path.join(os.path.dirname(os.path.abspath(root)), "ledger.db")
        if ledger.record_case(led, stamp, g, labels):
            with open(os.path.join(folder, "evidence_ledger.md"), "w", encoding="utf-8") as f:
                f.write(ledger.report_text(led, stamp))
    except Exception:
        pass  # the ledger is optional: the case is complete without it
    try:  # addresses worth naming join the review queue automatically
        review.enqueue(os.path.join(os.path.dirname(os.path.abspath(root)), "review.db"), g, stamp, labels)
    except Exception:
        pass
    return {"graph": g, "summary": case["summary"], "letters": case["letters"], "folder": folder, "case_id": stamp}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=chains.ORDER)
    ap.add_argument("address", nargs="?")
    ap.add_argument("--graph", help="reuse an existing graph.json instead of tracing")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--stolen", type=float, default=None, help="stolen amount (Bitcoin taint mode)")
    ap.add_argument("--victim")
    ap.add_argument("--contact")
    ap.add_argument("--report-no")
    ap.add_argument("--incident", help="incident date")
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--out", default="cases")
    ap.add_argument("--no-network", action="store_true", help="skip balance lookups")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    a = ap.parse_args()
    if not a.address and not a.graph:
        sys.exit("Give an address or --graph graph.json")
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    graph = json.load(open(a.graph, encoding="utf-8")) if a.graph else None
    out = run_case(a.chain, a.address, a.depth, a.stolen, labels, a.out,
                   {"victim": a.victim, "contact": a.contact, "report_no": a.report_no, "incident": a.incident},
                   a.api_key, graph, not a.no_network)
    print(out["summary"])
    print("\nSaved to", out["folder"], "(%d letters)" % len(out["letters"]))


if __name__ == "__main__":
    main()
