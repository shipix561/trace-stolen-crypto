#!/usr/bin/env python3
"""
brief.py - law-enforcement brief for a case. Python 3.8+.

    python brief.py --case ID [--cases cases] [--db ledger.db] [--out brief.md]

Merges two things you already have:
  - the case's trace (cases/ID/graph.json): which known platforms the funds reached, at which
    addresses, in which transactions, with the tainted amounts;
  - the ledger's platform registry: the platform's legal entity, the country it is registered in, and its
    legal-request channel, each with its SOURCE and DATE.
For every platform it writes one section a police officer or lawyer can act on, and it lists what is still
missing (for example "legal entity not documented") so you know what to add to the ledger first.

It does not invent facts: if the ledger has nothing about a platform, the brief says "not documented" and tells
you where to look (the platform's official terms and legal-notice pages). It never states who the account holder is.
The route of the request (direct order, international cooperation, the platform's law-enforcement portal) is decided
by the investigating authority; the general note in the brief is not legal advice.
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

import ledger
import taxonomy

PLATFORM_CATEGORIES = set(taxonomy.PLATFORM)
RECORDS = [
    "بيانات تسجيل الحساب والتحقق من الهوية (KYC) للحساب أو الحسابات التي تحكمت في العناوين المذكورة.",
    "سجلات الدخول وعناوين الشبكة والأجهزة المرتبطة بالحساب خلال الفترة المعنية.",
    "سجل الإيداع والسحب، وعناوين السحب المسجّلة، وأي عمليات تحويل لعملات أخرى أو إلى نقد.",
    "الحسابات الأخرى المرتبطة بنفس بيانات التسجيل أو الدخول، إن وُجدت.",
    "حفظ هذه السجلات وتقييد السحب من الحساب ريثما يصدر الطلب الرسمي، بقدر ما تسمح به سياسة المنصة والقانون.",
]


def fmt_time(t):
    if isinstance(t, (int, float)):
        t = t / 1000 if t > 1e11 else t
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(t) if t else "غير معروف"


def amount(e):
    return e.get("amount", e.get("btc", 0)) or 0


def valid_case_id(case_id):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", case_id or "") or case_id in (".", ".."):
        raise ValueError("رقم قضية غير صالح.")
    return case_id


def platforms_in_case(graph):
    """label -> {"addresses": {addr: inferred_note_or_None}, "edges": [edges into those addresses]}"""
    out = defaultdict(lambda: {"addresses": {}, "edges": []})
    for a, n in graph.get("nodes", {}).items():
        if n.get("label") and n.get("category") in PLATFORM_CATEGORIES and a != graph.get("start"):
            out[n["label"]]["addresses"][a] = n.get("inferred")
    for e in graph.get("edges", []):
        for label, info in out.items():
            if e["to"] in info["addresses"]:
                info["edges"].append(e)
    return out


def build(case_id, cases_dir="cases", db="ledger.db"):
    case_id = valid_case_id(case_id)
    gpath = os.path.join(cases_dir, case_id, "graph.json")
    graph = json.load(open(gpath, encoding="utf-8")) if os.path.exists(gpath) else None
    registry = {p["platform"].strip().casefold(): p for p in ledger.platforms(db)}
    found = platforms_in_case(graph) if graph else {}
    for c in ledger.claims(db, case_id):  # platforms known only from ledger claims (no graph available)
        if c["kind"] == "platform_contact" and c["subject"] not in found:
            found[c["subject"]] = {"addresses": {}, "edges": []}
    chain = ledger.verify(db)
    L = ["# ملف للجهات المختصة: القضية %s" % case_id, "",
         "تاريخ الإعداد: %s | سلامة الدفتر: %s | بصمة الدفتر: %s" % (
             datetime.now(timezone.utc).strftime("%Y-%m-%d"), "سليمة" if not chain else "تالفة", ledger.head(db)[:16]),
         "", "> مادة منظَّمة لمساعدة الجهة المحققة. لا تحدد هوية أحد ولا تُثبت ملكية أي حساب: الهوية عند المنصة وتُسلَّم للجهات المختصة بالطريق الرسمي. "
             "الأدلة الأصلية هي التي تُقدَّم، وهذا الملف تلخيص لها. لا يُتخذ إجراء ضد شخص بناءً عليه."]
    if chain:
        L += ["", "**تحذير: سلسلة الدفتر تالفة، لا تعتمد ما فيه قبل مراجعته.**"]
    L += ["", "## 1. ملخص القضية"]
    if graph:
        L.append("- الشبكة: %s | عنوان البداية: %s | العناوين المتتبَّعة: %d | التحويلات: %d" % (
            graph.get("chain", "btc").upper(), graph["start"], len(graph["nodes"]), len(graph["edges"])))
        if graph.get("model"):
            L.append("- نموذج التتبع: %s (التلوث مدى: تقدير نسبي وحد أقصى)." % graph["model"])
        if graph.get("unspent"):
            L.append("- مال ملوّث لم يُنفق بعد: %.6f في %d مخرج." % (sum(u["taint"] for u in graph["unspent"]), len(graph["unspent"])))
    else:
        L.append("- لا يوجد graph.json لهذه القضية في %s: التفاصيل أدناه من الدفتر فقط." % cases_dir)
    L += ["", "## 2. المنصات التي وصلتها الأموال والاختصاص"]
    tasks = []
    if not found:
        L.append("- لم تُسجَّل منصات معروفة وصلتها الأموال في هذه القضية.")
    for name in sorted(found, key=str.casefold):
        info, reg = found[name], registry.get(name.strip().casefold())
        L += ["", "### المنصة: %s" % name]
        gaps = []
        entities = sorted({e for r in (reg or {}).get("registration", []) for e in r["entities"]})
        if entities:
            L.append("- الكيان القانوني: %s" % "، ".join(entities))
        else:
            gaps.append("الكيان القانوني غير موثّق")
            L.append("- الكيان القانوني: **غير موثّق.** ابحث عنه في شروط الاستخدام وصفحة الإشعار القانوني على الموقع الرسمي للمنصة.")
        regs = (reg or {}).get("registration", [])
        if regs:
            for r in regs:
                L.append("- دولة التسجيل: %s، **%s** (%s). المصادر: %s، آخر تاريخ: %s%s" % (
                    ledger.cname(r["country"]), ledger.STRENGTH_AR[r["strength"]], r["why"], "، ".join(r["sources"]),
                    r["latest"], " ⚠ قديم: تحقق من حداثته" if r["stale"] else ""))
            if len({r["country"] for r in regs if r["strength"] != "weak"}) > 1:
                gaps.append("تعارض في دولة التسجيل")
                L.append("- ⚠ تعارض في دولة التسجيل بين مصادر مختلفة: يُحسم بالرجوع للسجل الرسمي.")
            if all(r["strength"] == "weak" for r in regs):
                gaps.append("دولة التسجيل بمصادر ضعيفة فقط")
        else:
            gaps.append("دولة التسجيل غير موثّقة")
            L.append("- دولة التسجيل: **غير موثّقة.**")
        chans = (reg or {}).get("channels", [])
        if chans:
            for c in chans:
                L.append("- قناة الطلبات القانونية: %s (المصدر: %s، %s، موثوقية %s)%s" % (
                    c["value"], c["source"], c["obtained_at"], {"high": "عالية", "medium": "متوسطة", "low": "منخفضة"}[c["reliability"]],
                    " ⚠ قديمة: تحقق أنها ما زالت معتمدة" if c["stale"] else ""))
            if all(c["stale"] for c in chans):
                gaps.append("قناة الطلبات قديمة")
        else:
            gaps.append("قناة الطلبات القانونية غير مسجّلة")
            L.append("- قناة الطلبات القانونية: **غير مسجّلة.** تُؤخذ من صفحة جهات إنفاذ القانون في الموقع الرسمي للمنصة.")
        if info["addresses"]:
            L.append("- العناوين التي وصلتها الأموال:")
            for a, inf in info["addresses"].items():
                L.append("  - `%s`%s" % (a, "  [مستنتج: %s: يحتاج تأكيدًا من المنصة]" % inf if inf else ""))
        if info["edges"]:
            L += ["", "| المعاملة | الوقت | المبلغ | الملوّث (تقدير / حد أقصى) |", "|---|---|---|---|"]
            for e in info["edges"]:
                tt = "%.6f / %.6f" % (e["taint"], e.get("taint_max", 0)) if e.get("taint") is not None else "-"
                L.append("| %s | %s | %.8g %s | %s |" % (e["txid"], fmt_time(e.get("time")), amount(e), e.get("asset", "BTC"), tt))
        L += ["", "السجلات المطلوب حفظها وتزويد الجهة المحققة بها:"] + ["- " + r for r in RECORDS]
        L.append("")
        L.append("**جاهزية الملف:** " + ("مكتمل المعلومات الأساسية." if not gaps else "ناقص: " + "؛ ".join(gaps) + "."))
        tasks += ["%s: %s" % (name, g) for g in gaps]
    L += ["", "## 3. طريق الطلب (إرشاد عام وليس استشارة قانونية)",
          "- تُحدِّد الجهة المحققة المسار: طلب مباشر إن كانت المنصة ضمن اختصاصها، أو قنوات التعاون الدولي، أو بوابة المنصة المخصصة لجهات الإنفاذ إن وُجدت.",
          "- دولة تسجيل المنصة تبيّن أي جهة قضائية تخضع لها الشركة، وليست دولة صاحب الحساب ولا دولة نقطة اتصاله.",
          "- الرسائل الجاهزة للمنصات (exchange_notice_*.md) إشعارات حفظ من الضحية ولا تغني عن الطلب الرسمي."]
    L += ["", "## 4. ما ينقص الدفتر", ("- " + "\n- ".join(tasks)) if tasks else "- لا نقص في المعلومات الأساسية للمنصات المذكورة.",
          "", "أضف الناقص في لسان «الأدلة والدول» (يُنصح بتسجيل معلومات المنصات تحت رقم القضية GLOBAL لتُستعمل في كل القضايا)، من مصادر رسمية فقط."]
    return "\n".join(L)


def save(case_id, cases_dir="cases", db="ledger.db"):
    text = build(case_id, cases_dir, db)
    folder = os.path.join(cases_dir, valid_case_id(case_id))
    path = None
    if os.path.isdir(folder):
        path = os.path.join(folder, "law_enforcement_brief.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return text, path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--cases", default="cases")
    ap.add_argument("--db", default="ledger.db")
    ap.add_argument("--out")
    a = ap.parse_args()
    try:
        text = build(a.case, a.cases, a.db)
    except ValueError as e:
        sys.exit(str(e))
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text)
    print(text)


if __name__ == "__main__":
    main()
