#!/usr/bin/env python3
"""
precheck.py - before you send money. Python 3.8+.

    python precheck.py --flag seed_phrase                                  no internet needed
    python precheck.py --chain btc --address ADDRESS                       what do your sources say about it?
    python precheck.py --url https://site.example --flag withdrawal_fee    previously scanned sites and your blocklist
    python precheck.py --chain eth --address 0x... --url https://... --live   also scans the site and asks public providers

Flags you can raise yourself (--flag, repeatable):
    seed_phrase  withdrawal_fee  guaranteed_returns  remote_access  recovery_offer      (each one alone means STOP)
    online_relationship  urgency  unlicensed  address_from_chat  changed_address         (each one means CAUTION)

The verdict has three values and never "safe":
    STOP        a signal that is enough to refuse (a sanctioned or scam-reported address, a high-risk site, a flag above)
    CAUTION     something worrying that needs checking first
    NO FLAGS    nothing was found in the sources consulted. That does NOT mean the other side is honest.

Most scams that reach people carry one of the STOP flags in the story itself (fees to withdraw, a guaranteed profit,
a request for the recovery phrase), and no database is needed to see it. The data adds evidence on top.
"""
import argparse
import os
import sys
import urllib.parse

import identify
import labels_tool
import site_scan
import taxonomy

RED_FLAGS = {
    "seed_phrase": ("stop", "طُلبت منك عبارة الاسترداد أو المفتاح الخاص، أو ربط محفظتك بموقع لا تعرفه",
                    "لا تشارك عبارة الاسترداد مع أي أحد ولا تدخلها في أي موقع. من يطلبها يريد الاستيلاء على محفظتك."),
    "withdrawal_fee": ("stop", "طُلبت منك رسوم أو ضريبة أو تأمين لتتمكن من سحب أموالك",
                       "المنصات الحقيقية تخصم رسومها من الرصيد ولا تطلب دفعة جديدة قبل السحب. هذا من أكثر أنماط الاحتيال شيوعًا."),
    "guaranteed_returns": ("stop", "وعد بأرباح مضمونة أو يومية أو ثابتة",
                           "لا يوجد استثمار مضمون الربح. الوعد بذلك علامة احتيال."),
    "remote_access": ("stop", "طُلب منك تثبيت برنامج للتحكم بجهازك عن بعد",
                      "لا تثبّت برنامج تحكم عن بعد بطلب من أحد: يتيح له الوصول إلى حساباتك ومحفظتك."),
    "recovery_offer": ("stop", "عرض عليك أحد استرداد أموال فُقدت سابقًا مقابل رسوم مسبقة",
                       "هذه غالبًا عملية احتيال ثانية تستهدف الضحايا. لا تدفع مقابل وعد بالاسترداد."),
    "online_relationship": ("caution", "من يوجّهك للاستثمار شخص تعرّفت عليه عبر الإنترنت ولم تلتقِه",
                            "نمط شائع: بناء علاقة ثم توجيه للاستثمار. لا تحوّل مالًا لشخص لم تلتقِه، مهما بدا صادقًا."),
    "urgency": ("caution", "ضغط للاستعجال أو عرض محدود الوقت",
                "الاستعجال يمنعك من التحقق. المعاملة الصادقة تحتمل الانتظار يومًا."),
    "unlicensed": ("caution", "لم تجد للجهة سجلًا لدى جهة رقابية في بلدك",
                   "ابحث عن اسم الشركة في سجل الجهة الرقابية الرسمي في بلدك بنفسك، لا عبر رابط أرسلوه لك."),
    "address_from_chat": ("caution", "عنوان الدفع وصلك في محادثة أو رسالة، لا من موقع المنصة الرسمي الذي فتحته بنفسك",
                          "العناوين المرسلة في الرسائل تُنتحل بسهولة. خذ العنوان من القناة الرسمية فقط."),
    "changed_address": ("caution", "تغيّر عنوان الدفع عن المرة السابقة",
                        "تحقق بوسيلة أخرى (اتصال بالرقم الرسمي) قبل الدفع: تغيير العنوان حيلة معروفة."),
}
VERDICT_AR = {"STOP": "توقف: لا تدفع الآن", "CAUTION": "حذر: تحقق قبل أن تدفع",
              "NO_FLAGS": "لا مؤشرات في المصادر المستشارة (وهذا لا يعني أنه آمن)"}
GENERAL_ADVICE = [
    "لا تعتمد على لقطات شاشة أو أرقام أو روابط أعطاك إياها الطرف الآخر لإثبات صدقه.",
    "إن شككت: أوقف الدفع، وتحدث مع شخص تثق به قبل أي تحويل. التحويلات بالعملات الرقمية لا تُسترد.",
]
AFTER_PAYING = "إن كنت دفعت بالفعل: توقف عن أي دفعة إضافية فورًا، واحفظ كل الأدلة، وأبلغ الشرطة والمنصة التي حوّلت منها، ثم استعمل لسان «ابدأ من هنا» لبناء قضيتك."


def _site_signals(url, base_dir, live, scanner, payment_addr):
    host = urllib.parse.urlparse(url).hostname
    reasons, info, not_checked = [], None, []
    bare = site_scan.bare(host)
    block = site_scan.load_json(os.path.join(base_dir, site_scan.BLOCK_FILE), {})
    src = site_scan.blocklist_hit(bare, block)
    if src:
        reasons.append(("stop", "النطاق %s في قائمة حظر أدخلتها (%s)" % (bare, src), "قائمة الحظر"))
    prev = site_scan.load_json(os.path.join(base_dir, site_scan.DB_FILE), {}).get(bare)
    res = None
    if live:
        try:
            res = scanner(url, 4, base_dir, None, False)
        except (ValueError, RuntimeError) as e:
            not_checked.append("فحص الموقع تعذّر: %s" % e)
        except Exception as e:
            not_checked.append("فحص الموقع تعذّر (%s)" % str(e)[:80])
    tier, when, addrs = (res["tier"], "الآن", [a["address"] for a in res["addresses"]]) if res else \
        ((prev["tier"], "فُحص في %s" % prev["scanned_at"], list(prev.get("addresses", {}))) if prev else (None, None, []))
    if tier == "HIGH":
        reasons.append(("stop", "الموقع %s بمؤشرات احتيال قوية (%s)" % (bare, when), "فحص الموقع"))
    elif tier == "MEDIUM":
        reasons.append(("caution", "الموقع %s بمؤشرات مقلقة (%s)" % (bare, when), "فحص الموقع"))
    elif tier == "LOW":
        reasons.append(("info", "فحص الموقع %s لم يجد مؤشرات كافية (%s). هذا لا يعني أنه آمن." % (bare, when), "فحص الموقع"))
    else:
        not_checked.append("الموقع لم يُفحص من قبل ولم يُفعَّل البحث الحي (استعمل «بحث حي» لفحصه)")
    if payment_addr and addrs and payment_addr not in addrs:
        reasons.append(("caution", "العنوان الذي ستدفع إليه ليس من العناوين المعروضة في الموقع: تأكد من مصدره", "فحص الموقع"))
    elif payment_addr and payment_addr in addrs:
        reasons.append(("info", "العنوان معروض في هذا الموقع نفسه", "فحص الموقع"))
    if res or prev:
        info = {"tier": tier, "when": when, "addresses": addrs[:10]}
    return reasons, info, not_checked


def _address_signals(chain, addr, base_dir, live, key, report_key):
    r = identify.identify(chain, addr, base_dir, None, None, live, False, key, report_key)
    a, reasons = r["assessment"], []
    for f in a["risk_flags"]:
        c, strong = f["flag"], f["confidence"] in ("medium", "high")
        if c == "sanctioned":
            reasons.append(("stop", "العنوان في قائمة عقوبات: الدفع إليه قد يخالف القانون (المصدر: %s)" % "، ".join(f["sources"]), "هوية العنوان"))
        elif c in ("scam", "theft", "ransomware", "darknet"):
            reasons.append(("stop" if strong else "caution", "العنوان موسوم «%s» بثقة %s (%s)" % (f["flag_ar"], identify.CONF_AR[f["confidence"]], "، ".join(f["sources"])), "هوية العنوان"))
        else:
            reasons.append(("caution", "مؤشر خطر على العنوان: %s (%s)" % (f["flag_ar"], "، ".join(f["sources"])), "هوية العنوان"))
    if a["entity"] and not a["risk_flags"]:
        reasons.append(("info", "العنوان مصنّف باسم «%s» (%s، ثقة %s). تأكد أنه عنوان إيداع حسابك الرسمي نفسه وليس عنوانًا أرسله لك طرف آخر." % (
            a["entity"]["name"], identify.STATUS_AR[a["status"]], identify.CONF_AR[a["entity"]["confidence"]]), "هوية العنوان"))
    summary = {"status": a["status"], "entity": a["entity"]["name"] if a["entity"] else None, "risk_flags": [f["flag"] for f in a["risk_flags"]]}
    return reasons, summary, [s for s in r["not_consulted"] if "لم يُفعَّل" in s or "Chainabuse" in s]


def precheck(chain="btc", address=None, url=None, flags=(), live=False, base_dir=".", key=None, report_key=None, scanner=None):
    flags = list(dict.fromkeys(flags or ()))
    unknown = [f for f in flags if f not in RED_FLAGS]
    if unknown:
        raise ValueError("علامة غير معروفة: %s" % unknown[0])
    address, url = (address or "").strip() or None, (url or "").strip() or None
    if not (address or url or flags):
        raise ValueError("أدخل عنوانًا أو رابط موقع أو علّم علامة واحدة على الأقل.")
    if url:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("الرابط يجب أن يبدأ بـ http أو https.")
    reasons, advice, identity, site, not_checked = [], [], None, None, []
    for f in flags:
        lvl, text, adv = RED_FLAGS[f]
        reasons.append((lvl, text, "إجابتك"))
        advice.append(adv)
    if address:
        addr = labels_tool.norm(address)
        if not addr:
            raise ValueError("عنوان غير صالح.")
        rs, identity, nc = _address_signals(chain, addr, base_dir, live, key, report_key)
        reasons += rs
        not_checked += nc
    if url:
        rs, site, nc = _site_signals(url, base_dir, live, scanner or site_scan.scan, labels_tool.norm(address) if address else None)
        reasons += rs
        not_checked += nc
    levels = {r[0] for r in reasons}
    verdict = "STOP" if "stop" in levels else "CAUTION" if "caution" in levels else "NO_FLAGS"
    advice = list(dict.fromkeys(advice)) + GENERAL_ADVICE + ([AFTER_PAYING] if verdict == "STOP" else [])
    return {"verdict": verdict, "verdict_ar": VERDICT_AR[verdict], "reasons": [{"level": l, "text": t, "source": s} for l, t, s in reasons],
            "advice": advice, "identity": identity, "site": site, "not_checked": list(dict.fromkeys(not_checked))}


def report_text(r):
    icon = {"stop": "⛔", "caution": "⚠", "info": "ℹ"}
    L = ["# فحص قبل الدفع", "", "## النتيجة: %s" % r["verdict_ar"], ""]
    L += ["- %s %s (%s)" % (icon[x["level"]], x["text"], x["source"]) for x in r["reasons"]] or ["- لا مؤشرات في ما أدخلته أو في المصادر المستشارة."]
    L += ["", "## ماذا تفعل"] + ["- " + a for a in r["advice"]]
    if r["not_checked"]:
        L += ["", "## ما لم يُفحص"] + ["- " + n for n in r["not_checked"]]
    L += ["", "> غياب المؤشرات لا يعني أن الطرف الآخر صادق، ووجودها دليل للمراجعة وليس حكمًا على شخص. القرار الأخير لك، وأي تحويل بالعملات الرقمية لا يُسترد."]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="btc", choices=__import__("chains").ORDER)
    ap.add_argument("--address")
    ap.add_argument("--url")
    ap.add_argument("--flag", action="append", default=[], choices=sorted(RED_FLAGS))
    ap.add_argument("--live", action="store_true", help="scan the site and ask public providers (needs internet)")
    ap.add_argument("--base", default=".")
    a = ap.parse_args()
    try:
        r = precheck(a.chain, a.address, a.url, a.flag, a.live, a.base, os.environ.get("TRACER_API_KEY"), os.environ.get("CHAINABUSE_KEY"))
    except ValueError as e:
        sys.exit(str(e))
    print(report_text(r))
    sys.exit({"STOP": 2, "CAUTION": 1, "NO_FLAGS": 0}[r["verdict"]])


if __name__ == "__main__":
    main()
