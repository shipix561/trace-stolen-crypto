#!/usr/bin/env python3
"""
identify.py - what do documented, public sources say about this address? Python 3.8+.

    python identify.py btc ADDRESS                      offline: your labels, site scans, cached reports, address type
    python identify.py btc ADDRESS --live               also asks public providers (explorer tags, address statistics)
    python identify.py eth 0xADDRESS --live --graph graph.json --out identity.md
    python identify.py btc ADDRESS --live --external    also asks the optional third-party label provider (enrich.py)

It collects EVIDENCE, each item with its source, the source's type, a date, a confidence and what it supports
(an entity name, a type, a risk). Then it summarizes: the probable entity (if any), the classification
(exchange / custodian / bridge / smart contract / service-like / unknown) and risk flags, always next to the
evidence and the list of sources that were and were NOT consulted.

What it deliberately does not do: it does not name a person. A label says something about an ADDRESS (it belongs to
a platform or service), never about an account holder; an ENS name is a self-chosen name and not an identity.
No result means "nothing found in the sources consulted", never "clean" or "no entity".
"""
import argparse
import json
import os
import re
import sys
from datetime import date

import acct_tracer
import chains
import btc_tracer
import labels_tool
import ledger
import site_scan
import taxonomy

LEVEL = {"high": 3, "medium": 2, "low": 1}
CONF_AR = {"high": "عالية", "medium": "متوسطة", "low": "منخفضة"}
STYPE_AR = {"official_record": "سجل رسمي", "company_disclosure": "إفصاح رسمي", "provider_record": "سجل مزوّد",
            "public_source": "مصدر عام", "user_statement": "إدخال يدوي منك", "automated_tool": "أداة آلية أو استنتاج"}
KIND_AR = {"label": "تصنيف", "tag": "وسم عام", "inference": "استنتاج", "site": "موقع", "report": "بلاغ", "technical": "تقني",
           "behavior": "سلوك", "ens": "اسم ENS", "registry": "سجل"}
STATUS_AR = {"identified": "محدَّدة", "probable": "محتملة", "weak": "ضعيفة الدعم", "conflict": "متعارضة", "unknown": "غير معروفة"}
LIMITS = [
    "هذا التقرير يصنّف عنوانًا ولا يحدد شخصًا: صاحب الحساب لدى المنصة لا يظهر في أي مصدر عام، ويصل إليه المحققون بطلب رسمي.",
    "التصنيف دليل وليس إثباتًا. أكّده من مصدر ثانٍ ومن المنصة نفسها قبل مراسلتها أو الاستناد إليه.",
    "غياب الأدلة يعني أن المصادر التي استُشيرت لا تعرف العنوان، ولا يعني أنه سليم ولا أنه بلا جهة.",
    "الاسم المنشور على مستكشف أو في ENS يختاره صاحبه أو يضعه المستكشف، وقد يكون خاطئًا أو مضلّلًا.",
]


def today():
    return date.today().isoformat()


def source_type_of(src):
    s = (src or "").lower()
    if s.startswith("official page"):
        return "company_disclosure"
    if s.startswith("review:"):
        return "user_statement"
    if s.startswith("bundle:"):
        return "public_source"
    if "ofac" in s:
        return "official_record"
    if s.startswith(("manual", "web")) or "manual" in s:
        return "user_statement"
    if any(k in s for k in ("site-scan", "satoshidata", "deposit pattern", "cluster inference", "inferred", "auto")):
        return "automated_tool"
    return "public_source"


def ev(source, stype, kind, statement, confidence, category=None, entity=None, when=None, supports=(), conflict=False, hint=None):
    return {"source": source, "source_type": stype, "kind": kind, "statement": statement, "confidence": confidence,
            "category": taxonomy.canon(category) if category else None, "entity": entity, "date": when or "غير مسجّل",
            "supports": list(supports), "conflict": conflict, "hint": hint}


# ---------------- providers ----------------
def p_labels(labels, addr):
    e = labels.get(addr)
    if e is None:
        return []
    if isinstance(e, str):
        e = {"label": e}
    rv = e.get("review") or {}
    if rv.get("status") == "rejected":
        return [ev("مراجعة: %s" % rv.get("by", "-"), "user_statement", "label", "رفض مراجع تصنيفًا لهذا العنوان%s: لا يُعتمد." % ((" (" + rv["note"] + ")") if rv.get("note") else ""), "low", when=rv.get("at"))]
    src = e.get("source") or "غير مسجّل"
    cat = taxonomy.canon(e.get("category"))
    seen = " | مراجَع ومؤكَّد: %s (%s)" % (rv.get("by"), rv.get("at")) if rv.get("status") == "confirmed" else ""
    out = [ev(src, source_type_of(src), "label", "مصنّف في قاعدتك: «%s»%s%s" % (e.get("label", ""), " (%s)" % taxonomy.ar(cat) if cat else "", seen),
              e.get("confidence") or "low", cat, e.get("label"), e.get("updated") or e.get("added"), ("entity", "type") if cat else ("entity",))]
    for alt in e.get("alt", []):
        out.append(ev(alt.get("source") or "غير مسجّل", source_type_of(alt.get("source")), "label",
                      "تصنيف مختلف في القاعدة: «%s»" % alt.get("label"), "low", entity=alt.get("label"), supports=("entity",), conflict=True))
    return out


def p_graph(graph, addr):
    n = (graph or {}).get("nodes", {}).get(addr)
    if not n or not n.get("inferred"):
        return []
    return [ev("استنتاج من التتبع (%s)" % n.get("source", "-"), "automated_tool", "inference",
               "عنوان يُرجَّح أنه تابع لـ«%s»: %s" % (n.get("label"), n["inferred"]), "low", n.get("category"), n.get("label"), supports=("entity", "type"))]


def p_sites(base_dir, addr):
    db = site_scan.load_json(os.path.join(base_dir, site_scan.DB_FILE), {})
    out = []
    for domain, s in db.items():
        if addr in s.get("addresses", {}):
            tier = s.get("tier")
            out.append(ev("فحص موقع (site_scan)", "automated_tool", "site",
                          "عُرض في الموقع %s (مؤشرات الخطر: %s)" % (domain, tier), "low",
                          "suspicious-site" if tier in ("HIGH", "MEDIUM") else None, None, s.get("scanned_at"),
                          ("risk",) if tier in ("HIGH", "MEDIUM") else ()))
    return out


def p_reports_cache(base_dir, chain, addr):
    import reports_check
    cache = site_scan.load_json(os.path.join(base_dir, reports_check.CACHE_FILE), {})
    s = cache.get("%s:%s" % (chain, addr))
    return _reports_ev(s, reports_check) if s else []


def _reports_ev(s, rc):
    if not s.get("count"):
        return [ev("Chainabuse (بلاغات عامة)", "public_source", "report", "لا بلاغات عامة عن هذا العنوان وقت الفحص.", "low", when=s.get("checked_at"))]
    lab = rc.label_from(s)
    return [ev("Chainabuse (بلاغات عامة من مستخدمين)", "public_source", "report",
               "%d بلاغًا عامًا (متحقَّق منها: %d، من موثوقين: %d). البلاغ ادعاء مستخدم وليس حكمًا." % (s["count"], s.get("checked", 0), s.get("trusted", 0)),
               lab[2], lab[1], None, s.get("checked_at"), ("risk",))]


def p_reports_live(base_dir, chain, addr, key):
    import reports_check
    return _reports_ev(reports_check.lookup(addr, chain, key, base_dir=base_dir), reports_check)


def p_technical(chain, addr):
    desc = None
    if chain == "btc":
        a = addr.lower()
        if addr.startswith("1"):
            desc = "P2PKH: عنوان مفتاح عام قياسي"
        elif addr.startswith("3"):
            desc = "P2SH: عنوان سكربت، قد يكون متعدد التوقيع أو حفظًا مشتركًا، ولا يدل على جهة بذاته"
        elif a.startswith("bc1q") and len(a) == 42:
            desc = "P2WPKH: SegWit بمفتاح عام"
        elif a.startswith("bc1q") and len(a) == 62:
            desc = "P2WSH: سكربت SegWit، قد يكون متعدد التوقيع أو حفظًا"
        elif a.startswith("bc1p"):
            desc = "P2TR: Taproot"
    elif chains.is_evm(chain):
        desc = "عنوان بصيغة EVM: لا يُعرف من الصيغة إن كان حسابًا أو عقدًا"
    elif chain == "tron":
        desc = "عنوان TRON (حساب أو عقد)"
    elif chain == "sol":
        desc = "عنوان Solana (حساب أو برنامج أو حساب رمز)"
    elif chains.is_utxo(chain):
        desc = "عنوان على شبكة %s: لا تدل الصيغة وحدها على جهة" % chains.get(chain)["name_ar"]
    return [ev("تحليل صيغة العنوان", "automated_tool", "technical", desc, "high", when=today(), supports=("type",))] if desc else []


def p_explorer(chain, addr, key=None):
    if chain != "eth":
        return []
    d = acct_tracer.http(acct_tracer.ETH_BASE + "/addresses/" + addr + ("?apikey=" + key if key else ""))
    src, out = "Blockscout (مستكشف عام)", []
    if d.get("is_contract"):
        out.append(ev(src, "public_source", "technical", "العنوان عقد ذكي%s" % (" باسم «%s»" % d["name"] if d.get("name") else ""),
                      "medium", "contract", None, today(), ("type",)))
    if d.get("ens_domain_name"):
        out.append(ev(src, "public_source", "ens", "اسم ENS مرتبط: %s (اسم يختاره المالك ولا يثبت هوية)" % d["ens_domain_name"], "low", when=today()))
    for t in d.get("public_tags") or []:
        name = t.get("display_name") or t.get("label") if isinstance(t, dict) else None
        if name:
            out.append(ev(src, "public_source", "tag", "وسم عام منشور: «%s»" % name, "low", entity=name, when=today(), supports=("entity",)))
    if d.get("is_scam"):
        out.append(ev(src, "public_source", "report", "المستكشف يعلّم هذا العنوان كاحتيال", "low", "scam", None, today(), ("risk",)))
    return out


def p_tronscan(addr):
    """Read public TRON account metadata; labels are evidence about an address, not a person."""
    import urllib.parse
    url = "https://apilist.tronscanapi.com/api/account?address=" + urllib.parse.quote(addr, safe="")
    d = acct_tracer.http(url)
    out = []
    name = d.get("name") or d.get("addressTag") or d.get("tag")
    if name:
        out.append(ev("TronScan (بيانات حساب عامة)", "public_source", "tag",
                      "اسم/وسم منشور للحساب: «%s»؛ لا يثبت هوية شخص طبيعي." % str(name)[:200],
                      "low", entity=str(name)[:200], when=today(), supports=("entity",)))
    if d.get("address") and d.get("address") != addr:
        out.append(ev("TronScan (بيانات حساب عامة)", "public_source", "technical",
                      "أعاد المزوّد عنوانًا مختلفًا؛ لم يُستخدم لتسمية العنوان المدخل.", "low", when=today()))
    if d.get("isContract") or d.get("contractMap"):
        out.append(ev("TronScan (بيانات حساب عامة)", "public_source", "technical",
                      "تظهر بيانات المزوّد مؤشرًا على عقد ذكي؛ يلزم التحقق من تفاصيل العقد.", "medium", "contract", when=today(), supports=("type",)))
    return out


def public_research_links(chain, addr):
    """URLs for manual verification in public sources; no personal-data scraping."""
    import urllib.parse
    q = urllib.parse.quote('"' + addr + '"')
    links = []
    if chain == "btc":
        links += [{"name": "mempool.space", "url": "https://mempool.space/address/" + addr},
                  {"name": "Blockstream Explorer", "url": "https://blockstream.info/address/" + addr}]
    elif chain == "eth":
        links += [{"name": "Etherscan", "url": "https://etherscan.io/address/" + addr},
                  {"name": "Blockscout", "url": "https://eth.blockscout.com/address/" + addr}]
    else:
        links += [{"name": "مستكشف الشبكة", "url": chains.explorer_addr(chain, addr)}]
    links += [{"name": "بحث ويب مطابق للعنوان", "url": "https://www.google.com/search?q=" + q},
              {"name": "بحث Bing مطابق للعنوان", "url": "https://www.bing.com/search?q=" + q}]
    return links


def p_behavior(chain, addr):
    if chain != "btc":
        return []
    d = btc_tracer.get("/address/" + addr)
    cs, ms = d["chain_stats"], d.get("mempool_stats") or {}
    n = cs["tx_count"] + ms.get("tx_count", 0)
    out = []
    if n >= 1000:
        out.append(ev("إحصاءات العنوان من مزوّد البلوكشين", "public_source", "behavior",
                      "نشاط مرتفع جدًا: %d معاملة. هذا النمط شائع في الخدمات (بورصة أو حفظ أو معالج دفع) وقليل في المحافظ الفردية، لكنه لا يسمّي الجهة." % n,
                      "low", when=today(), supports=("type",), hint="service-like"))
    funded, spent = cs["funded_txo_sum"], cs["spent_txo_sum"]
    if n >= 20 and funded > 0 and (funded - spent) / funded < 0.01:
        out.append(ev("إحصاءات العنوان من مزوّد البلوكشين", "public_source", "behavior",
                      "رصيد شبه صفري مقابل تدفق كبير (%d معاملة): عنوان تمرير للأموال." % n, "low", when=today(), supports=("type",), hint="pass-through"))
    return out


def p_external(chain, addr):
    import enrich
    if chain != "btc":
        return []
    res = enrich.provider_satoshidata()(addr)
    if not res:
        return []
    return [ev("satoshidata (طرف ثالث غير مُتحقَّق)", "automated_tool", "tag", "المزوّد يصنّفه: «%s» (%s)" % (res[0], taxonomy.ar(res[1])),
               "low", res[1], res[0], today(), ("entity", "type"))]


# ---------------- assessment ----------------
def assess(evidence):
    cands = {}
    for e in evidence:
        if e["entity"] and e["kind"] in ("label", "tag", "inference"):
            c = cands.setdefault(e["entity"].strip().casefold(), {"name": e["entity"], "evidence": []})
            c["evidence"].append(e)
    ranked = []
    for c in cands.values():
        ev_ = c["evidence"]
        sources = {e["source"] for e in ev_}
        best = max(LEVEL[e["confidence"]] for e in ev_)
        official = any(e["source_type"] in ("official_record", "company_disclosure") and e["confidence"] == "high" for e in ev_)
        medium_sources = {e["source"] for e in ev_ if LEVEL[e["confidence"]] >= 2 and e["source_type"] != "automated_tool"}
        if official or len(medium_sources) >= 2:
            conf = "high"
        elif medium_sources:
            conf = "medium"
        else:
            conf = "low"
        cats = [e["category"] for e in sorted(ev_, key=lambda e: -LEVEL[e["confidence"]]) if e["category"] and not taxonomy.is_risk(e["category"])]
        ranked.append({"name": c["name"], "confidence": conf, "category": cats[0] if cats else None, "sources": sorted(sources), "score": (LEVEL[conf], len(sources), best)})
    ranked.sort(key=lambda r: r["score"], reverse=True)
    strong = [r for r in ranked if r["confidence"] in ("high", "medium")]
    if not ranked:
        status = "unknown"
    elif len(strong) >= 2:
        status = "conflict"
    else:
        status = {"high": "identified", "medium": "probable", "low": "weak"}[ranked[0]["confidence"]]
    top = ranked[0] if ranked else None
    ctype = None
    if top and top["category"] and status != "conflict":
        ctype = {"type": top["category"], "label_ar": taxonomy.ar(top["category"]), "basis": "تصنيف الجهة المحتملة"}
    if not ctype:
        for e in evidence:
            if e["category"] == "contract":
                ctype = {"type": "contract", "label_ar": "عقد ذكي", "basis": e["source"]}
                break
    if not ctype and any(e.get("hint") == "service-like" for e in evidence):
        ctype = {"type": "service-like", "label_ar": "غالبًا خدمة (غير مسمّاة)", "basis": "نمط النشاط وليس تسمية"}
    risks = {}
    for e in evidence:
        flag = e["category"] if e["category"] and (taxonomy.is_risk(e["category"]) or e["category"] in ("suspicious-site", "reported")) else None
        if flag:
            r = risks.setdefault(flag, {"flag": flag, "flag_ar": taxonomy.ar(flag), "confidence": e["confidence"], "sources": set()})
            r["sources"].add(e["source"])
            if LEVEL[e["confidence"]] > LEVEL[r["confidence"]]:
                r["confidence"] = e["confidence"]
    return {"status": status, "entity": top, "alternatives": ranked[1:4], "classification": ctype,
            "risk_flags": [dict(r, sources=sorted(r["sources"])) for r in risks.values()]}


def identify(chain, address, base_dir=".", labels=None, graph=None, live=False, external=False, key=None, report_key=None):
    addr = labels_tool.norm(address)
    if not addr:
        raise ValueError("عنوان غير صالح.")
    if labels is None:
        labels = labels_tool.load(os.path.join(base_dir, "labels.json"))
    if chains.is_evm(chain):
        labels = {(k.lower() if k.startswith("0x") else k): v for k, v in labels.items()}
    evidence, consulted, skipped = [], [], []

    def run(name, fn, *args):
        try:
            evidence.extend(fn(*args))
            consulted.append(name)
        except Exception as e:
            skipped.append("%s: تعذّر (%s)" % (name, str(e)[:100]))
    run("قاعدة تصنيفاتك (labels.json، وفيها قائمة OFAC إن استوردتها)", p_labels, labels, addr)
    run("نتائج فحص المواقع التي فحصتها", p_sites, base_dir, addr)
    run("بلاغات Chainabuse المحفوظة محليًا", p_reports_cache, base_dir, chain, addr)
    run("صيغة العنوان", p_technical, chain, addr)
    if graph:
        run("استنتاجات التتبع الحالي", p_graph, graph, addr)
    if live:
        if chain == "eth":
            run("Blockscout (وسوم وعقود وENS)", p_explorer, chain, addr, key)
        elif chain == "tron":
            run("TronScan (بيانات الحساب العامة)", p_tronscan, addr)
        else:
            skipped.append("%s: لا يوجد ضمن هذا البرنامج مصدر مجاني موثوق يربط كل عنوان باسم شخص؛ راجع روابط البحث العامة أدناه" % chains.get(chain)["name_en"])
        run("إحصاءات النشاط من مزوّد البلوكشين", p_behavior, chain, addr)
        if report_key:
            run("Chainabuse (بحث مباشر، يستهلك من حصتك الشهرية)", p_reports_live, base_dir, chain, addr, report_key)
        else:
            skipped.append("Chainabuse المباشر: لا مفتاح (CHAINABUSE_KEY)")
    else:
        skipped.append("البحث الحي في المزوّدين العامين: لم يُفعَّل (استعمل --live)")
    if external:
        run("مزوّد وسوم خارجي (طرف ثالث)", p_external, chain, addr)
    else:
        skipped.append("مزوّد الوسوم الخارجي: لم يُفعَّل (--external)")
    a = assess(evidence)
    entity_name = a["entity"]["name"] if a["entity"] else None
    registry = None
    if entity_name and os.path.exists(os.path.join(base_dir, "ledger.db")):
        for p in ledger.platforms(os.path.join(base_dir, "ledger.db")):
            if p["platform"].strip().casefold() == entity_name.strip().casefold():
                registry = p
    return {"address": addr, "chain": chain, "generated": today(), "evidence": evidence, "assessment": a, "registry": registry,
            "research_links": public_research_links(chain, addr), "consulted": consulted, "not_consulted": skipped, "limits": LIMITS}


def report_text(r):
    a = r["assessment"]
    L = ["# هوية العنوان والأدلة", "", "العنوان: `%s` | الشبكة: %s | تاريخ التقرير: %s" % (r["address"], r["chain"].upper(), r["generated"]), "",
         "> تصنيف لعنوان من مصادر موثّقة، وليس تحديدًا لشخص. كل معلومة أدناه بمصدرها وتاريخها وثقتها."]
    L += ["", "## الخلاصة"]
    if a["entity"]:
        e = a["entity"]
        L.append("- الجهة المحتملة: **%s** | حالة التحديد: %s | الثقة: %s" % (e["name"], STATUS_AR[a["status"]], CONF_AR[e["confidence"]]))
        if a["status"] == "conflict":
            L.append("- ⚠ تعارض: توجد جهة أخرى بدعم متوسط أو أعلى: %s. لا تُحسم دون مراجعة المصادر." % "، ".join(x["name"] for x in a["alternatives"] if x["confidence"] != "low"))
        elif a["alternatives"]:
            L.append("- تسميات أخرى أضعف: %s" % "، ".join("%s (%s)" % (x["name"], CONF_AR[x["confidence"]]) for x in a["alternatives"]))
    else:
        L.append("- الجهة المحتملة: **لم تُعرف** في المصادر التي استُشيرت (انظر آخر التقرير).")
    c = a["classification"]
    L.append("- التصنيف: %s%s" % (c["label_ar"], " (الأساس: %s)" % c["basis"] if c else "") if c else "- التصنيف: غير معروف.")
    if a["risk_flags"]:
        L.append("- مؤشرات خطر: " + "؛ ".join("%s (ثقة %s: %s)" % (f["flag_ar"], CONF_AR[f["confidence"]], "، ".join(f["sources"])) for f in a["risk_flags"]))
    L += ["", "## الأدلة", "| # | النوع | ما يقوله | المصدر (نوعه) | التاريخ | الثقة |", "|---|---|---|---|---|---|"]
    if not r["evidence"]:
        L.append("| - | - | لا أدلة في المصادر المستشارة | - | - | - |")
    for i, e in enumerate(r["evidence"], 1):
        L.append("| %d | %s | %s%s | %s (%s) | %s | %s |" % (i, KIND_AR.get(e["kind"], e["kind"]), e["statement"].replace("|", "/"),
                                                         " ⚠ تعارض مع تصنيف آخر" if e["conflict"] else "", e["source"], STYPE_AR[e["source_type"]], e["date"], CONF_AR[e["confidence"]]))
    reg = r["registry"]
    if reg:
        L += ["", "## السجل الرسمي للمنصة (من دفتر أدلتك)"]
        for g in reg["registration"]:
            L.append("- دولة التسجيل: %s، %s%s. المصادر: %s. آخر تاريخ: %s%s" % (
                ledger.cname(g["country"]), ledger.STRENGTH_AR[g["strength"]], " (الكيان: %s)" % "، ".join(g["entities"]) if g["entities"] else "",
                "، ".join(g["sources"]), g["latest"], " ⚠ قديم" if g["stale"] else ""))
        for ch in reg["channels"]:
            L.append("- قناة الطلبات القانونية: %s (المصدر: %s، %s)%s" % (ch["value"], ch["source"], ch["obtained_at"], " ⚠ قديمة" if ch["stale"] else ""))
    if r.get("research_links"):
        L += ["", "## روابط للتحقق اليدوي (ليست أدلة بذاتها)", "افتحها بنفسك وسجّل ما تجده بدليله في «مراجعة التصنيفات» (review.py):"]
        L += ["- [%s](%s)" % (x["name"], x["url"]) for x in r["research_links"]]
    L += ["", "## المصادر", "**استُشيرت:** " + ("؛ ".join(r["consulted"]) or "لا شيء"), "**لم تُستشَر أو تعذّرت:**"] + ["- " + s for s in r["not_consulted"]]
    L += ["", "## ما لا يدل عليه هذا التقرير"] + ["- " + s for s in r["limits"]]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain", choices=chains.ORDER)
    ap.add_argument("address")
    ap.add_argument("--live", action="store_true", help="ask public providers (needs internet)")
    ap.add_argument("--external", action="store_true", help="ask the optional third-party label provider")
    ap.add_argument("--graph")
    ap.add_argument("--base", default=".")
    ap.add_argument("--out")
    ap.add_argument("--json")
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    a = ap.parse_args()
    graph = json.load(open(a.graph, encoding="utf-8")) if a.graph else None
    try:
        r = identify(a.chain, a.address, a.base, None, graph, a.live, a.external, a.api_key, os.environ.get("CHAINABUSE_KEY"))
    except ValueError as e:
        sys.exit(str(e))
    t = report_text(r)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(t)
    if a.json:
        json.dump(r, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(t)


if __name__ == "__main__":
    main()
