#!/usr/bin/env python3
"""
ledger.py - evidence ledger and country assessment. Python 3.8+.

    python ledger.py add --case ID --kind platform_registration --subject "Exchange X" --country AE \
        --source "Company registry extract" --source-type company_disclosure --date 2026-09-30 --method "official extract"
    python ledger.py show   --case ID
    python ledger.py report --case ID --out evidence_ledger.md
    python ledger.py verify
    python ledger.py cases

The ledger stores CLAIMS, never conclusions. Every claim has: what it says, who said it (source and its
type), the date it was obtained, how it was obtained, and a reliability level that follows from the source
type (it can be lowered by you, never raised). Claims are chained by hashes, so editing or removing an old
claim is detectable.

Four kinds of "country" are kept strictly apart, because they answer different questions and are NOT
interchangeable:
  platform_registration  where a platform's company is registered
  network_contact        the country of a network point (e.g. an IP) tied to an account, IF known
  hosting                where a website is hosted
  residence_evidence     the country where the evidence supports a person's residence
The assessment never merges them into one "country of the scammer". A residence country is shown only when
backed by an official record or a lawfully received provider record; otherwise the answer is "undetermined".

The ledger is for jurisdiction evidence. Do not store personal names or home addresses in it: subjects are
platforms, accounts, wallet addresses or sites. Identity data is released to law enforcement by the platform.
This is an organizing aid, not legal advice and not a verdict on anyone.
"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import date, datetime, timezone

KINDS = {
    "platform_contact": "تماس بمنصة (من التتبع)",
    "platform_registration": "دولة تسجيل منصة",
    "network_contact": "دولة نقطة اتصال شبكة",
    "hosting": "دولة استضافة موقع",
    "residence_evidence": "دليل إقامة",
    "platform_channel": "قناة طلبات قانونية لمنصة",
}
COUNTRY_KINDS = {"platform_registration", "network_contact", "hosting", "residence_evidence"}
SOURCE_TYPES = {
    "official_record": ("high", "سجل رسمي (محكمة أو جهة إنفاذ أو جهة رقابية)"),
    "company_disclosure": ("high", "إفصاح رسمي أو سجل شركات أو شروط المنصة"),
    "provider_record": ("medium", "سجل من مزوّد أو منصة سُلِّم لك بطريقة نظامية"),
    "public_source": ("low", "مصدر عام (خبر أو موقع)"),
    "user_statement": ("low", "إفادة أو لقطة من الضحية"),
    "automated_tool": ("low", "أداة آلية (استنتاج)"),
}
LEVELS = {"high": 3, "medium": 2, "low": 1}
STRENGTH_ORDER = {"strong": 3, "moderate": 2, "weak": 1}
STALE_DAYS = 180
CN = {"AE": "الإمارات", "SA": "السعودية", "EG": "مصر", "IL": "إسرائيل", "PS": "فلسطين", "JO": "الأردن", "LB": "لبنان",
      "SY": "سوريا", "IQ": "العراق", "KW": "الكويت", "QA": "قطر", "BH": "البحرين", "OM": "عُمان", "YE": "اليمن",
      "SD": "السودان", "LY": "ليبيا", "TN": "تونس", "DZ": "الجزائر", "MA": "المغرب", "TR": "تركيا", "IR": "إيران",
      "US": "الولايات المتحدة", "GB": "المملكة المتحدة", "DE": "ألمانيا", "FR": "فرنسا", "ES": "إسبانيا", "IT": "إيطاليا",
      "NL": "هولندا", "CH": "سويسرا", "SE": "السويد", "MT": "مالطا", "CY": "قبرص", "RU": "روسيا", "UA": "أوكرانيا",
      "CN": "الصين", "HK": "هونغ كونغ", "SG": "سنغافورة", "JP": "اليابان", "KR": "كوريا الجنوبية", "IN": "الهند",
      "PK": "باكستان", "NG": "نيجيريا", "ZA": "جنوب أفريقيا", "BR": "البرازيل", "CA": "كندا", "AU": "أستراليا",
      "VG": "جزر العذراء البريطانية", "KY": "جزر كايمان", "SC": "سيشل", "PA": "بنما", "BS": "جزر البهاما", "LT": "ليتوانيا",
      "EE": "إستونيا", "PL": "بولندا", "AT": "النمسا", "TH": "تايلاند", "VN": "فيتنام", "MY": "ماليزيا", "ID": "إندونيسيا"}
FIELDS = ("case_id", "kind", "subject", "country", "source", "source_type", "obtained_at", "method", "reliability",
          "vpn_possible", "value", "note", "evidence_ref", "evidence_hash", "added_at")
SCHEMA = """CREATE TABLE IF NOT EXISTS claims(
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, kind TEXT, subject TEXT, country TEXT, source TEXT, source_type TEXT,
  obtained_at TEXT, method TEXT, reliability TEXT, vpn_possible INTEGER, value TEXT, note TEXT, evidence_ref TEXT, evidence_hash TEXT,
  added_at TEXT, prev_hash TEXT, entry_hash TEXT);
CREATE INDEX IF NOT EXISTS claims_case ON claims(case_id);"""


def cname(code):
    return "%s (%s)" % (CN[code], code) if code in CN else (code or "-")


def connect(path):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    db = sqlite3.connect(path, timeout=15)
    db.executescript(SCHEMA)
    if "value" not in {r[1] for r in db.execute("PRAGMA table_info(claims)")}:
        db.execute("ALTER TABLE claims ADD COLUMN value TEXT")  # older ledgers: keeps their hashes valid
        db.commit()
    db.row_factory = sqlite3.Row
    return db


def entry_hash(prev, row):
    canon = json.dumps({k: row[k] for k in FIELDS if k != "value" or row.get("value") is not None}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((prev + "|" + canon).encode("utf-8")).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------- writing ----------------
def add(path, case_id, kind, subject, source, source_type, obtained_at, method, country=None, reliability=None,
        vpn_possible=False, note="", evidence_ref=None, base_dir=None, value=None):
    case_id, subject, source, method = (str(x or "").strip() for x in (case_id, subject, source, method))
    if not case_id or not subject or not source or not method:
        raise ValueError("الحقول المطلوبة: القضية، الموضوع، المصدر، طريقة الحصول.")
    if kind not in KINDS:
        raise ValueError("نوع دليل غير معروف.")
    if source_type not in SOURCE_TYPES:
        raise ValueError("نوع مصدر غير معروف.")
    try:
        when = date.fromisoformat(str(obtained_at))
    except ValueError:
        raise ValueError("تاريخ الحصول يجب أن يكون بالصيغة YYYY-MM-DD.")
    if when > date.today():
        raise ValueError("تاريخ الحصول في المستقبل.")
    country = (country or "").strip().upper() or None
    if kind in COUNTRY_KINDS:
        if not country or not re.fullmatch(r"[A-Z]{2}", country):
            raise ValueError("الدولة مطلوبة برمز من حرفين (مثل AE).")
    else:
        country = None
    value = (str(value).strip() if value else "") or None
    if kind == "platform_channel":
        if not value or not (re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) or re.fullmatch(r"https?://\S+", value)):
            raise ValueError("قناة الطلبات يجب أن تكون بريدًا إلكترونيًا للجهة أو رابطًا رسميًا (http/https).")
    elif kind != "platform_registration":
        value = None  # only platform_registration (legal entity name) and platform_channel carry a value
    if value:
        value = value[:300]
    cap = SOURCE_TYPES[source_type][0]
    level = reliability if reliability in LEVELS else cap
    if LEVELS[level] > LEVELS[cap]:
        level = cap  # a claim can never be more reliable than its source type allows
    ev_hash = None
    if evidence_ref:
        p = os.path.abspath(os.path.join(base_dir or ".", evidence_ref))
        root = os.path.abspath(base_dir or ".")
        if not (p == root or p.startswith(root + os.sep)):
            raise ValueError("ملف الدليل خارج مجلد الأدوات.")
        if not os.path.isfile(p):
            raise ValueError("ملف الدليل غير موجود.")
        ev_hash = sha256_file(p)
    row = {"case_id": case_id, "kind": kind, "subject": subject[:200], "country": country, "source": source[:200],
           "source_type": source_type, "obtained_at": when.isoformat(), "method": method[:200], "reliability": level,
           "vpn_possible": 1 if vpn_possible else 0, "value": value, "note": str(note or "")[:1000], "evidence_ref": evidence_ref,
           "evidence_hash": ev_hash, "added_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        last = db.execute("SELECT entry_hash FROM claims ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last else "0" * 64
        eh = entry_hash(prev, row)
        cur = db.execute("INSERT INTO claims(%s, prev_hash, entry_hash) VALUES(%s)" % (
            ",".join(FIELDS), ",".join("?" * (len(FIELDS) + 2))), [row[k] for k in FIELDS] + [prev, eh])
        db.commit()
        return cur.lastrowid
    finally:
        db.close()


def record_case(path, case_id, g, labels=None):
    """Automatic claims from a trace: which known platforms the funds reached (low reliability, automated)."""
    n = 0
    db = connect(path)
    have = {(r["subject"], r["note"]) for r in db.execute("SELECT subject, note FROM claims WHERE case_id=? AND kind='platform_contact'", (case_id,))}
    db.close()
    for a, node in g.get("nodes", {}).items():
        if not node.get("label") or node.get("category") == "coinjoin" or a == g.get("start"):
            continue
        how = "عنوان إيداع مستنتج بالنمط (%s)" % node["inferred"] if node.get("inferred") else "عنوان مصنّف في قاعدة التصنيفات"
        tt = " ملوّث %.4f (حد أقصى %.4f)." % (node["taint"], node.get("taint_max", 0)) if node.get("taint") else ""
        note = "وصلت أموال إلى العنوان %s: %s (المصدر: %s، الثقة: %s).%s" % (
            a, how, node.get("source") or "-", node.get("confidence") or "-", tt)
        if (node["label"], note) in have:
            continue
        add(path, case_id, "platform_contact", node["label"], "تتبّع تلقائي للبلوكشين", "automated_tool",
            date.today().isoformat(), "تتبّع مسار الأموال وتصنيف العناوين", note=note)
        n += 1
    return n


# ---------------- reading ----------------
def claims(path, case_id=None):
    if not os.path.exists(path):
        return []
    db = connect(path)
    q = "SELECT * FROM claims" + (" WHERE case_id=?" if case_id else "") + " ORDER BY id"
    rows = [dict(r) for r in db.execute(q, (case_id,) if case_id else ())]
    db.close()
    return rows


def cases(path):
    if not os.path.exists(path):
        return []
    db = connect(path)
    rows = [dict(r) for r in db.execute("SELECT case_id, COUNT(*) AS claims, MAX(added_at) AS last FROM claims GROUP BY case_id ORDER BY last DESC")]
    db.close()
    return rows


def verify(path):
    """Problems found in the hash chain (empty list = intact). Store head() elsewhere to also catch a deleted tail."""
    problems, prev = [], "0" * 64
    for r in claims(path):
        if r["prev_hash"] != prev:
            problems.append("الادعاء %d: السلسلة مقطوعة (حُذف أو أُعيد ترتيب ادعاء قبله)" % r["id"])
        if entry_hash(r["prev_hash"], r) != r["entry_hash"]:
            problems.append("الادعاء %d: محتواه عُدِّل بعد تسجيله" % r["id"])
        prev = r["entry_hash"]
    return problems


def head(path):
    rows = claims(path)
    return rows[-1]["entry_hash"] if rows else "0" * 64


# ---------------- assessment ----------------
def stale(c):
    try:
        return (date.today() - date.fromisoformat(c["obtained_at"])).days > STALE_DAYS
    except ValueError:
        return False


def strength(kind, cs):
    """Explicit rules. Returns (strength, why)."""
    high = [c for c in cs if c["reliability"] == "high"]
    med = [c for c in cs if c["reliability"] == "medium"]
    if kind == "residence_evidence":
        if any(c["source_type"] == "official_record" for c in cs):
            return "strong", "مدعومة بسجل رسمي"
        if any(c["source_type"] == "provider_record" for c in cs):
            return "moderate", "مدعومة بسجل مزوّد سُلِّم بطريقة نظامية، وتحتاج تأكيدًا رسميًا"
        return "weak", "إشارات ضعيفة فقط ولا تُعد دليل إقامة"
    if kind == "network_contact":
        if high and not any(c["vpn_possible"] for c in high) and not any(stale(c) for c in high):
            return "strong", "سجل رسمي حديث دون مؤشر على VPN"
        if high or med:
            why = []
            if any(c["vpn_possible"] for c in cs):
                why.append("احتمال VPN أو وسيط")
            if any(stale(c) for c in cs):
                why.append("الدليل قديم (عناوين الشبكة تتغير)")
            return "moderate", "لا يتجاوز متوسطًا: " + ("، ".join(why) or "مصدر غير رسمي")
        return "weak", "مصادر ضعيفة فقط"
    if kind == "hosting":
        return ("moderate", "الاستضافة مؤجَّرة من أي بلد ولا تدل على صاحب الموقع") if (high or med) else ("weak", "مصادر ضعيفة فقط")
    if high:
        return "strong", "إفصاح أو سجل رسمي"
    return ("moderate", "مصدر متوسط") if med else ("weak", "مصادر ضعيفة فقط")


def assess(cs):
    roles = {}
    for kind in ("residence_evidence", "platform_registration", "network_contact", "hosting"):
        groups = defaultdict(list)
        for c in cs:
            if c["kind"] == kind and c["country"]:
                groups[(c["subject"] if kind in ("platform_registration", "hosting") else None, c["country"])].append(c)
        entries = []
        for (subj, country), items in groups.items():
            st, why = strength(kind, items)
            entries.append({"subject": subj, "country": country, "strength": st, "why": why,
                            "claims": [c["id"] for c in items], "sources": sorted({c["source"] for c in items})})
        entries.sort(key=lambda e: (-STRENGTH_ORDER[e["strength"]], e["subject"] or "", e["country"]))
        roles[kind] = entries
    res = roles["residence_evidence"]
    top = [e for e in res if e["strength"] in ("strong", "moderate")]
    if not top:
        status, countries = "undetermined", []
    else:
        best = [e for e in top if e["strength"] == top[0]["strength"]]
        status = "supported" if len({e["country"] for e in best}) == 1 else "conflict"
        countries = sorted({e["country"] for e in best})
    notes = []
    if status == "undetermined":
        notes.append("إقامة غير محسومة: لا يُستنتج بلد الشخص من دولة تسجيل المنصة أو نقطة الاتصال أو الاستضافة، فهي أدلة على أشياء أخرى.")
    if status == "conflict":
        notes.append("أدلة الإقامة متعارضة بين %s: لا يُحسم الأمر دون مراجعة المصادر." % "، ".join(cname(c) for c in countries))
    if status == "supported":
        for kind, label in (("platform_registration", "تسجيل المنصة"), ("network_contact", "نقطة الاتصال")):
            other = {e["country"] for e in roles[kind] if e["strength"] in ("strong", "moderate")} - set(countries)
            if other:
                notes.append("اختلاف %s (%s) عن دولة الإقامة المدعومة أمر وارد: المنصة تخدم عملاء من بلدان أخرى، والشبكة قد تكون VPN أو سفرًا." % (
                    label, "، ".join(cname(c) for c in sorted(other))))
    for e in roles["network_contact"]:
        if e["strength"] == "weak":
            notes.append("دليل نقطة اتصال ضعيف (%s): لا يُعتمد عليه." % cname(e["country"]))
    for subj in {e["subject"] for e in roles["platform_registration"]}:
        ctr = {e["country"] for e in roles["platform_registration"] if e["subject"] == subj and e["strength"] != "weak"}
        if len(ctr) > 1:
            notes.append("تعارض في دولة تسجيل «%s»: %s." % (subj, "، ".join(cname(c) for c in sorted(ctr))))
    return {"roles": roles, "residence": {"status": status, "countries": countries}, "notes": notes}


def stale365(c):
    try:
        return (date.today() - date.fromisoformat(c["obtained_at"])).days > 365
    except ValueError:
        return False


def platforms(path):
    """Platform registry built from claims of ALL cases: legal entity, registration country (with strength)
    and legal-request channels, each with its source and date. Names are matched ignoring case and spaces."""
    by = defaultdict(list)
    for c in claims(path):
        if c["kind"] in ("platform_registration", "platform_channel"):
            by[c["subject"].strip().casefold()].append(c)
    out = []
    for items in by.values():
        groups = defaultdict(list)
        for c in items:
            if c["kind"] == "platform_registration":
                groups[c["country"]].append(c)
        reg = []
        for country, g in groups.items():
            st, why = strength("platform_registration", g)
            reg.append({"country": country, "strength": st, "why": why, "claims": [c["id"] for c in g],
                        "entities": sorted({c["value"] for c in g if c.get("value")}),
                        "sources": sorted({c["source"] for c in g}), "latest": max(c["obtained_at"] for c in g),
                        "stale": all(stale365(c) for c in g)})
        reg.sort(key=lambda e: -STRENGTH_ORDER[e["strength"]])
        ch = [{"id": c["id"], "value": c["value"], "source": c["source"], "obtained_at": c["obtained_at"],
               "reliability": c["reliability"], "stale": stale365(c)} for c in items if c["kind"] == "platform_channel"]
        out.append({"platform": items[0]["subject"], "registration": reg, "channels": ch})
    return sorted(out, key=lambda p: p["platform"].casefold())


STATUS_AR = {"supported": "مدعومة بالأدلة", "conflict": "متعارضة", "undetermined": "غير محسومة"}
ROLE_AR = {"residence_evidence": "دولة الإقامة (ما تدعمه الأدلة)", "platform_registration": "دولة تسجيل المنصة",
           "network_contact": "دولة نقطة اتصال الشبكة (إن عُرفت)", "hosting": "دولة استضافة الموقع"}
STRENGTH_AR = {"strong": "قوي", "moderate": "متوسط", "weak": "ضعيف"}


def report_text(path, case_id):
    cs = claims(path, case_id)
    a = assess(cs)
    chain = verify(path)
    L = ["# دفتر الأدلة وتقييم الدول: القضية %s" % case_id, "",
         "تاريخ التقرير: %s | عدد الادعاءات: %d | سلامة الدفتر: %s | بصمة الرأس: %s" % (
             datetime.now(timezone.utc).strftime("%Y-%m-%d"), len(cs), "سليمة" if not chain else "تالفة: راجع verify", head(path)[:16]),
         "", "> هذه ادعاءات موثّقة بمصادرها وتواريخها وليست حكمًا على أحد. الأنواع الأربعة للدولة تجيب عن أسئلة مختلفة ولا يُعامل أحدها كأنه الآخر. "
             "القرار للشرطة والقضاء، ولا يُتخذ إجراء ضد شخص بناءً على هذا التقرير."]
    if chain:
        L += ["", "**تحذير: سلسلة الدفتر تالفة**"] + ["- " + p for p in chain]
    L += ["", "## تقييم الدول (أدوار منفصلة)"]
    res = a["residence"]
    L += ["", "### %s: %s%s" % (ROLE_AR["residence_evidence"], STATUS_AR[res["status"]],
                              " (%s)" % "، ".join(cname(c) for c in res["countries"]) if res["countries"] else "")]
    for kind in ("residence_evidence", "platform_registration", "network_contact", "hosting"):
        if kind != "residence_evidence":
            L += ["", "### " + ROLE_AR[kind]]
        ents = a["roles"][kind]
        if not ents:
            L.append("- لا أدلة مسجّلة.")
        for e in ents:
            L.append("- %s%s: **%s** (%s). المصادر: %s. الادعاءات: %s" % (
                "«%s» " % e["subject"] if e["subject"] else "", cname(e["country"]), STRENGTH_AR[e["strength"]], e["why"],
                "، ".join(e["sources"]), ", ".join("#%d" % i for i in e["claims"])))
    if a["notes"]:
        L += ["", "## ملاحظات"] + ["- " + n for n in a["notes"]]
    contacts = [c for c in cs if c["kind"] == "platform_contact"]
    if contacts:
        L += ["", "## منصات وصلت إليها الأموال (من التتبع الآلي: موثوقية منخفضة)"]
        L += ["- #%d %s: %s" % (c["id"], c["subject"], c["note"]) for c in contacts]
    L += ["", "## كل الادعاءات", "| # | النوع | الموضوع | الدولة | المصدر (نوعه) | تاريخ الحصول | الطريقة | الموثوقية | ملاحظة |", "|---|---|---|---|---|---|---|---|---|"]
    for c in cs:
        L.append("| %d | %s | %s | %s | %s (%s) | %s%s | %s | %s | %s%s |" % (
            c["id"], KINDS[c["kind"]], c["subject"], cname(c["country"]) if c["country"] else "-", c["source"],
            SOURCE_TYPES[c["source_type"]][1], c["obtained_at"], " ⚠ قديم" if stale(c) else "", c["method"],
            {"high": "عالية", "medium": "متوسطة", "low": "منخفضة"}[c["reliability"]],
            ((c.get("value") + " | " if c.get("value") else "") + (c["note"] or "")).replace("|", "/").replace("\n", " ")[:160], " [VPN محتمل]" if c["vpn_possible"] else ""))
    L += ["", "## قبل الاستعمال", "- قدّم الأصل الرسمي لكل دليل للجهة المختصة، لا هذا الجدول وحده.",
          "- خزّن بصمة الرأس أعلاه خارج هذا الحاسوب لتثبت لاحقًا أن الدفتر لم يُغيَّر.",
          "- لا تُدخل أسماء أشخاص أو عناوين سكن في الدفتر. الهوية تُسلَّم للشرطة من المنصة."]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="ledger.db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add")
    p.add_argument("--case", required=True)
    p.add_argument("--kind", required=True, choices=sorted(KINDS))
    p.add_argument("--subject", required=True)
    p.add_argument("--country")
    p.add_argument("--source", required=True)
    p.add_argument("--source-type", required=True, choices=sorted(SOURCE_TYPES))
    p.add_argument("--date", required=True, help="date the evidence was obtained, YYYY-MM-DD")
    p.add_argument("--method", required=True)
    p.add_argument("--reliability", choices=sorted(LEVELS))
    p.add_argument("--vpn-possible", action="store_true")
    p.add_argument("--note", default="")
    p.add_argument("--value", help="legal entity name (platform_registration) or request channel: email/URL (platform_channel)")
    p.add_argument("--evidence-file", help="file inside this folder: its SHA-256 is stored")
    p = sub.add_parser("show")
    p.add_argument("--case", required=True)
    p = sub.add_parser("report")
    p.add_argument("--case", required=True)
    p.add_argument("--out")
    sub.add_parser("verify")
    sub.add_parser("cases")
    sub.add_parser("platforms")
    a = ap.parse_args()
    try:
        if a.cmd == "add":
            cid = add(a.db, a.case, a.kind, a.subject, a.source, a.source_type, a.date, a.method, a.country,
                      a.reliability, a.vpn_possible, a.note, a.evidence_file, base_dir=".", value=a.value)
            print("claim #%d added" % cid)
        elif a.cmd == "show":
            print(json.dumps(assess(claims(a.db, a.case)), ensure_ascii=False, indent=1))
        elif a.cmd == "report":
            t = report_text(a.db, a.case)
            if a.out:
                open(a.out, "w", encoding="utf-8").write(t)
            print(t)
        elif a.cmd == "verify":
            pr = verify(a.db)
            print("Ledger intact. Head hash: " + head(a.db) if not pr else "PROBLEMS:\n" + "\n".join(pr))
            sys.exit(1 if pr else 0)
        elif a.cmd == "platforms":
            print(json.dumps(platforms(a.db), ensure_ascii=False, indent=1))
        elif a.cmd == "cases":
            for c in cases(a.db):
                print("%s: %d claims (last %s)" % (c["case_id"], c["claims"], c["last"]))
    except ValueError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
