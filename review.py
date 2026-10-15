#!/usr/bin/env python3
"""
review.py - turn guesses about addresses into reviewed, dated, attributable labels. Python 3.8+.

    python review.py enqueue graph.json --case ID          put the addresses worth naming into the review queue
    python review.py list [--limit 20]                     the queue, most valuable first
    python review.py decide ADDRESS --action confirm --reviewer "Name" --label "Platform X" --category exchange \
                            --confidence high --evidence "https://official-page/proof-of-reserves"
    python review.py decide ADDRESS --action reject --reviewer "Name" --note "personal wallet, not a platform"
    python review.py import-official list.txt --platform "Platform X" --category exchange \
                            --source-url https://platform.example/addresses --date 2026-09-30 --reviewer "Name"
    python review.py export --out labels_bundle.json       reviewed labels, with a SHA-256 you can verify elsewhere
    python review.py import-bundle labels_bundle.json --reviewer "Name"
    python review.py verify-bundle labels_bundle.json | history [--address A] | stats

Why: the value of every report depends on labels. Guessed labels (a deposit pattern, a third-party provider, a site
scan) are low confidence on purpose. A review is how a human turns a guess into evidence, with a name and a date.

Rules that cannot be skipped:
  - a reviewer name is required; every decision is stored in a hash-chained history (editing it is detectable);
  - HIGH confidence needs written evidence (an official link or a description of the source);
  - a RISK label (scam, theft, mixer...) always needs evidence and is capped at MEDIUM here, because calling an address
    a scam can hurt someone who is not;
  - a rejected label stays rejected: every tool ignores it, and automatic inference will not re-apply it;
  - imported bundles are capped at MEDIUM until someone here confirms them.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
from datetime import date, datetime, timezone

import labels_tool
import taxonomy

REASONS_AR = {"high_activity": "نشاط مرتفع جدًا (غالبًا خدمة غير مسمّاة)", "collection_point": "نقطة تجميع: استلمت من عدة عناوين متتبَّعة",
              "inferred": "تسمية مستنتجة تحتاج تأكيدًا", "low_confidence_label": "تسمية آلية منخفضة الثقة"}
WEIGHT = {"high_activity": 2.0, "collection_point": 2.0, "inferred": 1.0, "low_confidence_label": 1.0}
AUTOMATED = ("site-scan", "satoshidata", "deposit pattern", "cluster inference", "inferred", "auto")
SCHEMA = """CREATE TABLE IF NOT EXISTS queue(address TEXT PRIMARY KEY, chain TEXT, reasons TEXT, inflow REAL, cases TEXT,
  status TEXT, proposed_label TEXT, proposed_category TEXT, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT, action TEXT, label TEXT, category TEXT,
  confidence TEXT, evidence TEXT, reviewer TEXT, note TEXT, at TEXT, prev_hash TEXT, entry_hash TEXT);"""
DEC_FIELDS = ("address", "action", "label", "category", "confidence", "evidence", "reviewer", "note", "at")


def today():
    return date.today().isoformat()


def connect(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    db = sqlite3.connect(path, timeout=15)
    db.executescript(SCHEMA)
    db.row_factory = sqlite3.Row
    return db


def explorer(chain, addr):
    import chains
    return (chains.CHAINS[chain]["addr_url"] if chain in chains.CHAINS else chains.CHAINS["btc"]["addr_url"]) % addr


def rejected(entry):
    return isinstance(entry, dict) and (entry.get("review") or {}).get("status") == "rejected"


def confirmed(entry):
    return isinstance(entry, dict) and (entry.get("review") or {}).get("status") == "confirmed"


# ---------------- queue ----------------
def enqueue(path, graph, case_id="", labels=None):
    labels = labels or {}
    chain, nodes, inflow = graph.get("chain", "btc"), graph["nodes"], {}
    for e in graph["edges"]:
        inflow[e["to"]] = inflow.get(e["to"], 0) + (e.get("amount", e.get("btc", 0)) or 0)
    found = {}
    for a, n in nodes.items():
        if a == graph.get("start") or a.startswith("coinjoin:"):
            continue
        entry = labels.get(a)
        if rejected(entry) or confirmed(entry):
            continue
        reasons, proposed = [], (None, None)
        note = n.get("note") or ""
        if not n.get("label") and not entry:
            if "high activity" in note:
                reasons.append("high_activity")
            if "collection point" in note:
                reasons.append("collection_point")
        if n.get("inferred"):
            reasons.append("inferred")
            proposed = (n.get("label"), n.get("category"))
        if isinstance(entry, dict) and (entry.get("confidence") in (None, "low") or any(k in (entry.get("source") or "") for k in AUTOMATED)):
            reasons.append("low_confidence_label")
            proposed = (entry.get("label"), entry.get("category"))
        if reasons:
            found[a] = (reasons, proposed)
    db, added, updated = connect(path), 0, 0
    try:
        for a, (reasons, proposed) in found.items():
            row = db.execute("SELECT * FROM queue WHERE address=?", (a,)).fetchone()
            if row is None:
                db.execute("INSERT INTO queue VALUES(?,?,?,?,?,?,?,?,?,?)", (a, chain, "|".join(sorted(set(reasons))), inflow.get(a, 0),
                           case_id, "pending", proposed[0], proposed[1], today(), today()))
                added += 1
            else:
                merged = "|".join(sorted(set(row["reasons"].split("|")) | set(reasons)))
                cases = ",".join(sorted(set(filter(None, (row["cases"] or "").split(","))) | ({case_id} if case_id else set())))
                status = "pending" if row["status"] == "skipped" else row["status"]
                db.execute("UPDATE queue SET reasons=?, inflow=?, cases=?, status=?, proposed_label=COALESCE(?, proposed_label), "
                           "proposed_category=COALESCE(?, proposed_category), last_seen=? WHERE address=?",
                           (merged, max(row["inflow"] or 0, inflow.get(a, 0)), cases, status, proposed[0], proposed[1], today(), a))
                updated += 1
        db.commit()
    finally:
        db.close()
    return added, updated


def priority(row):
    reasons = row["reasons"].split("|") if row["reasons"] else []
    return round(math.log1p(row["inflow"] or 0) + 2 * len([c for c in (row["cases"] or "").split(",") if c]) + sum(WEIGHT.get(r, 0) for r in reasons), 3)


def queue(path, status="pending", limit=20):
    if not os.path.exists(path):
        return []
    db = connect(path)
    rows = db.execute("SELECT * FROM queue" + ("" if status == "all" else " WHERE status=?"), () if status == "all" else (status,)).fetchall()
    db.close()
    items = [{"address": r["address"], "chain": r["chain"], "reasons": r["reasons"].split("|"), "reasons_ar": [REASONS_AR.get(x, x) for x in r["reasons"].split("|")],
              "inflow": r["inflow"], "cases": [c for c in (r["cases"] or "").split(",") if c], "status": r["status"], "priority": priority(r),
              "proposed_label": r["proposed_label"], "proposed_category": r["proposed_category"], "url": explorer(r["chain"], r["address"])} for r in rows]
    items.sort(key=lambda i: -i["priority"])
    return items[:limit]


def stats(path):
    out = {"pending": 0, "confirmed": 0, "rejected": 0, "skipped": 0, "decisions": 0}
    if os.path.exists(path):
        db = connect(path)
        for r in db.execute("SELECT status, COUNT(*) AS n FROM queue GROUP BY status"):
            out[r["status"]] = r["n"]
        out["decisions"] = db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        db.close()
    return out


# ---------------- decisions (hash-chained) ----------------
def _hash(prev, row):
    return hashlib.sha256((prev + "|" + json.dumps({k: row[k] for k in DEC_FIELDS}, sort_keys=True, ensure_ascii=False)).encode("utf-8")).hexdigest()


def _record(db, row):
    last = db.execute("SELECT entry_hash FROM decisions ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["entry_hash"] if last else "0" * 64
    db.execute("INSERT INTO decisions(%s, prev_hash, entry_hash) VALUES(%s)" % (",".join(DEC_FIELDS), ",".join("?" * (len(DEC_FIELDS) + 2))),
               [row[k] for k in DEC_FIELDS] + [prev, _hash(prev, row)])


def history(path, address=None):
    if not os.path.exists(path):
        return []
    db = connect(path)
    rows = [dict(r) for r in db.execute("SELECT * FROM decisions" + (" WHERE address=?" if address else "") + " ORDER BY id", (address,) if address else ())]
    db.close()
    return rows


def verify_history(path):
    problems, prev = [], "0" * 64
    for r in history(path):
        if r["prev_hash"] != prev:
            problems.append("القرار %d: السلسلة مقطوعة" % r["id"])
        if _hash(r["prev_hash"], r) != r["entry_hash"]:
            problems.append("القرار %d: عُدِّل بعد تسجيله" % r["id"])
        prev = r["entry_hash"]
    return problems


def decide(db_path, labels_path, address, action, reviewer, label=None, category=None, confidence=None, evidence="", note=""):
    addr = labels_tool.norm(address)
    reviewer = (reviewer or "").strip()
    if not addr:
        raise ValueError("عنوان غير صالح.")
    if len(reviewer) < 2:
        raise ValueError("اسم المراجع مطلوب: كل قرار يُسجَّل باسم صاحبه.")
    if action not in ("confirm", "reject", "skip"):
        raise ValueError("إجراء غير معروف.")
    evidence, note = (evidence or "").strip()[:400], (note or "").strip()[:400]
    labels = labels_tool.load(labels_path)
    cat = taxonomy.canon(category)
    if action == "confirm":
        if not (label or "").strip():
            raise ValueError("اكتب اسم الجهة.")
        if cat not in taxonomy.ALL:
            raise ValueError("فئة غير صالحة.")
        if confidence not in ("medium", "high"):
            raise ValueError("المراجعة تمنح ثقة متوسطة أو عالية فقط.")
        if confidence == "high" and len(evidence) < 8:
            raise ValueError("الثقة العالية تتطلب دليلًا مكتوبًا: رابط رسمي أو وصفًا واضحًا للمصدر.")
        if taxonomy.is_risk(cat):
            if len(evidence) < 8:
                raise ValueError("وسم عنوان بفئة خطر (%s) يتطلب دليلًا مكتوبًا: التصنيف الخاطئ قد يضر بريئًا." % taxonomy.ar(cat))
            confidence = "medium"  # reviews never make a risk label 'high'
        entry = labels.get(addr)
        if isinstance(entry, str):
            entry = {"label": entry, "category": "other", "source": "legacy", "confidence": "medium", "sources": ["legacy"]}
        src = "review: %s%s" % (reviewer, " | " + evidence[:120] if evidence else "")
        if isinstance(entry, dict) and entry.get("label") and entry["label"].strip().casefold() != label.strip().casefold():
            entry.setdefault("alt", []).append({"label": entry["label"], "source": entry.get("source")})
        entry = entry if isinstance(entry, dict) else {"added": today()}
        entry.update(label=label.strip(), category=cat, source=src, confidence=confidence, updated=today(),
                     review={"status": "confirmed", "by": reviewer, "at": today(), "evidence": evidence})
        entry.setdefault("added", today())
        entry["sources"] = sorted(set(entry.get("sources", [])) | {src})
        labels[addr] = entry
        labels_tool.save(labels, labels_path)
        qstatus = "confirmed"
    elif action == "reject":
        entry = labels.get(addr)
        if isinstance(entry, dict):
            entry["review"] = {"status": "rejected", "by": reviewer, "at": today(), "note": note}
            entry["updated"] = today()
            labels_tool.save(labels, labels_path)
        else:
            labels[addr] = {"label": "(مرفوض)", "category": "other", "source": "review: %s" % reviewer, "confidence": "low", "added": today(),
                            "review": {"status": "rejected", "by": reviewer, "at": today(), "note": note}}
            labels_tool.save(labels, labels_path)
        qstatus = "rejected"
    else:
        qstatus = "skipped"
    db = connect(db_path)
    try:
        db.execute("BEGIN IMMEDIATE")
        row = {"address": addr, "action": action, "label": (label or "").strip() or None, "category": cat, "confidence": confidence,
               "evidence": evidence, "reviewer": reviewer, "note": note, "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        _record(db, row)
        if db.execute("SELECT 1 FROM queue WHERE address=?", (addr,)).fetchone():
            db.execute("UPDATE queue SET status=?, last_seen=? WHERE address=?", (qstatus, today(), addr))
        else:
            db.execute("INSERT INTO queue VALUES(?,?,?,?,?,?,?,?,?,?)", (addr, "btc", "", 0, "", qstatus, row["label"], cat, today(), today()))
        db.commit()
        remaining = db.execute("SELECT COUNT(*) FROM queue WHERE status='pending'").fetchone()[0]
    finally:
        db.close()
    return {"status": qstatus, "address": addr, "remaining": remaining}


# ---------------- official lists and bundles ----------------
def import_official(db_path, labels_path, file_path, platform, category, source_url, when, reviewer, confidence="high", text=None):
    cat = taxonomy.canon(category)
    if not taxonomy.is_platform(cat):
        raise ValueError("القوائم الرسمية تُستورد بفئة منصة أو خدمة (بورصة، حفظ، جسر...).")
    if not re.fullmatch(r"https://\S+", source_url or ""):
        raise ValueError("رابط المصدر الرسمي (https) مطلوب: لا استيراد بلا مصدر.")
    try:
        d = date.fromisoformat(when)
    except (TypeError, ValueError):
        raise ValueError("تاريخ نشر القائمة مطلوب بالصيغة YYYY-MM-DD.")
    if d > date.today():
        raise ValueError("تاريخ القائمة في المستقبل.")
    if len((reviewer or "").strip()) < 2 or not (platform or "").strip():
        raise ValueError("اسم المراجع واسم المنصة مطلوبان.")
    if text is None:
        text = open(file_path, encoding="utf-8", errors="ignore").read()
    addrs = []
    for tok in re.split(r"[\s,;\"']+", text):
        n = labels_tool.norm(tok)
        if n and n not in addrs:
            addrs.append(n)
    if not addrs:
        raise ValueError("لم أجد أي عنوان صالح في القائمة.")
    labels = labels_tool.load(labels_path)
    added = updated = 0
    src = "official page: %s (%s)" % (source_url, d.isoformat())
    for a in addrs:
        entry = labels.get(a)
        if isinstance(entry, str):
            entry = {"label": entry, "category": "other", "source": "legacy", "confidence": "medium", "sources": ["legacy"]}
        if isinstance(entry, dict):
            if entry.get("label", "").strip().casefold() != platform.strip().casefold():
                entry.setdefault("alt", []).append({"label": entry.get("label"), "source": entry.get("source")})
            updated += 1
        else:
            entry, added = {"added": today()}, added + 1
        entry.update(label=platform.strip(), category=cat, source=src, confidence=confidence, updated=today(),
                     review={"status": "confirmed", "by": reviewer.strip(), "at": today(), "evidence": source_url})
        entry.setdefault("added", today())
        entry["sources"] = sorted(set(entry.get("sources", [])) | {src})
        labels[a] = entry
    labels_tool.save(labels, labels_path)
    db = connect(db_path)
    try:
        db.execute("BEGIN IMMEDIATE")
        _record(db, {"address": "(batch of %d)" % len(addrs), "action": "import-official", "label": platform.strip(), "category": cat, "confidence": confidence,
                     "evidence": source_url, "reviewer": reviewer.strip(), "note": "published %s" % d.isoformat(), "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        db.commit()
    finally:
        db.close()
    return {"addresses": len(addrs), "added": added, "updated": updated}


def bundle_hash(labels):
    return hashlib.sha256(json.dumps(labels, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def export_bundle(labels_path, only_reviewed=True):
    labels = labels_tool.load(labels_path)
    keep = {}
    for a, e in labels.items():
        if not isinstance(e, dict) or rejected(e):
            continue
        if only_reviewed and not (confirmed(e) or "OFAC" in (e.get("source") or "") or (e.get("source") or "").startswith("official page")):
            continue
        keep[a] = e
    return {"format": "labels-bundle-1", "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "count": len(keep),
            "sha256": bundle_hash(keep), "labels": keep}


def verify_bundle(bundle):
    if bundle.get("format") != "labels-bundle-1" or not isinstance(bundle.get("labels"), dict):
        return False, "صيغة الحزمة غير معروفة."
    if bundle_hash(bundle["labels"]) != bundle.get("sha256"):
        return False, "البصمة لا تطابق المحتوى: الحزمة عُدِّلت أو تالفة."
    return True, "الحزمة سليمة (%d تسمية)." % len(bundle["labels"])


def import_bundle(db_path, labels_path, bundle, name, reviewer):
    ok, msg = verify_bundle(bundle)
    if not ok:
        raise ValueError(msg)
    if len((reviewer or "").strip()) < 2:
        raise ValueError("اسم المراجع مطلوب.")
    labels = labels_tool.load(labels_path)
    added = updated = skipped = 0
    src = "bundle:%s:%s" % (name, (bundle.get("exported_at") or "")[:10])
    for a, e in bundle["labels"].items():
        addr = labels_tool.norm(a)
        if not addr or not isinstance(e, dict) or not e.get("label"):
            skipped += 1
            continue
        mine = labels.get(addr)
        if confirmed(mine) or rejected(mine):
            skipped += 1  # a local human decision always wins over an imported one
            continue
        conf = e.get("confidence") if e.get("confidence") in ("low", "medium") else "medium"  # imports never exceed medium
        new = {"label": e["label"], "category": taxonomy.canon(e.get("category")) or "other", "source": src, "confidence": conf,
               "added": today(), "updated": today(), "sources": [src], "review": {"status": "imported", "from": name, "at": today(), "by": reviewer.strip()}}
        if isinstance(mine, dict) and mine.get("label") and mine["label"].strip().casefold() != e["label"].strip().casefold():
            new["alt"] = [{"label": mine["label"], "source": mine.get("source")}] + mine.get("alt", [])
            new["added"] = mine.get("added", today())
        labels[addr] = new
        updated += 1 if mine else 0
        added += 0 if mine else 1
    labels_tool.save(labels, labels_path)
    db = connect(db_path)
    try:
        db.execute("BEGIN IMMEDIATE")
        _record(db, {"address": "(bundle of %d)" % len(bundle["labels"]), "action": "import-bundle", "label": name, "category": None, "confidence": "medium",
                     "evidence": bundle.get("sha256", ""), "reviewer": reviewer.strip(), "note": "added %d, updated %d, skipped %d" % (added, updated, skipped),
                     "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        db.commit()
    finally:
        db.close()
    return {"added": added, "updated": updated, "skipped": skipped, "message": msg}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="review.db")
    ap.add_argument("--labels", default="labels.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("enqueue")
    p.add_argument("graph")
    p.add_argument("--case", default="")
    p = sub.add_parser("list")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--status", default="pending")
    p = sub.add_parser("decide")
    p.add_argument("address")
    p.add_argument("--action", required=True, choices=["confirm", "reject", "skip"])
    p.add_argument("--reviewer", required=True)
    p.add_argument("--label")
    p.add_argument("--category")
    p.add_argument("--confidence", choices=["medium", "high"])
    p.add_argument("--evidence", default="")
    p.add_argument("--note", default="")
    p = sub.add_parser("import-official")
    p.add_argument("file")
    p.add_argument("--platform", required=True)
    p.add_argument("--category", required=True)
    p.add_argument("--source-url", required=True)
    p.add_argument("--date", required=True)
    p.add_argument("--reviewer", required=True)
    p = sub.add_parser("export")
    p.add_argument("--out", default="labels_bundle.json")
    p.add_argument("--all", action="store_true", help="include unreviewed labels too")
    p = sub.add_parser("import-bundle")
    p.add_argument("file")
    p.add_argument("--reviewer", required=True)
    p = sub.add_parser("verify-bundle")
    p.add_argument("file")
    p = sub.add_parser("history")
    p.add_argument("--address")
    sub.add_parser("stats")
    a = ap.parse_args()
    try:
        if a.cmd == "enqueue":
            g = json.load(open(a.graph, encoding="utf-8"))
            print("added %d, updated %d" % enqueue(a.db, g, a.case, labels_tool.load(a.labels)))
        elif a.cmd == "list":
            for i in queue(a.db, a.status, a.limit):
                print("%6.2f  %s  %s | %s | inflow %.4g | cases %s" % (i["priority"], i["address"], i["status"], "؛ ".join(i["reasons_ar"]), i["inflow"], ",".join(i["cases"]) or "-"))
                print("        " + i["url"])
        elif a.cmd == "decide":
            print(json.dumps(decide(a.db, a.labels, a.address, a.action, a.reviewer, a.label, a.category, a.confidence, a.evidence, a.note), ensure_ascii=False))
        elif a.cmd == "import-official":
            print(json.dumps(import_official(a.db, a.labels, a.file, a.platform, a.category, a.source_url, a.date, a.reviewer), ensure_ascii=False))
        elif a.cmd == "export":
            b = export_bundle(a.labels, not a.all)
            json.dump(b, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print("%d labels written to %s | sha256 %s (keep it somewhere else to prove the file was not changed)" % (b["count"], a.out, b["sha256"]))
        elif a.cmd == "import-bundle":
            print(json.dumps(import_bundle(a.db, a.labels, json.load(open(a.file, encoding="utf-8")), os.path.basename(a.file), a.reviewer), ensure_ascii=False))
        elif a.cmd == "verify-bundle":
            ok, msg = verify_bundle(json.load(open(a.file, encoding="utf-8")))
            print(msg)
            sys.exit(0 if ok else 1)
        elif a.cmd == "history":
            pr = verify_history(a.db)
            for h in history(a.db, a.address):
                print("#%d %s %s %s %s by %s %s" % (h["id"], h["at"], h["action"], h["address"], h["label"] or "", h["reviewer"], h["note"] or ""))
            print("history intact" if not pr else "PROBLEMS: " + "; ".join(pr))
        elif a.cmd == "stats":
            print(json.dumps(stats(a.db), ensure_ascii=False))
    except ValueError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
