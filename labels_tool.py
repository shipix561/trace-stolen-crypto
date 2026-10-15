#!/usr/bin/env python3
"""
labels_tool.py - build and maintain labels.json for btc_tracer.py (Python 3.8+).

Commands:
  import-csv FILE --source NAME     import any CSV with an address column
  import-ofac FILE                  import Bitcoin addresses from the US Treasury OFAC SDN list
                                    (SDN.XML, or SDN.CSV / any text file); covers BTC, ETH, TRON addresses
  add ADDRESS "Name" --category exchange --source manual --confidence high
  lookup ADDRESS
  stats
  sync                              refresh from every source in sources.json
  candidates GRAPH                  list unlabeled flagged addresses from a trace, for manual review
  export-csv                        dump the database to CSV

Each label keeps: label, category, source, confidence (low/medium/high), and
the list of all sources that mentioned the address. If two sources disagree,
the higher confidence wins and the other label is kept under "alt".
Categories used by the tracer as high-risk: sanctioned, scam, mixer,
darknet, ransomware, theft.
"""
import argparse
import csv
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import date
from collections import Counter

import taxonomy

DB = "labels.json"
CONF = {"low": 1, "medium": 2, "high": 3}
ADDR = re.compile(r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,87})$")
EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
TRON = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
OFAC_TXT = re.compile(
    r"Digital Currency Address - (?:XBT|ETH|TRX|USDT|USDC)\s+([A-Za-z0-9]{26,90})")
CATMAP = {"cex": "exchange", "exchanges": "exchange", "scams": "scam",
          "sanction": "sanctioned", "sanctions": "sanctioned", "hack": "theft"}


SOL = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")  # Solana (base58 public key)
LTC = re.compile(r"^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{11,87})$")
DOGE = re.compile(r"^[DA9][a-km-zA-HJ-NP-Z1-9]{25,34}$")
BCH = re.compile(r"^(?:bitcoincash:)?[qp][a-z0-9]{41}$")


def norm(addr):
    addr = (addr or "").strip()
    if BCH.match(addr.lower()):
        a = addr.lower()
        return a if a.startswith("bitcoincash:") else "bitcoincash:" + a
    if addr.lower().startswith("ltc1") and LTC.match(addr.lower()):
        return addr.lower()
    if LTC.match(addr) or DOGE.match(addr):
        return addr
    if EVM.match(addr):
        return addr.lower()  # Ethereum addresses are stored lowercase
    if TRON.match(addr):
        return addr  # TRON addresses are case-sensitive
    if addr.upper().startswith("BC1"):
        addr = addr.lower()
    if ADDR.match(addr):
        return addr
    return addr if SOL.match(addr) and not addr.startswith(("0x",)) else None


def load(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save(db, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=1, sort_keys=True)


def merge(db, addr, label, category, source, conf):
    addr = norm(addr)
    if not addr:
        return "invalid"
    today = date.today().isoformat()
    category = taxonomy.canon(category) or "other"
    new = {"label": label, "category": category, "source": source, "confidence": conf}
    old = db.get(addr)
    if old is None:
        new.update(sources=[source], added=today)
        db[addr] = new
        return "added"
    if isinstance(old, str):
        old = {"label": old, "category": "other", "source": "legacy", "confidence": "medium", "sources": ["legacy"]}
    old["sources"] = sorted(set(old.get("sources", [])) | {source})
    if CONF.get(conf, 0) > CONF.get(old.get("confidence"), 0):
        old.setdefault("alt", []).append({"label": old["label"], "source": old["source"]})
        old.update(new)
    elif label != old["label"]:
        old.setdefault("alt", []).append({"label": label, "source": source})
    old.setdefault("added", today)  # entries from before dates were recorded get today's date as 'first seen here'
    old["updated"] = today
    db[addr] = old
    return "updated"


def tally(results):
    c = Counter(results)
    print("added: %d | updated: %d | invalid/skipped: %d" % (c["added"], c["updated"], c["invalid"]))


def cmd_import_csv(a, db):
    res = []
    with open(a.file, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            chain = row.get(a.chain_col) if a.chain_col else None
            if chain and a.chain != "all" and chain.strip().lower() != a.chain:
                continue
            name = (row.get(a.name_col) or row.get("name") or row.get("entity") or a.default_name or "").strip()
            cat = (row.get(a.category_col) or a.category or "unknown").strip().lower()
            if not name:
                res.append("invalid")  # unnamed rows (e.g. unreviewed candidates) are skipped
                continue
            res.append(merge(db, row.get(a.address_col), name, CATMAP.get(cat, cat),
                             a.source, a.confidence))
    tally(res)
    return res


def ofac_entries(path):
    if path.lower().endswith(".xml"):
        for _, el in ET.iterparse(path):
            if el.tag.split("}")[-1] != "sdnEntry":
                continue
            name = " ".join((c.text or "").strip() for c in el
                            if c.tag.split("}")[-1] in ("firstName", "lastName"))
            for i in el.iter():
                if i.tag.split("}")[-1] == "id":
                    t = {c.tag.split("}")[-1]: (c.text or "") for c in i}
                    if t.get("idType", "").startswith("Digital Currency Address - "):
                        yield t.get("idNumber", ""), name.strip() or "OFAC SDN"
            el.clear()
    else:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for m in OFAC_TXT.finditer(f.read()):
                yield m.group(1), "OFAC SDN"


def cmd_import_ofac(a, db):
    tally([merge(db, ad, "OFAC: " + nm, "sanctioned", "OFAC SDN", "high")
           for ad, nm in ofac_entries(a.file)])


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CAND = re.compile(r"(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{40}|bc1[a-z0-9]{11,87}|ltc1[a-z0-9]{11,87}|[13LMDT][1-9A-HJ-NP-Za-km-z]{25,34})(?![A-Za-z0-9])")


def _b58_ok(a):
    import hashlib
    n = 0
    for c in a:
        n = n * 58 + B58.index(c)
    b = b"\0" * (len(a) - len(a.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return len(b) > 4 and hashlib.sha256(hashlib.sha256(b[:-4]).digest()).digest()[:4] == b[-4:]


def _bech_ok(a):
    ch = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if "1" not in a or any(c not in ch for c in a.rsplit("1", 1)[1]):
        return False
    hrp, d = a.rsplit("1", 1)
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + [ch.index(c) for c in d]:
        t = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if (t >> i) & 1:
                chk ^= gen[i]
    return chk in (1, 0x2bc830a3)


def valid_address(a):
    """True only if the address passes its own checksum (Base58Check / Bech32) or is a well-formed 0x address."""
    if EVM.match(a):
        return True
    if a.lower().startswith(("bc1", "ltc1")):
        return (a == a.lower() or a == a.upper()) and _bech_ok(a.lower())
    try:
        return _b58_ok(a)
    except ValueError:
        return False


def extract_addresses(text):
    """Every address in free text (a press release, an HTML page, XML, JSON) that passes its checksum. Order kept, duplicates removed."""
    seen, out = set(), []
    for m in CAND.finditer(text):
        a = m.group(0)
        if a not in seen and valid_address(a):
            seen.add(a)
            out.append(a)
    return out


def read_any(path):
    raw = open(path, "rb").read()
    if raw[:4] == b"%PDF":
        try:
            import subprocess
            return subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, timeout=60).stdout.decode("utf-8", "ignore")
        except Exception:
            raise ValueError("PDF: install pdftotext or paste the text into a .txt file")
    return raw.decode("utf-8", "ignore")


def cmd_import_text(a, db):
    """Pull the addresses out of any file (text, HTML, XML, JSON, PDF with pdftotext) and label them all the same."""
    addrs = extract_addresses(read_any(a.file))
    print("found %d addresses that pass their checksum" % len(addrs))
    name = a.name or a.source
    tally([merge(db, ad, name, a.category, a.source + (" | " + a.url if a.url else ""), a.confidence) for ad in addrs])
    return addrs


def cmd_add(a, db):
    tally([merge(db, a.address, a.name, a.category, a.source, a.confidence)])


def cmd_lookup(a, db):
    v = db.get(a.address.strip())
    print(json.dumps(v, ensure_ascii=False, indent=1) if v else "not found")


def cmd_stats(a, db):
    print("total addresses:", len(db))
    cats = Counter((v if isinstance(v, dict) else {}).get("category", "unknown") for v in db.values())
    for k, n in cats.most_common():
        print("  %-12s %d" % (k, n))
    alts = sum(1 for v in db.values() if isinstance(v, dict) and v.get("alt"))
    print("addresses with conflicting labels (check manually):", alts)


def fetch_url(url, dest):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "labels-tool/0.2"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def cmd_sync(a, db):
    """Refresh the database from every source listed in sources.json."""
    import types
    with open(a.sources, encoding="utf-8") as f:
        sources = json.load(f)
    os.makedirs(a.cache, exist_ok=True)
    for s in sources:
        name = s["name"]
        if s.get("enabled") is False:
            continue
        try:
            path = s.get("path")
            if s.get("url"):
                path = path or os.path.join(a.cache, name.replace(" ", "_"))
                fetch_url(s["url"], path)
            if not path or not os.path.exists(path):
                print("[%s] skipped, file not found: %s | %s" % (name, path, s.get("note", "")))
                continue
            print("[%s]" % name, end=" ")
            if s["type"] == "ofac":
                cmd_import_ofac(types.SimpleNamespace(file=path), db)
            elif s["type"] == "text":
                cmd_import_text(types.SimpleNamespace(file=path, source=name, name=s.get("label", name), category=s.get("category", "scam"),
                                                      confidence=s.get("confidence", "high"), url=s.get("url", "")), db)
            else:
                cmd_import_csv(types.SimpleNamespace(
                    file=path, source=name, address_col=s.get("address_col", "address"),
                    name_col=s.get("name_col", "entity"), category_col=s.get("category_col", "category"),
                    chain_col=s.get("chain_col", "chain"), chain=s.get("chain", "all"),
                    category=s.get("category", "unknown"), default_name=s.get("default_name", ""),
                    confidence=s.get("confidence", "medium")), db)
        except Exception as e:
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                hint = (" | The connection to this site is being intercepted by something on this network or computer (antivirus, filter, proxy), so the certificate is not trusted."
                        " Security checks are NOT disabled. Download the file by hand in the browser, save it as %s next to this tool, and run sync again." % (s.get("path") or "the file"))
            print("[%s] failed: %s%s" % (name, e, hint))


def cmd_candidates(a, db):
    """List unlabeled addresses a trace flagged (high activity / collection points) for manual review."""
    with open(a.graph, encoding="utf-8") as f:
        g = json.load(f)
    rows = [(ad, n["note"]) for ad, n in g["nodes"].items()
            if n.get("note") and not n.get("label") and not db.get(ad)]
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address", "name", "category", "note"])
        for ad, note in rows:
            w.writerow([ad, "", "", note])
    print("%d candidates written to %s." % (len(rows), a.out))
    print("Check each address in a block explorer, fill name + category, then run:")
    print("  python labels_tool.py import-csv %s --source manual-review --name-col name" % a.out)


def cmd_export_csv(a, db):
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address", "label", "category", "source", "confidence", "sources"])
        for ad, v in sorted(db.items()):
            v = v if isinstance(v, dict) else {"label": v}
            w.writerow([ad, v.get("label", ""), v.get("category", ""), v.get("source", ""),
                        v.get("confidence", ""), ";".join(v.get("sources", []))])
    print("exported %d rows to %s" % (len(db), a.out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("import-csv")
    p.add_argument("file")
    p.add_argument("--source", required=True)
    p.add_argument("--address-col", default="address")
    p.add_argument("--name-col", default="entity")
    p.add_argument("--category-col", default="category")
    p.add_argument("--chain-col", default="chain")
    p.add_argument("--chain", default="all", help="bitcoin / ethereum / tron / all")
    p.add_argument("--category", default="unknown")
    p.add_argument("--default-name", default="")
    p.add_argument("--confidence", default="medium", choices=CONF)
    p.set_defaults(fn=cmd_import_csv)

    p = sub.add_parser("import-ofac")
    p.add_argument("file")
    p.set_defaults(fn=cmd_import_ofac)

    p = sub.add_parser("import-text", help="extract addresses from any text/HTML/XML/JSON/PDF file (a government notice, a report)")
    p.add_argument("file")
    p.add_argument("--source", required=True, help="who published it, e.g. 'FBI IC3 PSA 2024'")
    p.add_argument("--url", default="")
    p.add_argument("--name", default="", help="label to show (default: the source)")
    p.add_argument("--category", default="scam")
    p.add_argument("--confidence", default="high", choices=CONF)
    p.set_defaults(fn=cmd_import_text)

    p = sub.add_parser("add")
    p.add_argument("address")
    p.add_argument("name")
    p.add_argument("--category", default="unknown")
    p.add_argument("--source", default="manual")
    p.add_argument("--confidence", default="medium", choices=CONF)
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("lookup")
    p.add_argument("address")
    p.set_defaults(fn=cmd_lookup)

    p = sub.add_parser("stats")
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("sync")
    p.add_argument("--sources", default="sources.json")
    p.add_argument("--cache", default="labels_cache")
    p.set_defaults(fn=cmd_sync)

    p = sub.add_parser("candidates")
    p.add_argument("graph")
    p.add_argument("--out", default="candidates.csv")
    p.set_defaults(fn=cmd_candidates)

    p = sub.add_parser("export-csv")
    p.add_argument("--out", default="labels_export.csv")
    p.set_defaults(fn=cmd_export_csv)

    a = ap.parse_args()
    db = load(a.db)
    a.fn(a, db)
    if a.cmd not in ("lookup", "stats", "candidates", "export-csv"):
        save(db, a.db)
        print("saved to", a.db)


if __name__ == "__main__":
    main()
