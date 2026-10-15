#!/usr/bin/env python3
"""
site_scan.py - link crypto wallets to the websites that display them. Python 3.8+.

    python site_scan.py scan https://suspicious-site.example [--pages 8]
    python site_scan.py lookup ADDRESS            where have we seen this wallet?
    python site_scan.py network                   sites tied together by shared wallets / contacts
    python site_scan.py import-blocklist FILE --source NAME     domains from a list you trust

What `scan` does (read-only, public pages only, never logs in and never submits forms):
  1. Fetches the page and a few related pages of the SAME site, saving each as tamper-evident evidence.
  2. Extracts every wallet address shown (BTC / ETH / TRON), keeping only addresses with a valid checksum.
  3. Collects public domain facts: registration date, certificate age, hosting IPs.
  4. Scores scam indicators (young domain, promised returns, withdrawal fees, wallet-connect traps...).
  5. Writes labels.json entries so the tracers and the map flag these wallets, and saves a report.

Honest limits:
  - Many scam platforms show deposit addresses only AFTER registration. This tool does not register.
    If you were given an address inside such a platform, trace it directly and add it with labels_tool.py.
  - A wallet shown on a site is "associated" with it, not proof the site's owner controls it.
    Only HIGH-tier results are labeled as scam, with medium confidence unless a trusted blocklist matches.
  - A LOW score never means a site is safe.
  - Do not open suspicious sites in your normal browser, and do not contact numbers or accounts found
    on them. Give them to the police.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

import labels_tool
import verify

UA = "site-scan/0.1 (anti-fraud research; read-only)"
DELAY = 1.0
DB_FILE, BLOCK_FILE, EVID_DIR, REPORT_DIR = "sites.json", "blocklist.json", "site_evidence", "site_reports"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".css", ".js", ".ico", ".pdf", ".zip", ".mp4", ".woff", ".woff2")
PRIORITY = ("deposit", "wallet", "pay", "invest", "withdraw", "contact", "about", "terms", "faq", "plan", "package")
RED = {
    "returns": (2, "وعود بأرباح مضمونة أو يومية", ["guaranteed profit", "guaranteed return", "daily profit", "daily return", "double your", "risk-free", "risk free", "أرباح مضمونة", "ربح يومي", "بدون مخاطر", "ضاعف أموالك"]),
    "fees": (2, "رسوم أو ضرائب مسبقة للسحب (نمط احتيال شائع)", ["withdrawal fee", "withdrawal tax", "tax to withdraw", "insurance fee", "unlock fee", "activation fee", "رسوم السحب", "ضريبة السحب", "رسوم التأمين", "رسوم التفعيل"]),
    "wallet": (2, "طلب ربط المحفظة أو التحقق منها (فخ سرقة شائع)", ["connect wallet", "verify your wallet", "validate wallet", "sync wallet", "ربط المحفظة", "التحقق من المحفظة"]),
    "pressure": (1, "ضغط زمني على الضحية", ["limited time", "act now", "last chance", "عرض محدود", "آخر فرصة"]),
}


# ---------------- address extraction (checksum validated) ----------------
def b58check(addr):
    n = 0
    for c in addr:
        i = B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    if n.bit_length() > 200:
        return None
    raw = n.to_bytes(25, "big")
    return raw[0] if hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:] else None


def bech32_ok(addr):
    a = addr.lower()
    if addr != a and addr != addr.upper():
        return False
    pos = a.rfind("1")
    hrp, data = a[:pos], a[pos + 1:]
    if not hrp or len(data) < 6 or any(c not in BECH for c in data):
        return False
    gen, chk = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3], 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + [BECH.find(c) for c in data]:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk in (1, 0x2bc830a3)


def find_addresses(text):
    found = {}
    for m in re.findall(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text):
        if b58check(m) in (0x00, 0x05):
            found[m] = "btc"
    for m in re.findall(r"\b(bc1[a-zA-Z0-9]{11,87})\b", text):
        if bech32_ok(m):
            found[m.lower()] = "btc"
    for m in re.findall(r"\b(0x[a-fA-F0-9]{40})\b", text):
        found[m.lower()] = "eth"
    for m in re.findall(r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b", text):
        if b58check(m) == 0x41:
            found[m] = "tron"
    return found


# ---------------- safe fetching ----------------
def resolve(host):
    last = None
    for port, kw in ((443, {"type": socket.SOCK_STREAM}), (None, {}), (80, {"type": socket.SOCK_STREAM})):
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, **kw)})
        except (OSError, UnicodeError) as e:
            last = e
    raise OSError(str(last))


def check_url(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Only http/https links are accepted.")
    try:
        ips = resolve(p.hostname)
    except OSError as e:
        raise ValueError("The domain does not resolve (it may be taken down or mistyped): %s" % str(e)[:100])
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:
            raise ValueError("This link points to a private or local address; refusing to fetch it.")
    return p


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(SafeRedirect)


def get_page(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
        with OPENER.open(req, timeout=20) as r:
            ct = r.headers.get("Content-Type", "")
            if not any(k in ct for k in ("html", "text", "json")):
                return None
            return r.read(2_000_000)
    except ValueError:
        raise
    except Exception:
        return None


def registrable(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def tls_info(host):
    try:
        with socket.create_connection((host, 443), timeout=10) as s, ssl.create_default_context().wrap_socket(s, server_hostname=host) as ss:
            c = ss.getpeercert()
        nb = datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z")
        return {"not_before": nb.strftime("%Y-%m-%d"), "issuer": dict(x[0] for x in c.get("issuer", ())).get("organizationName")}
    except Exception:
        return {}


def rdap(domain, base="https://rdap.org/domain/"):
    try:
        req = urllib.request.Request(base + domain, headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        d = json.load(urllib.request.urlopen(req, timeout=20))
        created = next((e["eventDate"][:10] for e in d.get("events", []) if e.get("eventAction") == "registration"), None)
        registrar = None
        for ent in d.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item[0] == "fn":
                        registrar = item[3]
        return {"created": created, "registrar": registrar}
    except Exception:
        return {}


# ---------------- analysis ----------------
def bare(h):
    h = (h or "").lower()
    return h[4:] if h.startswith("www.") else h


def links(html, base, host):
    out = []
    for h in re.findall(r'href=["\']([^"\'#]+)', html, re.I):
        u = urllib.parse.urljoin(base, h)
        q = urllib.parse.urlparse(u)
        if q.scheme in ("http", "https") and bare(q.hostname) == bare(host) and not q.path.lower().endswith(SKIP_EXT):
            out.append(u)
    return out


def priority(u):
    return sum(k in u.lower() for k in PRIORITY)


def contacts_in(html):
    out = set()
    for h in re.findall(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_+]{3,})", html):
        out.add(("telegram", h.lower()))
    for n in re.findall(r"(?:wa\.me/|api\.whatsapp\.com/send\?phone=)(\+?\d{6,15})", html):
        out.add(("whatsapp", n))
    for e in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html):
        if not e.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")):
            out.add(("email", e.lower()))
    return out


def load_json(path, default):
    return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else default


def blocklist_hit(host, block):
    parts = host.lower().split(".")
    for i in range(len(parts) - 1):
        d = ".".join(parts[i:])
        if d in block.get("domains", {}):
            return block["domains"][d]
    return None


def assess(host, pages, meta, block, now=None):
    now = now or datetime.now(timezone.utc)
    reasons, addrs, contacts = [], {}, set()
    text_all = ""
    for pg in pages:
        for a, c in find_addresses(pg["html"]).items():
            addrs.setdefault(a, {"chain": c, "pages": []})["pages"].append(pg["url"])
        contacts |= contacts_in(pg["html"])
        clean = re.sub(r"<(script|style).*?</\1>", " ", pg["html"], flags=re.S | re.I)
        text_all += " " + re.sub(r"<[^>]+>", " ", clean).lower()
    created = (meta.get("rdap") or {}).get("created")
    if created:
        age = (now - datetime.strptime(created, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days
        pts = 3 if age < 30 else 2 if age < 90 else 1 if age < 365 else 0
        if pts:
            reasons.append((pts, "النطاق مسجّل منذ %d يومًا فقط" % age))
    else:
        reasons.append((0, "عمر النطاق غير معروف (بيانات التسجيل محجوبة أو غير متاحة)"))
    nb = (meta.get("tls") or {}).get("not_before")
    if nb and (now - datetime.strptime(nb, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days < 14:
        reasons.append((1, "شهادة الأمان صدرت حديثًا (أقل من 14 يومًا)"))
    hit = set()
    for key, (pts, desc, words) in RED.items():
        if any(w in text_all for w in words):
            hit.add(key)
            reasons.append((pts, desc))
    kinds = {k for k, _ in contacts}
    if kinds and kinds <= {"telegram", "whatsapp"}:
        reasons.append((1, "التواصل عبر تطبيق مراسلة فقط دون بريد رسمي"))
    if len(addrs) >= 3:
        reasons.append((1, "عدة عناوين محافظ مختلفة معروضة (تدوير العناوين)"))
    if addrs and ({"returns", "fees"} & hit):
        reasons.append((1, "طلب إيداع إلى محفظة مع وعود أرباح أو رسوم"))
    src = blocklist_hit(host, block)
    if src:
        reasons.append((5, "النطاق في قائمة حظر قدّمتها (%s)" % src))
    score = sum(p for p, _ in reasons)
    title = re.search(r"<title[^>]*>(.*?)</title>", pages[0]["html"], re.S | re.I)
    return {"score": score, "tier": "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW",
            "reasons": reasons, "addresses": addrs, "contacts": sorted(contacts), "blocklist": src,
            "title": re.sub(r"\s+", " ", title.group(1)).strip()[:120] if title else ""}


TIER_AR = {"HIGH": "مرتفع: مؤشرات قوية على احتيال", "MEDIUM": "متوسط: مؤشرات مقلقة تحتاج مراجعة", "LOW": "منخفض: لا مؤشرات كافية (لا يعني أنه آمن)"}


def report_text(host, url, res, meta, folder, npages):
    r = meta.get("rdap") or {}
    L = ["# تقرير فحص موقع: %s" % host, "",
         "الرابط: %s | تاريخ الفحص: %s | الصفحات المفحوصة: %d" % (url, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), npages),
         "", "## الحكم: %s (نقاط الخطر: %d)" % (TIER_AR[res["tier"]], res["score"]),
         "مؤشرات آلية وليست دليلًا قضائيًا. لا تنشر اتهامًا علنيًا بناءً عليها، سلّمها للجهات المختصة.", "",
         "## بيانات النطاق", "- العنوان: %s" % (res["title"] or "غير معروف"),
         "- تاريخ تسجيل النطاق: %s | المسجِّل: %s" % (r.get("created") or "غير معروف", r.get("registrar") or "غير معروف"),
         "- شهادة الأمان: %s (%s)" % ((meta.get("tls") or {}).get("not_before") or "غير معروف", (meta.get("tls") or {}).get("issuer") or "-"),
         "- عناوين الاستضافة: %s" % (", ".join(meta.get("ips") or []) or "غير معروف")]
    L += ["", "## مؤشرات الخطر"] + (["- (+%d) %s" % (p, t) if p else "- %s" % t for p, t in res["reasons"]] or ["- لا شيء"])
    L += ["", "## محافظ معروضة في الموقع (%d)" % len(res["addresses"])]
    L += ["- %s (%s) في %d صفحة" % (a, v["chain"], len(v["pages"])) for a, v in res["addresses"].items()] or ["- لم يُعثر على عناوين في الصفحات العامة. قد تظهر العناوين بعد التسجيل في المنصة (لا تسجّل)."]
    if res["contacts"]:
        L += ["", "## قنوات تواصل يعرضها الموقع (للشرطة فقط: لا تتواصل معها)"] + ["- %s: %s" % c for c in res["contacts"]]
    L += ["", "## ماذا تفعل الآن",
          "1. تتبّع المحافظ أعلاه (زر تتبّع في الصفحة أو btc_tracer / acct_tracer) و'ابنِ القضية' إن كنت ضحية.",
          "2. اللقطات المحفوظة في %s بأرشيف مرتبط بالبصمات (python verify.py check-archive %s)." % (folder, folder),
          "3. أبلغ الشرطة، وأبلغ مزوّد الاستضافة ومسجّل النطاق (abuse) ومنصات الحماية من التصيّد لإيقاف الموقع.",
          "4. لا تفتح الموقع من جهازك الشخصي ولا تدخل بياناتك فيه."]
    return "\n".join(L)


# ---------------- scan / database ----------------
def scan(url, max_pages=8, base_dir=".", labels_path=None, write_labels=True, now=None):
    p = check_url(url)
    host = bare(p.hostname)
    rec = verify.Recorder(os.path.join(base_dir, EVID_DIR))
    queue, seen, pages = [url], set(), []
    while queue and len(pages) < max_pages:
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        raw = get_page(u)
        if not raw:
            continue
        rec.record(u, raw)
        html = raw.decode("utf-8", "ignore")
        pages.append({"url": u, "html": html})
        queue += [l for l in links(html, u, host) if l not in seen and l not in queue]
        queue.sort(key=lambda x: -priority(x))
        time.sleep(DELAY)
    if not pages:
        raise RuntimeError("No page could be fetched (blocked, offline or not HTML).")
    try:
        ips = resolve(p.hostname)
    except OSError:
        ips = []
    meta = {"ips": ips, "tls": tls_info(p.hostname), "rdap": rdap(registrable(host))}
    res = assess(host, pages, meta, load_json(os.path.join(base_dir, BLOCK_FILE), {}), now)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    db_path = os.path.join(base_dir, DB_FILE)
    db = load_json(db_path, {})
    db[host] = {"url": url, "scanned_at": day, "score": res["score"], "tier": res["tier"], "title": res["title"],
                "reasons": [t for _, t in res["reasons"]], "addresses": res["addresses"],
                "contacts": res["contacts"], "ips": ips, "created": (meta["rdap"] or {}).get("created")}
    json.dump(db, open(db_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    text = report_text(host, url, res, meta, os.path.join(base_dir, EVID_DIR), len(pages))
    os.makedirs(os.path.join(base_dir, REPORT_DIR), exist_ok=True)
    open(os.path.join(base_dir, REPORT_DIR, "%s_%s.md" % (host, day)), "w", encoding="utf-8").write(text)
    labeled = 0
    if write_labels and labels_path and res["tier"] in ("HIGH", "MEDIUM") and res["addresses"]:
        ldb = labels_tool.load(labels_path)
        for a in res["addresses"]:
            if res["tier"] == "HIGH":
                labeled += labels_tool.merge(ldb, a, "Scam site: " + host, "scam", "site-scan %s %s" % (host, day),
                                             "high" if res["blocklist"] else "medium") != "invalid"
            else:
                labeled += labels_tool.merge(ldb, a, "Suspicious site: " + host, "suspicious-site",
                                             "site-scan %s %s" % (host, day), "low") != "invalid"
        labels_tool.save(ldb, labels_path)
    return {"report": text, "tier": res["tier"], "score": res["score"], "domain": host, "labeled": labeled,
            "addresses": [{"address": a, "chain": v["chain"]} for a, v in res["addresses"].items()]}


def norm_addr(a):
    return a.lower() if a.startswith("0x") or a.lower().startswith("bc1") else a


def cmd_lookup(a):
    db, hits = load_json(DB_FILE, {}), []
    want = norm_addr(a.address.strip())
    for host, s in db.items():
        if want in s["addresses"]:
            hits.append("%s | %s (score %d) | scanned %s | pages: %s" % (host, s["tier"], s["score"], s["scanned_at"], ", ".join(s["addresses"][want]["pages"][:3])))
    print("\n".join(hits) if hits else "Not seen on any scanned site (this does not mean it is clean).")


def cmd_network(a):
    db = load_json(DB_FILE, {})
    by_addr, by_contact, by_ip = defaultdict(set), defaultdict(set), defaultdict(set)
    for host, s in db.items():
        for ad in s["addresses"]:
            by_addr[ad].add(host)
        for c in s["contacts"]:
            by_contact[tuple(c)].add(host)
        for ip in s["ips"]:
            by_ip[ip].add(host)
    print("== Same wallet on several sites (strong link) ==")
    for k, v in by_addr.items():
        if len(v) > 1:
            print("%s: %s" % (k, ", ".join(sorted(v))))
    print("== Same contact channel on several sites (strong link) ==")
    for k, v in by_contact.items():
        if len(v) > 1:
            print("%s %s: %s" % (k[0], k[1], ", ".join(sorted(v))))
    print("== Same hosting IP (weak: CDNs and shared hosting are common) ==")
    for k, v in by_ip.items():
        if len(v) > 1:
            print("%s: %s" % (k, ", ".join(sorted(v))))


def cmd_import_blocklist(a):
    block = load_json(BLOCK_FILE, {"domains": {}})
    n = 0
    for line in open(a.file, encoding="utf-8", errors="ignore"):
        tok = re.split(r"[,\s;]", line.strip())[0]
        if not tok or tok.startswith("#"):
            continue
        host = bare(urllib.parse.urlparse(tok if "//" in tok else "//" + tok).hostname)
        if host and "." in host:
            block["domains"][host] = a.source
            n += 1
    json.dump(block, open(BLOCK_FILE, "w", encoding="utf-8"), indent=1)
    print("imported %d domains from %s" % (n, a.source))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.add_argument("url")
    p.add_argument("--pages", type=int, default=8)
    p.add_argument("--labels", default="labels.json")
    p.add_argument("--no-labels", action="store_true")
    p = sub.add_parser("lookup")
    p.add_argument("address")
    sub.add_parser("network")
    p = sub.add_parser("import-blocklist")
    p.add_argument("file")
    p.add_argument("--source", required=True)
    a = ap.parse_args()
    if a.cmd == "scan":
        try:
            out = scan(a.url, a.pages, ".", a.labels, not a.no_labels)
        except (ValueError, RuntimeError) as e:
            sys.exit(str(e))
        print(out["report"])
        print("\nwallet labels written: %d" % out["labeled"])
    else:
        {"lookup": cmd_lookup, "network": cmd_network, "import-blocklist": cmd_import_blocklist}[a.cmd](a)


if __name__ == "__main__":
    main()
