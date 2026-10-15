#!/usr/bin/env python3
"""
serve.py - local app that connects the tracers to the map page. Python 3.8+.

    python serve.py [--port 8765]

Then open http://127.0.0.1:8765 : the site has a tab for every tool (start from your payment,
trace, scan a site, wallet profile, verification, labels, watch) around one shared transaction map.

Keep these files in the same folder:
    serve.py  index.html  and all the tool modules (btc_tracer, acct_tracer, utxo_trace, case_builder, ...)
    (labels.json optional)

The server listens on your own machine only (127.0.0.1). Optional environment
variable TRACER_API_KEY is passed to the Ethereum/TRON data providers.
"""
import argparse
import json
import os
import re
import sys
import types
import webbrowser
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import acct_tracer  # noqa: E402
import brief  # noqa: E402
import identify  # noqa: E402
import btc_tracer  # noqa: E402
import case_builder  # noqa: E402
import chains  # noqa: E402
import intake  # noqa: E402
import payments  # noqa: E402
import diagnose  # noqa: E402
import ledger  # noqa: E402
import links  # noqa: E402
import labels_tool  # noqa: E402
import operation  # noqa: E402
import precheck  # noqa: E402
import patterns  # noqa: E402
import reports_check  # noqa: E402
import review  # noqa: E402
import site_scan  # noqa: E402
import taxonomy  # noqa: E402
import verify  # noqa: E402
import wallet_profile  # noqa: E402
import watch  # noqa: E402

BTC_RE = re.compile(r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,87})$")


def load_labels():
    p = os.path.join(HERE, "labels.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return {}


def run_trace(chain, addr, depth, all_tokens, taint=False, stolen=None, save=True):
    labels = load_labels()
    depth = max(1, min(depth, 5))
    if chains.is_utxo(chain):
        addr = case_builder.valid_address(chain, addr)
        with btc_tracer.use_chain(chain):
            g = btc_tracer.trace(addr, depth, 200, chains.DEFAULT_MIN_NATIVE[chains.native(chain)], labels, taint=taint, stolen=stolen)
        g["chain"] = chain
    elif chains.is_account(chain):
        if taint:
            raise ValueError("تتبّع المسروق متاح لشبكات بتكوين-الشكل فقط حاليًا.")
        addr = case_builder.valid_address(chain, addr)
        args = types.SimpleNamespace(
            depth=depth, min_stable=10, min_native=None, max_pages=4, max_fanout=30,
            all_tokens=all_tokens, api_key=os.environ.get("TRACER_API_KEY"), internal=True)
        g = acct_tracer.trace(chain, addr, args, labels)
    else:
        raise ValueError("Unknown network.")
    if save:
        with open(os.path.join(HERE, "graph.json"), "w", encoding="utf-8") as f:
            json.dump(g, f, ensure_ascii=False, indent=2)
    return g


def run_profile(chain, addr):
    addr = case_builder.valid_address(chain, addr)
    args = types.SimpleNamespace(max_txs=500, max_pages=6, all_tokens=False,
                                 api_key=os.environ.get("TRACER_API_KEY"))
    text, _ = wallet_profile.build(chain, addr, load_labels(), args)
    with open(os.path.join(HERE, "profile.md"), "w", encoding="utf-8") as f:
        f.write(text)
    return {"report": text}


CATEGORIES = set(taxonomy.ALL)
MAX_BODY = 8 * 1024 * 1024


def qv(q, k, d=""):
    return q.get(k, [d])[0]


def tkey():
    return os.environ.get("TRACER_API_KEY")


def check_graph(g):
    if not (isinstance(g, dict) and isinstance(g.get("nodes"), dict) and isinstance(g.get("edges"), list)
            and g.get("start") in g["nodes"]):
        raise ValueError("graph.json غير صالح.")
    return g


# ---------------- GET routes ----------------
def g_trace(q):
    return run_trace(qv(q, "chain", "btc"), qv(q, "address").strip(), int(qv(q, "depth", "3")),
                     qv(q, "all_tokens", "0") == "1", qv(q, "taint", "0") == "1",
                     float(qv(q, "stolen")) if qv(q, "stolen") else None)


def g_profile(q):
    return run_profile(qv(q, "chain", "btc"), qv(q, "address").strip())


def g_case(q):
    params = {k: qv(q, k) for k in ("txid", "asset", "incident", "vout", "victim", "contact", "report_no", "lang") if qv(q, k)}
    return case_builder.run_case(qv(q, "chain", "btc"), qv(q, "address"), int(qv(q, "depth", "3")),
                                 float(qv(q, "stolen")) if qv(q, "stolen") else None, load_labels(),
                                 os.path.join(HERE, "cases"), params=params, key=tkey())


def g_intake(q):
    return intake.find(qv(q, "txid"), qv(q, "chain", "auto"))


def g_payments(q):
    chain = qv(q, "chain", "btc")
    amt = qv(q, "amount", "")
    try:
        amount = float(amt) if amt else None
    except ValueError:
        raise ValueError("المبلغ يجب أن يكون رقمًا.")
    res = payments.list_payments(chain, qv(q, "address"), amount, qv(q, "date", "") or None, None, 8, tkey())
    res["text"] = payments.format_list(res, qv(q, "lang", "ar"))
    return res


def g_diagnose(q):
    chain = qv(q, "chain", "btc")
    d = diagnose.diagnose(chain, qv(q, "address"), load_labels(), tkey())
    return {"diagnosis": d, "lines": diagnose.lines_ar(d, qv(q, "lang", "ar"))}


def g_scan(q):
    return site_scan.scan(qv(q, "url").strip(), base_dir=HERE, labels_path=os.path.join(HERE, "labels.json"))


def g_operation(q):
    chain = qv(q, "chain", "btc")
    addr = case_builder.valid_address(chain, qv(q, "address"))
    ops = operation.analyze(operation.collect(chain, addr, tkey()), load_labels())
    return {"lines": operation.lines_ar(ops), "ops": ops}


def g_reports(q):
    chain = qv(q, "chain", "btc")
    addr = case_builder.valid_address(chain, qv(q, "address"))
    s = reports_check.lookup(addr, chain, os.environ.get("CHAINABUSE_KEY"), base_dir=HERE)
    return {"lines": reports_check.lines_ar(s, addr), "summary": s}


def g_lookup(q):
    addr = labels_tool.norm(qv(q, "address").strip())
    if not addr:
        raise ValueError("عنوان غير صالح.")
    entry = load_labels().get(addr)
    label = entry if isinstance(entry, dict) else ({"label": entry} if entry else None)
    db = site_scan.load_json(os.path.join(HERE, site_scan.DB_FILE), {})
    sites = [{"domain": d, "tier": s.get("tier")} for d, s in db.items() if addr in s.get("addresses", {})]
    cache = site_scan.load_json(os.path.join(HERE, reports_check.CACHE_FILE), {})
    rep = next((v for k, v in cache.items() if k.split(":", 1)[-1] == addr), None)
    return {"address": addr, "label": label, "sites": sites, "reports": rep}


def g_balance(q):
    chain = qv(q, "chain", "btc")
    addr = case_builder.valid_address(chain, qv(q, "address"))
    return {"balance": case_builder.fetch_balance(chain, addr, tkey()),
            "pending": watch.pending_btc(addr, {}) if chain == "btc" else []}


def g_labels_stats(q):
    db = load_labels()
    cats = Counter((v.get("category") if isinstance(v, dict) else None) or "غير محدد" for v in db.values())
    return {"total": len(db), "categories": dict(cats),
            "conflicts": sum(1 for v in db.values() if isinstance(v, dict) and v.get("alt"))}


def g_archive_check(q):
    path = os.path.abspath(os.path.join(HERE, qv(q, "folder", "evidence")))
    if not (path == HERE or path.startswith(HERE + os.sep)):
        raise ValueError("المجلد خارج مجلد الأدوات.")
    manifest = os.path.join(path, "manifest.json")
    if not os.path.exists(manifest):
        raise ValueError("لا يوجد أرشيف أدلة بهذا الاسم.")
    problems = verify.check_archive(path)
    return {"ok": not problems, "problems": problems, "entries": len(json.load(open(manifest, encoding="utf-8")))}


def ledger_path():
    return os.path.join(HERE, "ledger.db")


def g_ledger_cases(q):
    return {"cases": ledger.cases(ledger_path())}


def g_ledger(q):
    cid = qv(q, "case").strip()
    if not cid:
        raise ValueError("اكتب رقم القضية.")
    cs = ledger.claims(ledger_path(), cid)
    return {"claims": cs, "assessment": ledger.assess(cs), "report": ledger.report_text(ledger_path(), cid),
            "chain_ok": not ledger.verify(ledger_path())}


def run_identify(chain, address, live=False, external=False, graph=None):
    addr = case_builder.valid_address(chain, address)
    r = identify.identify(chain, addr, HERE, None, graph, live, external, tkey(), os.environ.get("CHAINABUSE_KEY"))
    return {"report": identify.report_text(r), "result": r}


def g_identify(q):
    return run_identify(qv(q, "chain", "btc"), qv(q, "address"), qv(q, "live", "0") == "1", qv(q, "external", "0") == "1")


def p_identify(b):
    g = b.get("graph")
    if g is not None:
        check_graph(g)
    return run_identify(b.get("chain") or "btc", b.get("address") or "", bool(b.get("live")), bool(b.get("external")), g)


def p_links(b):
    res = links.analyze(check_graph(b.get("graph")), (b.get("address") or "").strip() or None)
    return {"links": res["links"], "report": links.report_text(res)}


def review_db():
    return os.path.join(HERE, "review.db")


def labels_file():
    return os.path.join(HERE, "labels.json")


def g_review_queue(q):
    return {"items": review.queue(review_db(), qv(q, "status", "pending"), int(qv(q, "limit", "20"))), "stats": review.stats(review_db())}


def g_review_stats(q):
    return dict(review.stats(review_db()), history_ok=not review.verify_history(review_db()))


def g_review_bundle(q):
    return {"bundle": review.export_bundle(labels_file(), qv(q, "all", "0") != "1")}


def p_review_enqueue(b):
    added, updated = review.enqueue(review_db(), check_graph(b.get("graph")), str(b.get("case") or "")[:80], load_labels())
    return {"added": added, "updated": updated}


def p_review_decide(b):
    return review.decide(review_db(), labels_file(), b.get("address"), b.get("action"), b.get("reviewer"), b.get("label"),
                         b.get("category"), b.get("confidence"), b.get("evidence") or "", b.get("note") or "")


def p_review_official(b):
    return review.import_official(review_db(), labels_file(), None, b.get("platform"), b.get("category"), b.get("source_url"),
                                  b.get("date"), b.get("reviewer"), "high", b.get("text") or "")


def p_review_bundle_import(b):
    return review.import_bundle(review_db(), labels_file(), b.get("bundle") or {}, str(b.get("name") or "bundle")[:80], b.get("reviewer"))


def p_precheck(b):
    chain = b.get("chain") or "btc"
    addr = (b.get("address") or "").strip()
    if addr:
        addr = case_builder.valid_address(chain, addr)
    flags = b.get("flags") or []
    if not isinstance(flags, list):
        raise ValueError("العلامات يجب أن تكون قائمة.")
    r = precheck.precheck(chain, addr or None, (b.get("url") or "").strip() or None, flags, bool(b.get("live")), HERE, tkey(),
                          os.environ.get("CHAINABUSE_KEY"))
    return {"report": precheck.report_text(r), "result": r}


def g_ledger_platforms(q):
    return {"platforms": ledger.platforms(ledger_path())}


def g_brief(q):
    text, path = brief.save(qv(q, "case").strip(), os.path.join(HERE, "cases"), ledger_path())
    return {"report": text, "saved": os.path.relpath(path, HERE) if path else None}


def g_ledger_verify(q):
    problems = ledger.verify(ledger_path())
    return {"ok": not problems, "problems": problems, "head": ledger.head(ledger_path())}


GET_ROUTES = {"/api/review/queue": g_review_queue, "/api/review/stats": g_review_stats, "/api/review/bundle": g_review_bundle, "/api/identify": g_identify, "/api/ledger/platforms": g_ledger_platforms, "/api/brief": g_brief, "/api/ledger/cases": g_ledger_cases, "/api/ledger": g_ledger, "/api/ledger/verify": g_ledger_verify,
              "/api/trace": g_trace, "/api/profile": g_profile, "/api/case": g_case, "/api/intake": g_intake, "/api/payments": g_payments, "/api/diagnose": g_diagnose,
              "/api/scan": g_scan, "/api/operation": g_operation, "/api/reports": g_reports, "/api/lookup": g_lookup,
              "/api/balance": g_balance, "/api/labels-stats": g_labels_stats, "/api/archive-check": g_archive_check}


# ---------------- POST routes ----------------
def p_verify(b):
    g = check_graph(b.get("graph"))
    args = types.SimpleNamespace(archive=None, no_network=bool(b.get("no_network")), second="https://mempool.space/api",
                                 second_eth="https://ethereum-rpc.publicnode.com", second_tron=None, max_check=40)
    text, verdict = verify.run_audit(g, load_labels(), args)
    return {"report": text, "verdict": verdict}


def p_patterns(b):
    res = patterns.analyze(check_graph(b.get("graph")))
    return {"tier": res["tier"], "score": res["score"], "tier_text": res["tier_text"],
            "findings": [{"type": f["type"], "weight": f["weight"], "text": f["text"]} for f in res["findings"]]}


def p_label(b):
    addr = labels_tool.norm(str(b.get("address", "")).strip())
    name = str(b.get("label", "")).strip()[:120]
    if not addr:
        raise ValueError("عنوان غير صالح.")
    if not name:
        raise ValueError("اكتب اسم الجهة.")
    if b.get("category") not in CATEGORIES or b.get("confidence") not in labels_tool.CONF:
        raise ValueError("فئة أو درجة ثقة غير صالحة.")
    path = os.path.join(HERE, "labels.json")
    db = labels_tool.load(path)
    status = labels_tool.merge(db, addr, name, b["category"], "manual (web)", b["confidence"])
    labels_tool.save(db, path)
    return {"status": status, "address": addr}


def p_ledger_add(b):
    cid = ledger.add(ledger_path(), b.get("case"), b.get("kind"), b.get("subject"), b.get("source"), b.get("source_type"),
                     b.get("date"), b.get("method"), b.get("country"), b.get("reliability"), bool(b.get("vpn_possible")),
                     b.get("note") or "", b.get("evidence_file") or None, base_dir=HERE, value=b.get("value"))
    return {"id": cid}


POST_ROUTES = {"/api/precheck": p_precheck, "/api/review/enqueue": p_review_enqueue, "/api/review/decide": p_review_decide, "/api/review/import-official": p_review_official, "/api/review/bundle-import": p_review_bundle_import, "/api/identify": p_identify, "/api/links": p_links, "/api/ledger/add": p_ledger_add, "/api/verify": p_verify, "/api/patterns": p_patterns, "/api/label": p_label}


LANG_CODES = ("ar", "en", "es", "fr", "tr", "ru", "fa")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def guard(self, path):
        # Only this machine may talk to the server, and every /api call must carry a custom header:
        # a web page on another site cannot add it without a CORS preflight, which this server never grants.
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host not in ("127.0.0.1", "localhost"):
            self.reply(403, {"error": "forbidden"})
            return False
        if path.startswith("/api/") and path != "/api/ping" and self.headers.get("X-Tracer") != "1":
            self.reply(403, {"error": "missing X-Tracer header"})
            return False
        return True

    def run(self, fn, arg):
        try:
            return self.reply(200, fn(arg))
        except (ValueError, RuntimeError) as e:
            return self.reply(400, {"error": str(e)})
        except Exception as e:
            return self.reply(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_GET(self):
        u = urlparse(self.path)
        if not self.guard(u.path):
            return
        if u.path in ("/", "/index.html"):
            for name in ("index.html",):
                p = os.path.join(HERE, name)
                if os.path.exists(p):
                    with open(p, "rb") as f:
                        return self.reply(200, f.read(), "text/html; charset=utf-8")
            return self.reply(404, {"error": "index.html is missing"})
        if u.path == "/api/ping":
            return self.reply(200, {"ok": True})
        fn = GET_ROUTES.get(u.path)
        if fn:
            q = parse_qs(u.query)
            lang = (self.headers.get("X-Lang") or "").lower()[:2]
            if lang in LANG_CODES:
                q["lang"] = [lang]   # server texts exist in Arabic (source) and English (pivot for en/es/fr/tr/ru)
            return self.run(fn, q)
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if not self.guard(u.path):
            return
        fn = POST_ROUTES.get(u.path)
        if not fn:
            return self.reply(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return self.reply(400, {"error": "empty or too large body"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self.reply(400, {"error": "invalid JSON"})
        return self.run(fn, body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--archive", default=None,
                    help="folder: save every raw API response with SHA-256 hash chain (evidence)")
    a = ap.parse_args()
    if a.archive:
        verify.install_recorder(verify.Recorder(a.archive))
        print("Archiving raw API responses to", a.archive)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    url = "http://127.0.0.1:%d" % a.port
    print("Open", url, "(Ctrl+C to stop)")
    if not a.no_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
