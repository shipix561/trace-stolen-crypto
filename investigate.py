#!/usr/bin/env python3
"""
investigate.py - one command, one report about an address. Read-only. Python 3.8+.

    python investigate.py btc ADDRESS --depth 3 --live
    python investigate.py eth 0xADDRESS --depth 3 --live
    python investigate.py tron TADDRESS --depth 3 --live [--external]

It combines what the other tools do separately:
  - the plain-language FIRST LEADS (what the trace actually offers, in order),
  - the identity evidence for the address (sources, dates, confidence, research links for manual checks),
  - who paid into the address, behavior patterns, and the links between the addresses found,
  - the trace itself and the wallet behavior profile.

Output goes to a NEW folder, investigations/<chain>_<address>_<time>/ (investigation.md, investigation.json, graph.json).
Nothing in your current folder is overwritten. Load graph.json in the site to see the map.

For a victim's own case start from the payment transaction (intake.py or the site's "start here"): a trace by address
(what this script does for Bitcoin) can include money that belongs to other people.
The report never names a person: an address is not an identity.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import acct_tracer
import btc_tracer
import case_builder
import chains
import identify
import labels_tool
import links
import operation
import patterns
import wallet_profile

LIMIT = "التسمية دليل على جهة أو خدمة، وليست إثباتًا لهوية شخص أو محل إقامته."
FOOTER = ["عنوان المحفظة ليس هوية شخص بحد ذاته.", "بلد تسجيل منصة لا يثبت إقامة مستخدمها.",
          "علاقة التحويل أو تشابه السلوك لا يثبتان الملكية المشتركة.", "تحقّق من كل استنتاج مهم بمصدر مستقل قبل اتخاذ إجراء."]


def defaults(**k):
    a = dict(chain="btc", address="", depth=3, live=False, external=False, labels="labels.json", out=None, json=None, out_dir=None,
             max_txs=200, max_pages=4, max_fanout=30, min_stable=10.0, min_native=None, api_key=None, all_tokens=False, internal=False,
             report_key=None)
    a.update(k)
    return SimpleNamespace(**a)


def run(a):
    """Returns (result, markdown_text, folder). Raises ValueError for unusable input; partial failures are reported inside."""
    addr = case_builder.valid_address(a.chain, a.address)
    if a.depth < 0 or a.max_txs < 1 or a.max_pages < 1 or a.max_fanout < 1:
        raise ValueError("--depth يجب ألا يكون سالبًا، والحدود يجب أن تكون موجبة.")
    try:
        labels = labels_tool.load(a.labels)
    except (ValueError, OSError) as e:
        raise ValueError("تعذرت قراءة ملف التصنيفات: %s" % e)
    lab = {(k.lower() if k.startswith("0x") else k): v for k, v in labels.items()} if chains.is_evm(a.chain) else labels
    errors, g, ops, m, info, profile_text, ir, rows = [], None, None, None, None, "", None, None

    try:
        if chains.is_utxo(a.chain):
            with btc_tracer.use_chain(a.chain):
                g = btc_tracer.trace(addr, a.depth, a.max_txs, chains.DEFAULT_MIN_NATIVE[chains.native(a.chain)], lab)
        else:
            g = acct_tracer.trace(a.chain, addr, SimpleNamespace(
                depth=a.depth, min_stable=a.min_stable, min_native=a.min_native, max_pages=a.max_pages, max_fanout=a.max_fanout,
                all_tokens=a.all_tokens, internal=a.internal, api_key=a.api_key), lab)
        g.setdefault("chain", a.chain)
        case_builder.infer_labels(g)
    except Exception as e:
        errors.append("التتبّع: %s" % str(e)[:300])
        g = None
    try:  # one collection feeds the profile AND the payer analysis (no duplicate requests)
        collect = lambda ad, ns: wallet_profile.collect(a.chain, ad, ns)  # noqa: E731
        rows, info, trunc = collect(addr, SimpleNamespace(max_txs=a.max_txs, max_pages=a.max_pages, all_tokens=a.all_tokens, api_key=a.api_key))
        m = wallet_profile.analyze(rows, lab, trunc)
        profile_text = wallet_profile.build_report(a.chain, addr, m, info)
        ops = operation.analyze(rows, lab)
    except Exception as e:
        errors.append("ملف المحفظة: %s" % str(e)[:300])
    try:
        ir = identify.identify(a.chain, addr, ".", labels, g, a.live, a.external, a.api_key, a.report_key or os.environ.get("CHAINABUSE_KEY"))
    except Exception as e:
        errors.append("تحديد الجهة: %s" % str(e)[:300])

    diag = None
    if (chains.is_utxo(a.chain) and a.live) or (not chains.is_utxo(a.chain) and rows is not None):  # behaviour check: platform wallet or collection address (BTC reads the network)
        try:
            import diagnose
            diag = diagnose.diagnose(a.chain, addr, lab if isinstance(lab, dict) else {}, a.api_key, rows=rows if not chains.is_utxo(a.chain) else None)
        except Exception as e:
            errors.append("تشخيص العنوان: %s" % str(e)[:200])
    lead_md, extra_md, links_md, pat, lk = [], [], "", None, None
    if g is not None:
        try:
            balances = case_builder.collect_balances(g, a.chain, a.api_key) if a.live else {}
        except Exception as e:
            balances = {}
            errors.append("الأرصدة الحالية: %s" % str(e)[:200])
        groups = case_builder.classify(g, balances)
        pat = patterns.analyze(g)
        lk = links.analyze(g)
        lead_md = case_builder.lead_lines(g, groups, a.chain, {"investigation": True}, ops)
        extra_md = case_builder.extra_lines({"pat": pat, "ops": ops, "diag": diag})
        links_md = links.report_text(lk)

    now = datetime.now(timezone.utc)
    S = ["# تقرير التحقيق الموحّد", "", "**الشبكة:** %s  " % a.chain.upper(), "**العنوان:** `%s`  " % addr,
         "**تاريخ الإنشاء (UTC):** %s" % now.strftime("%Y-%m-%d %H:%M"), "",
         "> هذا التقرير يجمع بيانات عامة وتحليلات احتمالية. لا يمكن استنتاج الاسم الحقيقي أو مكان سكن شخص من عنوان البلوكشين وحده. " + LIMIT, ""]
    S += lead_md
    if ir:
        S += [re.sub(r"(?m)^# ", "## ", identify.report_text(ir)), ""]
    S += extra_md
    if links_md:
        S += ["", re.sub(r"(?m)^# ", "## ", links_md), ""]
    if g is not None:
        S += ["## التتبّع على الشبكة", "", "رسم التتبّع محفوظ في `graph.json` (حمّله في الموقع لرؤية الخريطة).", "",
              "- عدد العقد: %d" % len(g.get("nodes", {})), "- عدد الروابط: %d" % len(g.get("edges", [])), ""]
        for e in g.get("edges", [])[:100]:
            S.append("- `%s` → `%s` | %s %s | tx: `%s`" % (e.get("from", "?"), e.get("to", "?"), e.get("amount", e.get("btc", "?")),
                                                           e.get("asset", chains.native(a.chain) if chains.is_utxo(a.chain) else ""), e.get("txid", "?")))
        if len(g.get("edges", [])) > 100:
            S += ["", "عُرضت أول 100 رابط فقط؛ البيانات الكاملة في graph.json."]
    if profile_text:
        S += ["", "## ملف سلوك المحفظة", "", re.sub(r"(?m)^# ", "### ", profile_text)]
    if errors:
        S += ["", "## ما تعذّر إكماله", ""] + ["- " + x for x in errors]
    S += ["", "## حدود الاستنتاج", ""] + ["- " + x for x in FOOTER]
    text = "\n".join(S) + "\n"

    result = {"chain": a.chain, "address": addr, "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "depth": a.depth, "important_limit": LIMIT,
              "trace": g, "identity": ir, "profile": dict(m, info=info) if m else None, "payers": ops, "diagnosis": diag,
              "patterns": {k: pat[k] for k in ("score", "tier", "findings")} if pat else None, "links": lk, "errors": errors}
    folder = a.out_dir or os.path.join("investigations", "%s_%s_%s" % (a.chain, addr[:10], now.strftime("%Y%m%d-%H%M%S")))
    os.makedirs(folder, exist_ok=True)
    md_path = a.out or os.path.join(folder, "investigation.md")
    js_path = a.json or os.path.join(folder, "investigation.json")
    for path, data, kind in ((md_path, text, "text"), (js_path, result, "json"), (os.path.join(folder, "graph.json"), g, "json")):
        if kind == "json" and data is None:
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(data) if kind == "text" else json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    result["files"] = {"report": md_path, "json": js_path, "graph": os.path.join(folder, "graph.json") if g is not None else None, "folder": folder}
    return result, text, folder


def main():
    p = argparse.ArgumentParser(description="يجمع الخيوط الأولى والتتبّع وأدلة الهوية وملف المحفظة في تقرير واحد (قراءة فقط).")
    p.add_argument("chain", choices=chains.ORDER)
    p.add_argument("address")
    p.add_argument("--depth", type=int, default=3)
    p.add_argument("--live", action="store_true", help="تفعيل مصادر الهوية الحية المتاحة وقراءة الأرصدة")
    p.add_argument("--external", action="store_true", help="مصدر وسوم خارجي اختياري (طرف ثالث)")
    p.add_argument("--labels", default="labels.json")
    p.add_argument("--out-dir", help="مجلد الإخراج (الافتراضي: investigations/<الشبكة>_<العنوان>_<الوقت>)")
    p.add_argument("--out", help="مسار ملف التقرير (يتجاوز المجلد)")
    p.add_argument("--json", help="مسار ملف JSON (يتجاوز المجلد)")
    p.add_argument("--max-txs", type=int, default=200)
    p.add_argument("--max-pages", type=int, default=4)
    p.add_argument("--max-fanout", type=int, default=30)
    p.add_argument("--min-stable", type=float, default=10)
    p.add_argument("--min-native", type=float, default=None)
    p.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    p.add_argument("--all-tokens", action="store_true")
    p.add_argument("--internal", action="store_true")
    a = p.parse_args()
    try:
        result, _text, folder = run(a)
    except ValueError as e:
        sys.exit(str(e))
    print("تم الحفظ في: %s" % folder)
    for k, v in result["files"].items():
        if k != "folder" and v:
            print("  %s: %s" % (k, v))
    if result["errors"]:
        print("بعض الأجزاء لم تكتمل؛ راجع قسم «ما تعذّر إكماله» في التقرير.")
    ok = [result["trace"], result["identity"], result["profile"]]
    sys.exit(0 if any(ok) else 2)


if __name__ == "__main__":
    main()
