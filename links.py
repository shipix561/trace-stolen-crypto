#!/usr/bin/env python3
"""
links.py - how are these addresses connected, and how much does each connection prove? Python 3.8+.

    python links.py graph.json                    every link found in the trace
    python links.py graph.json --focus ADDRESS    only the links involving one address
    python links.py graph.json --out links.md

Three KINDS of link, kept apart because they prove different things:
  ownership-heuristic  addresses that probably share one wallet: spent together (common-input heuristic, with the
                       safeguards of clusters.py) or a probable change output. A lead about control, never a proof.
  service-structure    an address that sends everything to a known platform's wallet: it is probably that platform's
                       deposit address. It links addresses OF the platform, not the people who deposit.
  financial-flow       money moved between them, or several addresses paid the same destination / were funded by the
                       same source / formed a continuing chain. Money moving is NOT evidence of one owner.

Each link has a strength (strong / moderate / weak), the reasons behind it and the transactions to check.
This is a map of leads for an investigator, not an attribution.
"""
import argparse
import copy
import json
import sys
from collections import defaultdict

import patterns
import verify

KIND_AR = {"ownership-heuristic": "فرضية ملكية (قد تدل على محفظة واحدة، وليست إثباتًا)",
           "service-structure": "بنية خدمة (تربط عناوين المنصة نفسها لا مستخدميها)",
           "financial-flow": "ارتباط مالي فقط (انتقل مال، ولا يعني ذلك مالكًا واحدًا)"}
TYPE_AR = {"co_spend": "إنفاق مشترك", "change": "مخرج باقي الرصيد", "deposit_to_hot_wallet": "عنوان إيداع إلى محفظة المنصة",
           "common_destination": "وجهة مشتركة", "common_source": "مصدر مشترك", "continuation": "سلسلة تحويلات متتابعة"}
STRENGTH_AR = {"strong": "قوي", "moderate": "متوسط", "weak": "ضعيف"}
CONF_TO_STRENGTH = {"high": "strong", "medium": "moderate", "low": "weak"}
ORDER = {"strong": 0, "moderate": 1, "weak": 2}
GLOBAL_CAVEAT = ("الارتباط المالي بين العناوين لا يكفي دليلًا على أن مالكها واحد: قد تكون خدمة تدفع لعملائها، أو عميلًا يدفع لتاجر، أو محفظة مشتركة. "
                 "فرضيات الملكية أقوى من الارتباط المالي، لكنها تبقى فرضيات.")


def short(a):
    return a if len(a) <= 16 else a[:8] + "…" + a[-6:]


def analyze(graph, focus=None):
    g = copy.deepcopy(graph)
    nodes, edges, links = g["nodes"], g["edges"], []
    info = g.get("cluster_info")
    if not info:
        info = [{"members": c, "confidence": "medium", "type": "personal-likely", "reasons": ["مجموعة محسوبة في التتبع"], "txids": []} for c in g.get("clusters", [])]
    for c in info:
        links.append({"kind": "ownership-heuristic", "type": "co_spend", "members": c["members"], "strength": CONF_TO_STRENGTH[c["confidence"]],
                      "reasons": list(c["reasons"]) + (["المجموعة تمثّل خدمة وليس شخصًا"] if c.get("type") == "service-likely" else []),
                      "txids": c.get("txids", [])})
    for e in edges:
        if e.get("change"):
            links.append({"kind": "ownership-heuristic", "type": "change", "members": [e["from"], e["to"]], "strength": "weak",
                          "reasons": ["المخرج يُرجَّح أنه باقي رصيد عاد للمُرسِل (نوع العنوان أو المبلغ غير المستدير): تخمين"], "txids": [e["txid"]]})
    for a, n in nodes.items():
        inf = n.get("inferred") or ""
        if "sends all its funds to" in inf:
            target = inf.split(" to ", 1)[1].strip()
            links.append({"kind": "service-structure", "type": "deposit_to_hot_wallet", "members": [a, target], "strength": "moderate",
                          "reasons": ["يرسل كل أمواله إلى محفظة «%s» المصنّفة: غالبًا عنوان إيداع تابع للمنصة" % n.get("label", "-")],
                          "txids": [e["txid"] for e in edges if e["from"] == a and e["to"] == target][:5]})
    inc, out = defaultdict(set), defaultdict(set)
    for e in edges:
        out[e["from"]].add(e["to"])
        inc[e["to"]].add(e["from"])
    for d, srcs in inc.items():
        if len(srcs) >= 3 and not d.startswith("coinjoin:"):
            lab = nodes.get(d, {}).get("label")
            links.append({"kind": "financial-flow", "type": "common_destination", "members": sorted(srcs) + [d], "strength": "weak",
                          "reasons": ["%d عناوين أرسلت إلى الوجهة نفسها" % len(srcs)] + (["والوجهة «%s»: نمط تجميع إيداعات منصة" % lab] if lab else []),
                          "txids": sorted({e["txid"] for e in edges if e["to"] == d})[:5]})
    for s, ds in out.items():
        if len(ds) >= 3:
            links.append({"kind": "financial-flow", "type": "common_source", "members": [s] + sorted(ds), "strength": "weak",
                          "reasons": ["عنوان واحد موّل %d عناوين" % len(ds)], "txids": sorted({e["txid"] for e in edges if e["from"] == s})[:5]})
    for f in patterns.analyze(g)["findings"]:
        if f["type"] == "CHAIN":
            links.append({"kind": "financial-flow", "type": "continuation", "members": f["nodes"], "strength": "weak",
                          "reasons": [f["text"], "تتابع التحويلات يبيّن مسار المال لا هوية من يتحكم فيه"], "txids": []})
    if focus:
        links = [l for l in links if focus in l["members"]]
    links.sort(key=lambda l: (ORDER[l["strength"]], -len(l["members"])))
    neighbors = []
    if focus:
        flows = defaultdict(float)
        for e in edges:
            if e["from"] == focus:
                flows[("إلى", e["to"])] += verify.amount(e)
            elif e["to"] == focus:
                flows[("من", e["from"])] += verify.amount(e)
        neighbors = sorted(flows.items(), key=lambda kv: -kv[1])[:10]
    return {"links": links, "neighbors": neighbors, "caveat": GLOBAL_CAVEAT, "focus": focus}


def report_text(res):
    L = ["# الروابط بين المحافظ" + (": %s" % res["focus"] if res["focus"] else ""), "", "> " + res["caveat"]]
    if not res["links"]:
        L += ["", "لا روابط في هذا التتبع" + (" تخص هذا العنوان." if res["focus"] else ".") + " غياب الرابط لا يعني غياب العلاقة."]
    for kind in ("ownership-heuristic", "service-structure", "financial-flow"):
        items = [l for l in res["links"] if l["kind"] == kind]
        if not items:
            continue
        L += ["", "## " + KIND_AR[kind]]
        for l in items:
            L.append("- **%s** (%s): %s" % (TYPE_AR[l["type"]], STRENGTH_AR[l["strength"]], "، ".join(short(m) for m in l["members"][:8]) + (" …" if len(l["members"]) > 8 else "")))
            L += ["  - " + r for r in l["reasons"]]
            if l["txids"]:
                L.append("  - للتحقق: " + "، ".join(l["txids"][:3]))
    if res["neighbors"]:
        L += ["", "## أقرب الأطراف مالِيًّا (حسب المبلغ)"] + ["- %s %s: %.6g" % (d, short(a), v) for (d, a), v in res["neighbors"]]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("graph")
    ap.add_argument("--focus")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = analyze(json.load(open(a.graph, encoding="utf-8")), a.focus)
    t = report_text(res)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(t)
    print(t)


if __name__ == "__main__":
    main()
