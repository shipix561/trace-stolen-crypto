#!/usr/bin/env python3
"""
mix_check.py - what to say about money that passed through a mixer or a CoinJoin. Python 3.8+.

HONEST LIMITS. A mixer exists to break the link between the money that goes in and the money that comes out.
Nothing in this file defeats that, and nothing here is evidence of who received what:

  * detect()      finds where the trace entered a mixer/CoinJoin, and the last address before it (this part is a fact)
  * coinjoin_outputs()  lists the equal-value outputs of a CoinJoin transaction: if there are N, your money is
                  ONE of N and nothing in the data says which (the chance of a guess is at best 1/N)
  * match_candidates()  a purely statistical shortlist of later withdrawals of the same denomination: it always
                  carries the pool-size floor 1/N and is marked VERY LOW confidence. A shortlisted address may belong
                  to an innocent person. It is a lead for the police / the platform, never a name, never an accusation.

    python mix_check.py graph.json                   where did the trace enter a mixer?
    python mix_check.py coinjoin btc TXID            equal-value outputs of a CoinJoin transaction
    python mix_check.py match deposit.json pool.json  shortlist by amount and time (see match_candidates)
"""
import json
import sys
from collections import Counter

import taxonomy

WINDOW = 30 * 86400
TOL = 0.005      # 0.5% amount tolerance (fees)


def _amt(e):
    for k in ("btc", "amount", "taint"):
        if isinstance(e.get(k), (int, float)):
            return float(e[k])
    return 0.0


def detect(g):
    """The trace's entries into mixers/CoinJoins. Each event: kind, node, label, entries[(address, amount, time, txid)]."""
    ev = []
    for a, n in g["nodes"].items():
        cat = taxonomy.canon(n.get("category"))
        if cat not in ("mixer", "coinjoin"):
            continue
        ents = [(e["from"], _amt(e), e.get("time"), e.get("txid")) for e in g["edges"] if e["to"] == a]
        ev.append({"kind": "coinjoin" if a.startswith("coinjoin:") or cat == "coinjoin" else "mixer", "node": a,
                   "label": n.get("label"), "entries": ents})
    return ev


def coinjoin_outputs(tx):
    """Equal-value outputs of a CoinJoin-like transaction (Esplora shape). Returns None if there is no such group."""
    outs = [(o["value"], o.get("scriptpubkey_address")) for o in tx.get("vout", []) if o.get("scriptpubkey_address")]
    if len(outs) < 3:
        return None
    val, n = Counter(v for v, _ in outs).most_common(1)[0]
    if n < 3:
        return None
    return {"txid": tx.get("txid"), "denomination": val / 1e8, "count": n, "chance_floor": 1.0 / n,
            "equal_outputs": [a for v, a in outs if v == val], "other_outputs": [a for v, a in outs if v != val],
            "inputs": len(tx.get("vin", []))}


def match_candidates(deposit, pool, window=WINDOW, tol=TOL):
    """deposit {amount, time}; pool [{to, amount, time, txid}] withdrawals from the same mixer.
    Shortlist = same denomination (within tol) that left after the deposit and within `window`."""
    out = []
    for w in pool:
        if not w.get("time") or not deposit.get("time") or w["time"] < deposit["time"] or w["time"] - deposit["time"] > window:
            continue
        if abs(w["amount"] - deposit["amount"]) > tol * deposit["amount"]:
            continue
        out.append(dict(w, gap_days=round((w["time"] - deposit["time"]) / 86400.0, 2)))
    out.sort(key=lambda w: w["gap_days"])
    n = len(out)
    return {"candidates": out, "pool_size": n, "chance_floor": (1.0 / n) if n else None, "confidence": "very-low"}


def lines(events, lang="ar"):
    en = lang in ("en", "es", "fr", "tr", "ru")
    L = ["## Mixing / CoinJoin" if en else "## الخلط (Mixer / CoinJoin)"]
    if not events:
        L.append("- The trace did not pass through a mixer or a CoinJoin that we could detect." if en else "- لم يمرّ التتبع بخلّاط أو CoinJoin استطعنا كشفه.")
        return L
    for e in events:
        total = sum(x[1] for x in e["entries"])
        last = ", ".join(sorted({x[0] for x in e["entries"]})[:3])
        L.append(("- The trace entered %s (%s) with about %.6g in total. Last address(es) before it: %s." if en else
                  "- دخل التتبع إلى %s (%s) بنحو %.6g في المجموع. آخر عنوان قبل الخلط: %s.") %
                 (("CoinJoin" if en and e["kind"] == "coinjoin" else (e["label"] or e["node"])), "CoinJoin" if e["kind"] == "coinjoin" else "mixer", total, last))
    L.append("- A mixer is built to break the link between what goes in and what comes out. The tool does NOT claim to follow the money through it." if en else
             "- الخلّاط مصمَّم لقطع الصلة بين ما يدخل وما يخرج. الأداة لا تدّعي تتبع المال عبره.")
    L.append("- What helps: (1) report the mixing itself to the police: it is part of your case; (2) ask the platform you paid from and the police about records on the entry side; "
             "(3) watch the address before the mix; (4) if later money of the same size reaches a known platform, treat it as a lead with VERY LOW confidence, never as proof." if en else
             "- ما يفيد: (1) اذكر الخلط نفسه في بلاغ الشرطة فهو جزء من قضيتك؛ (2) اسأل المنصة التي دفعت منها والشرطة عن سجلات جهة الدخول؛ "
             "(3) راقب العنوان الذي قبل الخلط؛ (4) إن وصل لاحقًا مال بالقيمة نفسها إلى منصة معروفة فاعتبره خيطًا بثقة منخفضة جدًا وليس دليلًا.")
    return L


def main(argv):
    if len(argv) >= 4 and argv[1] == "coinjoin":
        import btc_tracer
        with btc_tracer.use_chain(argv[2]):
            r = coinjoin_outputs(btc_tracer.get("/tx/" + argv[3]))
        print(json.dumps(r, ensure_ascii=False, indent=1) if r else "no group of equal-value outputs found")
        return 0
    if len(argv) >= 4 and argv[1] == "match":
        r = match_candidates(json.load(open(argv[2])), json.load(open(argv[3])))
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0
    if len(argv) >= 2:
        print("\n".join(lines(detect(json.load(open(argv[1], encoding="utf-8"))))))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
