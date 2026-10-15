#!/usr/bin/env python3
"""
intake.py - start from YOUR payment transaction. Python 3.8+.

    python intake.py TXID                      show who received your payment
    python intake.py TXID --pick 1             build the full case from that receiver
    python intake.py 0xTXID --victim "Name" --contact "email" --report-no 77/2026 --pick 1

You only need the transaction hash of the payment you sent (your wallet or exchange shows it).
The tool reads the transaction on the public blockchain, lists the receiving addresses and amounts,
and, once you confirm which receiver is the scammer's address, runs the whole case builder with the
right address, the right stolen amount and the payment date.

Networks are detected from the hash: 0x + 64 hex = Ethereum; 64 hex = Bitcoin (tried first) or TRON.
Bitcoin transactions often have two receivers: the scammer and your own change coming back to you.
The smaller one is usually the change. Pick the address the scammer gave you.
"""
import argparse
import json
import os
import re
import sys
import urllib.error

import acct_tracer
import btc_tracer
import chains
import opreturn
import case_builder
import verify

ETH_RPC = "https://ethereum-rpc.publicnode.com"
TRON_NODE = "https://api.trongrid.io"


def detect_chains(txid):
    if re.fullmatch(r"0x[0-9a-fA-F]{64}", txid):
        return [c for c in chains.ORDER if chains.is_evm(c)]
    if re.fullmatch(r"[0-9a-fA-F]{64}", txid):
        return ["btc", "tron", "ltc", "doge", "bch"]
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{80,90}", txid):
        return ["sol"]
    raise ValueError("رقم المعاملة غير مفهوم: يجب أن يكون 64 خانة (وإيثريوم وأخواتها تبدأ بـ 0x، وSolana نص أطول).")


def btc_intake(txid, chain="btc"):
    with btc_tracer.use_chain(chain):
        tx = btc_tracer.get("/tx/" + txid)
    sym = chains.native(chain)
    ins = {}
    for v in tx["vin"]:
        pv = v.get("prevout") or {}
        if pv.get("scriptpubkey_address"):
            ins[pv["scriptpubkey_address"]] = ins.get(pv["scriptpubkey_address"], 0) + pv["value"]
    cands = [{"to": o["scriptpubkey_address"], "amount": o["value"] / 1e8, "asset": sym, "vout": i}
             for i, o in enumerate(tx["vout"]) if o.get("scriptpubkey_address") and o["scriptpubkey_address"] not in ins]
    cands.sort(key=lambda c: -c["amount"])
    res = {"chain": chain, "txid": txid, "time": (tx.get("status") or {}).get("block_time"),
           "senders": sorted(ins), "candidates": cands}
    for m in (opreturn.scan_tx(tx) if chain == "btc" else []):
        if m["protocol"] == "omni":
            o = m.get("omni") or {}
            res["warning"] = ("هذه معاملة Omni على بيتكوين (%s %s): المبلغ بالـ BTC رمزي والقيمة الفعلية داخل OP_RETURN، "
                              "فتتبّع BTC لا يعكس مسار الرموز." % (o.get("amount", "?"), o.get("token", "")))
        elif m["protocol"] == "runes":
            res["warning"] = "هذه معاملة Runes: قيمتها داخل OP_RETURN، وتتبّع BTC وحده لا يكفي."
    return res


def eth_intake(txid, call, chain="eth"):
    tx, rc = call("eth_getTransactionByHash", [txid]), call("eth_getTransactionReceipt", [txid])
    if not tx or not rc:
        raise ValueError("المعاملة غير موجودة على شبكة %s." % chains.get(chain)["name_ar"])
    if rc.get("status") != "0x1":
        raise ValueError("هذه المعاملة فشلت على الشبكة ولم تنتقل بها أموال.")
    cands = []
    if int(tx.get("value") or "0x0", 16) and tx.get("to"):
        cands.append({"to": tx["to"].lower(), "amount": int(tx["value"], 16) / 1e18, "asset": chains.native(chain)})
    for lg in rc.get("logs", []):
        t = lg.get("topics", [])
        ca = (lg.get("address") or "").lower()
        sym = acct_tracer.STABLES[chain].get(ca)
        if len(t) == 3 and t[0].lower() == verify.TRANSFER_TOPIC and sym:
            cands.append({"to": ("0x" + t[2][-40:]).lower(), "asset": sym, "from": ("0x" + t[1][-40:]).lower(),
                          "amount": int(lg["data"], 16) / 10 ** chains.stable_decimals(chain, ca, verify.ERC20_DEC.get(sym, 6))})
    when = None
    try:
        when = int(call("eth_getBlockByNumber", [rc["blockNumber"], False])["timestamp"], 16)
    except Exception:
        pass
    return {"chain": chain, "txid": txid, "time": when, "senders": [tx["from"].lower()], "candidates": cands}


def tron_intake(txid, post):
    tx = post("/wallet/gettransactionbyid", {"value": txid})
    if not tx or not tx.get("raw_data"):
        raise ValueError("المعاملة غير موجودة على شبكة TRON.")
    if ((tx.get("ret") or [{}])[0].get("contractRet") or "SUCCESS") != "SUCCESS":
        raise ValueError("هذه المعاملة فشلت على الشبكة.")
    c = tx["raw_data"]["contract"][0]
    v, b58 = c["parameter"]["value"], acct_tracer.hex_to_tron
    if c["type"] == "TransferContract":
        cands = [{"to": b58(v["to_address"]), "amount": v["amount"] / 1e6, "asset": "TRX"}]
    else:
        d = v.get("data", "")
        sym = acct_tracer.STABLES["tron"].get(b58(v.get("contract_address", "41" + "00" * 20))) if v.get("contract_address") else None
        if c["type"] != "TriggerSmartContract" or not d.startswith("a9059cbb") or not sym:
            raise ValueError("نوع المعاملة غير مدعوم بعد (المدعوم: TRX وUSDT المباشر).")
        cands = [{"to": b58("41" + d[32:72]), "amount": int(d[72:136], 16) / 1e6, "asset": sym}]
    ts = tx["raw_data"].get("timestamp")
    return {"chain": "tron", "txid": txid, "time": ts // 1000 if ts else None,
            "senders": [b58(v["owner_address"])], "candidates": cands}


def find(txid, chain="auto", eth_rpc=ETH_RPC, tron_node=TRON_NODE, call=None, post=None):
    txid = (txid or "").strip()
    tries = detect_chains(txid) if chain == "auto" else [chain]
    errors = []
    for ch in tries:
        try:
            if chains.is_utxo(ch):
                res = btc_intake(txid, ch)
            elif chains.is_evm(ch):
                res = eth_intake(txid, call or verify.make_rpc(eth_rpc if ch == "eth" else chains.get(ch)["rpc"]), ch)
            elif ch == "sol":
                import sol_api
                res = sol_api.intake_sol(txid)
            else:
                res = tron_intake(txid, post or verify.make_post(tron_node))
            res["time_str"] = case_builder.fmt_time(res["time"]) if res.get("time") else ""
            if not res["candidates"]:
                raise ValueError("لم أجد مستلمين في هذه المعاملة.")
            return res
        except urllib.error.HTTPError:
            errors.append("%s: المعاملة غير موجودة" % ch)
        except ValueError as e:
            errors.append("%s: %s" % (ch, e))
        except Exception as e:
            errors.append("%s: تعذّر الاتصال (%s)" % (ch, str(e)[:60]))
    raise ValueError("تعذّرت قراءة المعاملة. " + " | ".join(errors))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("txid")
    ap.add_argument("--chain", choices=["auto"] + chains.ORDER, default="auto")
    ap.add_argument("--pick", type=int, default=None, help="number of the receiver that is the scammer")
    ap.add_argument("--depth", type=int, default=None, help="default: 6 for Bitcoin (UTXO trace), 3 otherwise")
    ap.add_argument("--victim")
    ap.add_argument("--contact")
    ap.add_argument("--report-no")
    ap.add_argument("--labels", default="labels.json")
    ap.add_argument("--out", default="cases")
    ap.add_argument("--eth-rpc", default=ETH_RPC)
    ap.add_argument("--tron-node", default=TRON_NODE)
    ap.add_argument("--api-key", default=os.environ.get("TRACER_API_KEY"))
    a = ap.parse_args()
    try:
        res = find(a.txid, a.chain, a.eth_rpc, a.tron_node)
    except ValueError as e:
        sys.exit(str(e))
    print("الشبكة: %s | وقت المعاملة: %s | المرسِل: %s" % (res["chain"].upper(), res["time_str"] or "غير معروف", ", ".join(res["senders"])))
    if res.get("warning"):
        print("تنبيه:", res["warning"])
    for i, c in enumerate(res["candidates"], 1):
        print("  %d) %s  %s %s" % (i, c["to"], c["amount"], c["asset"]))
    pick = a.pick if a.pick else (1 if len(res["candidates"]) == 1 else None)
    if not pick:
        print("\nأي مستلم هو عنوان المحتال؟ أعد التشغيل مع --pick رقم_المستلم")
        return
    c = res["candidates"][pick - 1]
    labels = json.load(open(a.labels, encoding="utf-8")) if os.path.exists(a.labels) else {}
    params = {"victim": a.victim, "contact": a.contact, "report_no": a.report_no, "txid": res["txid"],
              "stolen": c["amount"], "asset": c["asset"], "incident": res["time_str"] or None,
              "vout": c.get("vout")}
    out = case_builder.run_case(res["chain"], c["to"], a.depth or (6 if chains.is_utxo(res["chain"]) else 3), c["amount"] if chains.is_utxo(res["chain"]) else None,
                                labels, a.out, params, a.api_key)
    print("\n" + out["summary"])
    print("\nSaved to", out["folder"], "(%d letters)" % len(out["letters"]))


if __name__ == "__main__":
    main()
