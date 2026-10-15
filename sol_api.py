"""
sol_api.py - Solana support: read a payment, list what an address sent and received, balances. Python 3.8+.

Works from transaction effects (balance changes), not from instruction types, so ordinary SOL and SPL-token (USDT/USDC) transfers
are read the same way. Limits, stated plainly: swaps, staking and programs that move funds through intermediate accounts show
as several transfers; the sender of a multi-sender transaction is taken to be the account that lost the most.
WRITTEN FROM MEMORY OF THE JSON-RPC DOCUMENTATION AND NEVER RUN against a real node: experimental until live_check passes.
Public nodes limit request rates hard; set SOLANA_RPC to your own endpoint when you have one.
"""
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import chains

DELAY = 0.25
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
MAX_SIGS = 100


def rpc(method, params):
    cfg = chains.get("sol")
    urls = [u for u in (os.environ.get("SOLANA_RPC"), cfg["rpc"], cfg["rpc_fallback"]) if u]
    last = None
    for url in urls:
        for attempt in range(3):
            try:
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
                req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "tracer/0.1"})
                with urllib.request.urlopen(req, timeout=25) as r:
                    d = json.load(r)
                time.sleep(DELAY)
                if d.get("error"):
                    raise RuntimeError(str(d["error"].get("message"))[:120])
                return d.get("result")
            except urllib.error.HTTPError as e:
                last = e
                if e.code == 429:
                    time.sleep(2 * (attempt + 1))
                    continue
                break
            except (urllib.error.URLError, RuntimeError, ValueError) as e:
                last = e
                time.sleep(1 + attempt)
    raise RuntimeError("تعذّر الاتصال بعقدة Solana (%s)" % str(last)[:100])


def _sym(mint, all_tokens=False):
    s = chains.stables("sol").get(mint)
    if s:
        return s
    return (mint[:6] + "…") if all_tokens else None


def transfers(tx, sig, all_tokens=False):
    """list of dict(frm, to, asset, amount, txid, time) read from the balance changes of one parsed transaction."""
    if not tx or (tx.get("meta") or {}).get("err") is not None:
        return []
    meta, msg = tx["meta"], tx["transaction"]["message"]
    keys = [k["pubkey"] if isinstance(k, dict) else k for k in msg["accountKeys"]]
    delta = {}   # asset -> {owner: change}
    fee = meta.get("fee", 0)
    for i, (a, b) in enumerate(zip(meta.get("preBalances", []), meta.get("postBalances", []))):
        d = b - a + (fee if i == 0 else 0)  # the fee payer's own change excludes the fee
        if d:
            delta.setdefault("SOL", {})[keys[i]] = delta.get("SOL", {}).get(keys[i], 0) + d / 1e9
    toks = {}
    for kind, sign in (("preTokenBalances", -1), ("postTokenBalances", 1)):
        for t in meta.get(kind) or []:
            sym = _sym(t.get("mint"), all_tokens)
            if not sym:
                continue
            ui = t.get("uiTokenAmount") or {}
            amt = int(ui.get("amount") or 0) / 10 ** int(ui.get("decimals") or 0)
            owner = t.get("owner") or keys[t["accountIndex"]]
            toks.setdefault(sym, {})[owner] = toks.get(sym, {}).get(owner, 0) + sign * amt
    for sym, owners in toks.items():
        delta[sym] = {o: v for o, v in owners.items() if abs(v) > 0}
    when = tx.get("blockTime")
    ts = datetime.fromtimestamp(when, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if when else None
    out = []
    for asset, d in delta.items():
        senders = sorted(((v, o) for o, v in d.items() if v < 0))
        if not senders:
            continue
        frm = senders[0][1]
        for o, v in d.items():
            if v > 1e-9 and o != frm:
                out.append(dict(frm=frm, to=o, asset=asset, amount=v, txid=sig, time=ts, ts=when))
    return out


def get_tx(sig):
    return rpc("getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 255}])


def history(addr, a=None):
    """(transfers touching addr, busy). Looks at the most recent MAX_SIGS signatures."""
    lim = min(MAX_SIGS, 25 * max(1, getattr(a, "max_pages", 4)))
    sigs = rpc("getSignaturesForAddress", [addr, {"limit": lim}]) or []
    out = []
    for s in sigs:
        if s.get("err") is not None:
            continue
        for t in transfers(get_tx(s["signature"]), s["signature"], bool(getattr(a, "all_tokens", False))):
            if t["frm"] == addr or t["to"] == addr:
                out.append(t)
    return out, len(sigs) >= lim


def sol_out(addr, a):
    """same contract as acct_tracer.eth_out: (outgoing transfers [to, asset, amount, txid, time], busy)"""
    allt, busy = history(addr, a)
    return [dict(to=t["to"], asset=t["asset"], amount=t["amount"], txid=t["txid"], time=t["time"]) for t in allt if t["frm"] == addr], busy


def collect_sol(addr, a):
    """rows for wallet_profile / operation / payments: (rows, info, truncated)"""
    allt, busy = history(addr, a)
    rows = []
    for t in allt:
        if t["frm"] == addr:
            rows.append(dict(dir="out", other=t["to"], asset=t["asset"], amount=t["amount"], txid=t["txid"], ts=t["ts"]))
        else:
            rows.append(dict(dir="in", other=t["frm"], asset=t["asset"], amount=t["amount"], txid=t["txid"], ts=t["ts"]))
    return rows, {}, busy


def intake_sol(sig):
    tx = get_tx(sig)
    if not tx:
        raise ValueError("المعاملة غير موجودة على شبكة Solana.")
    if (tx.get("meta") or {}).get("err") is not None:
        raise ValueError("هذه المعاملة فشلت على الشبكة ولم تنتقل بها أموال.")
    ts = transfers(tx, sig)
    cands = sorted(({"to": t["to"], "amount": t["amount"], "asset": t["asset"]} for t in ts if t["amount"] >= 1e-6),
                   key=lambda c: -c["amount"])
    return {"chain": "sol", "txid": sig, "time": tx.get("blockTime"), "senders": sorted({t["frm"] for t in ts}), "candidates": cands}


def fetch_balance(addr):
    out = {"SOL": (rpc("getBalance", [addr]) or {}).get("value", 0) / 1e9}
    accts = rpc("getTokenAccountsByOwner", [addr, {"programId": TOKEN_PROGRAM}, {"encoding": "jsonParsed"}]) or {}
    for it in accts.get("value", []):
        info = (((it.get("account") or {}).get("data") or {}).get("parsed") or {}).get("info") or {}
        sym = chains.stables("sol").get(info.get("mint"))
        if sym:
            out[sym] = out.get(sym, 0) + float((info.get("tokenAmount") or {}).get("uiAmount") or 0)
    return out
