"""
evm_api.py - one reader for every EVM network (Ethereum, BNB Chain, Polygon, Arbitrum, Base). Python 3.8+.

The tools were written against the Blockscout v2 JSON shape. Each network lists its providers in chains.py; this module tries them
in order and, for an Etherscan-v2-style provider (needs a free key in the ETHERSCAN_API_KEY environment variable), translates the
answers into the Blockscout shape, so nothing else in the toolkit needs to know which provider answered.
Only Ethereum was designed against provider documentation I could check; the others are marked experimental until live_check passes.
"""
import os
import time
import urllib.error
import urllib.parse
from datetime import datetime, timezone

import chains

DELAY = 0.4
ACTIONS = {"transactions": "txlist", "token-transfers": "tokentx", "internal-transactions": "txlistinternal"}


def _http(url, headers=None):
    import acct_tracer  # late import: acct_tracer imports this module too
    return acct_tracer.http(url, headers)


def _iso(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    except (TypeError, ValueError):
        return None


def _es_call(base, chain, params, keyless=False):
    key = os.environ.get("ETHERSCAN_API_KEY")
    if not key:
        raise RuntimeError("Etherscan needs a free key in ETHERSCAN_API_KEY")
    q = dict(params, chainid=chains.get(chain)["chain_id"], apikey=key)
    d = _http(base + "?" + urllib.parse.urlencode(q))
    res = d.get("result")
    if d.get("status") == "0" and isinstance(res, str) and "No transactions" not in res and "No records" not in res:
        raise RuntimeError("Etherscan: %s" % res[:120])
    return res if isinstance(res, list) else ([] if res in (None, "") or d.get("status") == "0" else res)


def _conv(action, r):
    ts = _iso(r.get("timeStamp"))
    if action == "txlist":
        return {"hash": r["hash"], "from": {"hash": r["from"]}, "to": {"hash": r["to"]} if r.get("to") else None, "value": r.get("value", "0"),
                "status": "ok" if str(r.get("isError", "0")) == "0" else "error", "timestamp": ts}
    if action == "tokentx":
        dec = r.get("tokenDecimal") or "18"
        return {"from": {"hash": r["from"]}, "to": {"hash": r["to"]}, "transaction_hash": r["hash"], "timestamp": ts,
                "token": {"address_hash": r.get("contractAddress"), "symbol": r.get("tokenSymbol"), "decimals": dec},
                "total": {"value": r.get("value", "0"), "decimals": dec}}
    return {"from": {"hash": r["from"]}, "to": {"hash": r.get("to")}, "value": r.get("value", "0"), "success": str(r.get("isError", "0")) == "0",
            "transaction_hash": r.get("hash"), "timestamp": ts}


def pages(chain, path, params, key, max_pages):
    """(items, truncated) in Blockscout shape. path: /addresses/<a>/transactions | token-transfers | internal-transactions."""
    errs = []
    for kind, base in chains.get(chain)["providers"]:
        try:
            if kind == "blockscout":
                return _blockscout_pages(base, path, params, key, max_pages)
            m = path.strip("/").split("/")
            addr, action = m[1], ACTIONS.get(m[2])
            if not action:
                raise RuntimeError("unsupported: " + path)
            items, n = [], 0
            while n < max_pages:
                n += 1
                res = _es_call(base, chain, {"module": "account", "action": action, "address": addr, "startblock": 0, "endblock": 99999999,
                                             "page": n, "offset": 100, "sort": "desc"})
                items += [_conv(action, r) for r in res]
                time.sleep(DELAY)
                if len(res) < 100:
                    return items, False
            return items, True
        except (urllib.error.URLError, RuntimeError, ValueError, KeyError) as e:
            errs.append("%s: %s" % (kind, str(e)[:70]))
    raise RuntimeError("لا مزوّد متاح لشبكة %s (%s)" % (chains.get(chain)["name_ar"], " | ".join(errs)[:260]))


def _blockscout_pages(base, path, params, key, max_pages):
    items, params, n = [], dict(params), 0
    while True:
        q = dict(params)
        if key:
            q["apikey"] = key
        d = _http(base + path + ("?" + urllib.parse.urlencode(q) if q else ""))
        items += d.get("items", [])
        n += 1
        time.sleep(DELAY)
        nxt = d.get("next_page_params")
        if not nxt:
            return items, False
        if n >= max_pages:
            return items, True
        params.update({k: v for k, v in nxt.items() if v is not None})


def address_info(chain, addr, key=None):
    """{'coin_balance': wei-string} (Blockscout shape)."""
    errs = []
    for kind, base in chains.get(chain)["providers"]:
        try:
            if kind == "blockscout":
                return _http(base + "/addresses/" + addr + ("?apikey=" + key if key else ""))
            res = _es_call(base, chain, {"module": "account", "action": "balance", "address": addr, "tag": "latest"})
            return {"coin_balance": str(res)}
        except (urllib.error.URLError, RuntimeError, ValueError, KeyError) as e:
            errs.append("%s: %s" % (kind, str(e)[:70]))
    raise RuntimeError("لا مزوّد متاح لشبكة %s (%s)" % (chains.get(chain)["name_ar"], " | ".join(errs)[:260]))


def token_balances(chain, addr, key=None):
    """list of {'token': {'address_hash','decimals'}, 'value'} for the supported stable coins."""
    errs = []
    for kind, base in chains.get(chain)["providers"]:
        try:
            if kind == "blockscout":
                tb = _http(base + "/addresses/" + addr + "/token-balances" + ("?apikey=" + key if key else ""))
                return tb if isinstance(tb, list) else tb.get("items", [])
            out = []
            for contract in (chains.get(chain).get("stables") or {}):
                v = _es_call(base, chain, {"module": "account", "action": "tokenbalance", "contractaddress": contract, "address": addr, "tag": "latest"})
                out.append({"token": {"address_hash": contract, "decimals": chains.stable_decimals(chain, contract)}, "value": str(v)})
            return out
        except (urllib.error.URLError, RuntimeError, ValueError, KeyError) as e:
            errs.append("%s: %s" % (kind, str(e)[:70]))
    raise RuntimeError("لا مزوّد متاح لشبكة %s (%s)" % (chains.get(chain)["name_ar"], " | ".join(errs)[:260]))
