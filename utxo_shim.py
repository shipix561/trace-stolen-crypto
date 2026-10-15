"""
utxo_shim.py - makes Dogecoin and Bitcoin Cash answer in the Esplora shape the Bitcoin tools already understand. Python 3.8+.

Source: Blockchair's public API (https://api.blockchair.com/<chain>/...). Free use is rate-limited; an optional key goes in the
BLOCKCHAIR_KEY environment variable. WRITTEN FROM MEMORY OF THE DOCUMENTATION AND NEVER RUN against the real service:
treat Dogecoin and Bitcoin Cash as experimental until `python live_check.py` shows them passing (or record a run with
`python capture.py record rec -- investigate.py doge ADDRESS --live` and send it for correction).
Translated calls: /address/<a>  /address/<a>/txs  /address/<a>/txs/chain/<last>  /tx/<id>  /tx/<id>/outspends  /blocks/tip/height
"""
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from calendar import timegm
from time import strptime

import chains

BASE = "https://api.blockchair.com"
DELAY = 1.2          # the free tier is slow: be polite
PER_PAGE = 25
_state = threading.local()


def _call(chain, path, params=None):
    q = dict(params or {})
    if os.environ.get("BLOCKCHAIR_KEY"):
        q["key"] = os.environ["BLOCKCHAIR_KEY"]
    url = "%s/%s%s%s" % (BASE, chains.get(chain)["shim_name"], path, ("?" + urllib.parse.urlencode(q)) if q else "")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tracer/0.1"}), timeout=25) as r:
                d = json.load(r)
            time.sleep(DELAY)
            return d.get("data")
        except urllib.error.HTTPError as e:
            if e.code in (402, 429, 430):
                time.sleep(3 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            time.sleep(1 + attempt)
    raise RuntimeError("request failed: " + url)


def _epoch(s):
    try:
        return timegm(strptime(s, "%Y-%m-%d %H:%M:%S"))
    except (TypeError, ValueError):
        return None


def _tx(d):
    """one Blockchair transaction record -> Esplora transaction"""
    t = d["transaction"]
    height = t.get("block_id")
    confirmed = isinstance(height, int) and height > 0
    return {"txid": t["hash"], "version": t.get("version"), "locktime": t.get("lock_time", 0),
            "status": {"confirmed": confirmed, "block_height": height if confirmed else None, "block_time": _epoch(t.get("time")) if confirmed else None},
            "vin": [{"txid": i.get("transaction_hash"), "vout": i.get("index"), "sequence": 0xffffffff,
                     "prevout": {"scriptpubkey_address": i.get("recipient"), "value": int(i.get("value") or 0), "scriptpubkey_type": i.get("type")}}
                    for i in d.get("inputs", [])],
            "vout": [{"scriptpubkey_address": o.get("recipient") if o.get("type") != "nulldata" else None, "value": int(o.get("value") or 0),
                      "scriptpubkey_type": "op_return" if o.get("type") == "nulldata" else o.get("type")} for o in d.get("outputs", [])]}


def _txs(chain, hashes):
    out = []
    for i in range(0, len(hashes), 10):
        part = hashes[i:i + 10]
        data = _call(chain, "/dashboards/transactions/" + ",".join(part))
        out += [_tx(data[h]) for h in part if h in data]
    return out


def get(chain, path):
    parts = path.strip("/").split("/")
    if parts[0] == "blocks" and parts[-1] == "height":
        return int(_call(chain, "/stats")["blocks"]) - 1
    if parts[0] == "address":
        a = parts[1]
        if len(parts) == 2:
            d = _call(chain, "/dashboards/address/" + a, {"limit": 1})[a]["address"]
            return {"chain_stats": {"tx_count": d.get("transaction_count", 0), "funded_txo_sum": d.get("received", 0), "spent_txo_sum": d.get("spent", 0)},
                    "mempool_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0}}
        seen = getattr(_state, "seen", None)
        if seen is None:
            seen = _state.seen = {}
        if len(parts) == 3:  # first page
            seen[a] = 0
        off = seen.get(a, 0)
        d = _call(chain, "/dashboards/address/" + a, {"limit": "%d,0" % PER_PAGE, "offset": "%d,0" % off})[a]
        hashes = d.get("transactions") or []
        seen[a] = off + len(hashes)
        return _txs(chain, hashes)
    if parts[0] == "tx":
        h = parts[1]
        data = _call(chain, "/dashboards/transaction/" + h)[h]
        if len(parts) == 2:
            return _tx(data)
        if parts[2] == "outspends":
            return [{"spent": bool(o.get("is_spent")), "txid": o.get("spending_transaction_id"), "vin": None,
                     "status": {"confirmed": True}} for o in data.get("outputs", [])]
    raise RuntimeError("unsupported path for this network: " + path)
