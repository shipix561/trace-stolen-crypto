#!/usr/bin/env python3
"""
opreturn.py - read the data embedded in Bitcoin transactions (OP_RETURN). Python 3.8+.

    python opreturn.py TXID          decode the OP_RETURN outputs of one transaction

Why it matters in a fraud case:
  - Some scams (and many marketing spams) write a message, link or contact handle into the chain.
  - Omni-layer transactions move USDT (and other tokens) over Bitcoin: the BTC amount is a tiny
    "dust" output and the real value is inside OP_RETURN. A trace in BTC terms would be wrong.
  - Runes transactions are also encoded in OP_RETURN.

Everything extracted is public blockchain data. Links and handles are leads to check (site_scan.py
for links), not proof about who wrote them.
"""
import argparse
import re
import sys

URL_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>]{4,}", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TG_RE = re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_+]{3,})", re.I)
OMNI_PROPERTIES = {31: "USDT"}


def pushes(raw):
    """Data pushes that follow OP_RETURN (0x6a)."""
    out, i = [], 1
    while i < len(raw):
        op = raw[i]
        if 1 <= op <= 75:
            n, i = op, i + 1
        elif op == 0x4c and i + 1 < len(raw):
            n, i = raw[i + 1], i + 2
        elif op == 0x4d and i + 2 < len(raw):
            n, i = int.from_bytes(raw[i + 1:i + 3], "little"), i + 3
        else:
            break
        out.append(raw[i:i + n])
        i += n
    return out


def printable(data):
    try:
        t = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(c.isprintable() or c in "\n\t" for c in t)
    return t.strip() if t and ok / len(t) >= 0.85 else None


def omni(data):
    if len(data) >= 20 and data[:4] == b"omni" and int.from_bytes(data[6:8], "big") == 0:
        prop = int.from_bytes(data[8:12], "big")
        return {"property": prop, "token": OMNI_PROPERTIES.get(prop, "property %d" % prop),
                "amount": int.from_bytes(data[12:20], "big") / 1e8}
    return None


def scan_tx(tx):
    res = []
    for i, o in enumerate(tx.get("vout", [])):
        if o.get("scriptpubkey_type") != "op_return":
            continue
        try:
            raw = bytes.fromhex(o.get("scriptpubkey") or "")
        except ValueError:
            continue
        data = b"".join(pushes(raw))
        item = {"txid": tx.get("txid"), "vout": i, "protocol": None, "hex": data.hex()[:160]}
        if data.startswith(b"omni"):
            item["protocol"] = "omni"
            item["omni"] = omni(data)
        elif raw[:2] == bytes([0x6a, 0x5d]):
            item["protocol"] = "runes"
        text = printable(data) if item["protocol"] is None else None
        if text:
            item["text"] = text[:300]
            for key, found in (("urls", URL_RE.findall(text)), ("emails", EMAIL_RE.findall(text)), ("telegram", TG_RE.findall(text))):
                if found:
                    item[key] = sorted(set(found))
        res.append(item)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("txid")
    a = ap.parse_args()
    import btc_tracer
    found = scan_tx(btc_tracer.get("/tx/" + a.txid))
    for m in found:
        print(m)
    if not found:
        print("(no OP_RETURN data in this transaction)")


if __name__ == "__main__":
    main()
