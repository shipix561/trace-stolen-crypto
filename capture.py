#!/usr/bin/env python3
"""
capture.py - record the REAL answers of the blockchain providers, and replay them later. Python 3.8+.

Why: the tools were tested on invented data. The fastest way to make them trustworthy is to run them once on the real
networks with a recorder on, and give the recording to whoever fixes them (or replay it yourself, offline, any time).

    python capture.py record rec -- investigate.py btc ADDRESS --live       record a run of ANY tool
    python capture.py record rec -- live_check.py                           record the live check
    python capture.py replay rec -- investigate.py btc ADDRESS --live       run it again offline against the recording
    python capture.py inspect rec                                           what is inside (hosts, statuses, sizes)
    python capture.py pack rec                                              rec.zip, ready to send

(live_check.py also has --record DIR and --replay DIR.)

What is recorded: only answers of the public blockchain providers (blockstream.info, mempool.space, Blockscout,
TronGrid, TronScan, publicnode). Never: API keys (removed from every URL, headers are not stored), Chainabuse
(its answers list contact details of accused people), website scans, notifications (ntfy), or any other host.
The recording does contain the ADDRESSES and TRANSACTIONS you looked up: they are public on the chain, but they show
what you investigated, so send the zip only to someone you trust with that. Open manifest.json to see every request.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import runpy
import shutil
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SAFE_HOSTS = {"blockstream.info", "mempool.space", "eth.blockscout.com", "api.trongrid.io", "apilist.tronscanapi.com",
              "ethereum-rpc.publicnode.com", "litecoinspace.org", "api.blockchair.com", "api.etherscan.io", "api.routescan.io",
              "bsc.blockscout.com", "polygon.blockscout.com", "arbitrum.blockscout.com", "base.blockscout.com",
              "bsc-rpc.publicnode.com", "polygon-bor-rpc.publicnode.com", "arbitrum-one-rpc.publicnode.com", "base-rpc.publicnode.com",
              "solana-rpc.publicnode.com", "api.mainnet-beta.solana.com"}
SECRET_PARAMS = {"apikey", "api_key", "key", "token", "access_token", "secret", "auth"}
MAX_ITEMS, MAX_BYTES = 6000, 120 * 1024 * 1024
README = ("Recording of real provider answers made with capture.py.\n"
          "manifest.json lists every request. NNNN.json holds one request and its answer. API keys are removed.\n"
          "It contains the public addresses and transactions that were looked up: send it only to someone you trust with that.\n"
          "Replay: python capture.py replay <this folder> -- <script> <args>\n")


def redact_url(url):
    p = urllib.parse.urlsplit(url)
    q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True) if k.lower() not in SECRET_PARAMS]
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(q), ""))


def norm_body(body):
    """JSON bodies compare without their request 'id' (a counter), anything else byte for byte."""
    if not body:
        return ""
    raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
    try:
        d = json.loads(raw)
        if isinstance(d, dict):
            d.pop("id", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":"))
    except ValueError:
        return base64.b64encode(raw).decode()


def request_key(method, url, body):
    return hashlib.sha256(("%s\n%s\n%s" % (method.upper(), redact_url(url), norm_body(body))).encode("utf-8")).hexdigest()


def _split(url, args, kw):
    data = args[0] if args else kw.get("data")
    if isinstance(url, str):
        return url, ("POST" if data else "GET"), data
    return url.full_url, url.get_method(), (url.data if url.data is not None else data)


class Resp(io.BytesIO):
    """What urlopen returns: readable, a context manager, with status and headers."""

    def __init__(self, body, status=200, headers=None, url=""):
        super().__init__(body)
        self.status, self.code, self.headers, self.url = status, status, headers or {}, url

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def info(self):
        return self.headers


class _Base:
    def __init__(self, folder):
        self.dir, self._orig, self.lock = folder, None, threading.Lock()

    def install(self):
        if self._orig is not None:
            return
        self._orig = urllib.request.urlopen
        urllib.request.urlopen = self._urlopen

    def uninstall(self):
        if self._orig is not None:
            urllib.request.urlopen = self._orig
            self._orig = None

    def __enter__(self):
        self.install()
        return self

    def __exit__(self, *exc):
        self.uninstall()
        if hasattr(self, "finish"):
            self.finish()
        return False


class Capture(_Base):
    def __init__(self, folder, hosts=None):
        super().__init__(folder)
        self.hosts = set(SAFE_HOSTS if hosts is None else hosts)
        self.items, self.bytes, self.stopped = [], 0, False
        os.makedirs(folder, exist_ok=True)

    def _save(self, method, url, body, status, ctype, raw, error=None):
        with self.lock:
            if self.stopped or len(self.items) >= MAX_ITEMS or self.bytes + len(raw or b"") > MAX_BYTES:
                self.stopped = True
                return
            n = len(self.items) + 1
            try:
                text, b64 = (raw or b"").decode("utf-8"), None
            except UnicodeDecodeError:
                text, b64 = None, base64.b64encode(raw).decode()
            btxt = None
            if body:
                try:
                    btxt = (body if isinstance(body, bytes) else str(body).encode()).decode("utf-8")
                except UnicodeDecodeError:
                    btxt = None
            rec = {"n": n, "method": method, "url": redact_url(url), "body": btxt, "status": status, "content_type": ctype,
                   "response": text, "response_b64": b64, "error": error, "sha256": hashlib.sha256(raw or b"").hexdigest(),
                   "key": request_key(method, url, body), "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            with open(os.path.join(self.dir, "%04d.json" % n), "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False)
            self.bytes += len(raw or b"")
            self.items.append({k: rec[k] for k in ("n", "method", "url", "status", "error", "sha256", "key")})

    def _urlopen(self, url, *args, **kw):
        full, method, body = _split(url, args, kw)
        host = urllib.parse.urlsplit(full).hostname
        if host not in self.hosts:
            return self._orig(url, *args, **kw)
        try:
            r = self._orig(url, *args, **kw)
        except urllib.error.HTTPError as e:
            raw = e.read() or b""
            self._save(method, full, body, e.code, (e.headers or {}).get("Content-Type"), raw)
            raise urllib.error.HTTPError(full, e.code, e.msg, e.headers, io.BytesIO(raw))
        except Exception as e:  # network failure: recorded too, it says why a run failed
            self._save(method, full, body, None, None, b"", error="%s: %s" % (type(e).__name__, str(e)[:200]))
            raise
        raw = r.read()
        status = getattr(r, "status", 200)
        ctype = r.headers.get("Content-Type") if getattr(r, "headers", None) else None
        self._save(method, full, body, status, ctype, raw)
        return Resp(raw, status, r.headers, full)

    def finish(self):
        man = {"version": 1, "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "hosts": sorted(self.hosts),
               "count": len(self.items), "bytes": self.bytes, "truncated": self.stopped, "items": self.items}
        with open(os.path.join(self.dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=1)
        with open(os.path.join(self.dir, "README.txt"), "w", encoding="utf-8") as f:
            f.write(README)
        return man


class Replay(_Base):
    def __init__(self, folder):
        super().__init__(folder)
        self.map, self.misses = {}, []
        if not os.path.exists(os.path.join(folder, "manifest.json")):
            raise ValueError("لا يوجد تسجيل في %s (manifest.json مفقود)." % folder)
        for name in sorted(os.listdir(folder)):
            if name[:4].isdigit() and name.endswith(".json"):
                rec = json.load(open(os.path.join(folder, name), encoding="utf-8"))
                self.map[rec["key"]] = rec  # the last answer recorded for a request wins (after retries it is the good one)

    def _urlopen(self, url, *args, **kw):
        full, method, body = _split(url, args, kw)
        rec = self.map.get(request_key(method, full, body))
        if rec is None:
            self.misses.append("%s %s" % (method, redact_url(full)))
            raise urllib.error.URLError("capture replay: request not in the recording: %s %s" % (method, redact_url(full)))
        if rec.get("error"):
            raise urllib.error.URLError("recorded failure: %s" % rec["error"])
        raw = base64.b64decode(rec["response_b64"]) if rec.get("response_b64") else (rec.get("response") or "").encode("utf-8")
        hdrs = {"Content-Type": rec.get("content_type") or "application/json"}
        if rec["status"] and rec["status"] >= 400:
            raise urllib.error.HTTPError(full, rec["status"], "recorded", hdrs, io.BytesIO(raw))
        return Resp(raw, rec["status"] or 200, hdrs, full)


def pack(folder):
    if not os.path.exists(os.path.join(folder, "manifest.json")):
        raise ValueError("لا يوجد تسجيل في %s." % folder)
    return shutil.make_archive(folder.rstrip("/\\"), "zip", folder)


def inspect(folder):
    man = json.load(open(os.path.join(folder, "manifest.json"), encoding="utf-8"))
    by = {}
    for it in man["items"]:
        h = urllib.parse.urlsplit(it["url"]).hostname
        d = by.setdefault(h, {"requests": 0, "statuses": {}})
        d["requests"] += 1
        d["statuses"][str(it["status"] or it["error"] or "?")] = d["statuses"].get(str(it["status"] or it["error"] or "?"), 0) + 1
    return {"count": man["count"], "bytes": man["bytes"], "truncated": man.get("truncated", False), "hosts": by, "created": man["created"]}


def run_script(script, args):
    path = script if os.path.exists(script) else (script + ".py" if os.path.exists(script + ".py") else
                                                  os.path.join(os.path.dirname(os.path.abspath(__file__)), script))
    if not os.path.exists(path) and os.path.exists(path + ".py"):
        path += ".py"
    if not os.path.exists(path):
        raise ValueError("السكربت غير موجود: %s" % script)
    sys.argv = [path] + list(args)
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))
    try:
        runpy.run_path(path, run_name="__main__")
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)


def main():
    argv = sys.argv[1:]
    rest = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["record", "replay", "inspect", "pack"])
    ap.add_argument("dir")
    ap.add_argument("--host", action="append", default=[], help="record one more host (the default list is the public blockchain providers)")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "inspect":
            print(json.dumps(inspect(a.dir), ensure_ascii=False, indent=1))
            return
        if a.cmd == "pack":
            print("تم: " + pack(a.dir))
            return
        if not rest:
            sys.exit("اكتب الأمر بعد --، مثال: python capture.py %s %s -- investigate.py btc ADDRESS --live" % (a.cmd, a.dir))
        if a.cmd == "record":
            cap = Capture(a.dir, SAFE_HOSTS | set(a.host))
            with cap:
                code = run_script(rest[0], rest[1:])
            print("\nسُجّل %d ردًّا في %s (الأسرار محذوفة)%s. للإرسال: python capture.py pack %s" % (
                len(cap.items), a.dir, " (توقف التسجيل عند الحد الأقصى)" if cap.stopped else "", a.dir))
            sys.exit(code)
        rp = Replay(a.dir)
        with rp:
            code = run_script(rest[0], rest[1:])
        if rp.misses:
            print("\nطلبات غير موجودة في التسجيل (%d):" % len(rp.misses))
            for m in sorted(set(rp.misses))[:20]:
                print("  " + m)
        sys.exit(code)
    except ValueError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
