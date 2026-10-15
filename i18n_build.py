#!/usr/bin/env python3
"""Build/check the multilingual dictionary embedded in index.html.

Arabic is the source language of the UI. Every Arabic fragment found in index.html
(outside the generated block) must have a row in i18n/translations.tsv:
    arabic_fragment<TAB>en<TAB>es<TAB>fr<TAB>tr<TAB>ru<TAB>fa

    python i18n_build.py --check     # list missing / unused fragments
    python i18n_build.py --write     # rewrite the block inside index.html
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(HERE, "index.html")
TSV = os.path.join(HERE, "i18n", "translations.tsv")
LANGS = ["en", "es", "fr", "tr", "ru", "fa"]
START, END = "/*I18N-START*/", "/*I18N-END*/"
L = "\u0621-\u064A\u0671-\u06D3"
AR = re.compile("[" + L + "]")


def core(t):
    """The Arabic part of a fragment: from its first Arabic letter to the end of the
    text node, without surrounding markup (cut at a quote or tag) or opening brackets."""
    t = t.replace("\\n", "\n").replace("\\'", "'")
    m = AR.search(t)
    if not m:
        return ""
    t = t[m.start():]
    t = re.split(r'["<>]', t, maxsplit=1)[0]
    return t.rstrip(" \t\r\n(|'،,")


LEAD = " \t\r\n\"'<>|()⬅➡◀⚠،,"
TRAIL = " \t\r\n\"'<>|(،,"


def tr_clean(t):
    return t.replace("\\n", "\n").lstrip(LEAD).rstrip(TRAIL)


def split_html(s):
    if START in s:
        a, rest = s.split(START, 1)
        _, b = rest.split(END, 1)
        return a, b
    return s, ""


def extract(html):
    """Unique Arabic cores used by the page, in first-seen order."""
    a, b = split_html(html)
    s = a + b
    head, rest = s.split("<script>", 1)
    js, tail = rest.split("</script>", 1)
    js = "\n".join(x for x in js.split("\n") if not x.startswith("const LANGS="))
    frags = []

    def add(t):
        t = re.sub(r"\s+", " ", t).strip() if "\\n" not in t else t.strip()
        c = core(t)
        if c:
            frags.append(c)

    page = re.sub(r"<style>.*?</style>", "", head, flags=re.S)
    for m in re.finditer(r">([^<>]+)<", page + "<"):
        add(m.group(1))
    for m in re.finditer(r'(?:placeholder|title|aria-label|alt)="([^"]*)"', page):
        add(m.group(1))
    for m in re.finditer(r"'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"", js):
        lit = m.group(1) if m.group(1) is not None else m.group(2)
        if not AR.search(lit):
            continue
        for seg in re.split(r"<[^>]*>", lit):
            add(seg)
    for m in re.finditer(r">([^<>]+)<", tail):
        add(m.group(1))
    seen = []
    for f in frags:
        if f not in seen:
            seen.append(f)
    return seen


def load_tsv(path=TSV):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            p = line.split("\t")
            if len(p) != 1 + len(LANGS):
                raise ValueError("%s:%d: expected %d columns, got %d" % (path, ln, 1 + len(LANGS), len(p)))
            rows[core(p[0]) or p[0]] = [tr_clean(x) for x in p[1:]]
    return rows


def dictionary(rows):
    d = {l: {} for l in LANGS}
    for k, vals in rows.items():
        for l, v in zip(LANGS, vals):
            if v:
                d[l][k] = v
    return d


def check(html=None, rows=None):
    html = html if html is not None else open(HTML, encoding="utf-8").read()
    rows = rows if rows is not None else load_tsv()
    need = extract(html)
    missing = [k for k in need if k not in rows]
    unused = [k for k in rows if k not in need]
    empty = [(k, l) for k, v in rows.items() for l, x in zip(LANGS, v) if not x]
    return missing, unused, empty


def build(html, rows):
    d = dictionary(rows)
    block = START + "const I18N=" + json.dumps(d, ensure_ascii=False, separators=(",", ":")) + ";" + END
    if START in html:
        a, rest = html.split(START, 1)
        _, b = rest.split(END, 1)
        return a + block + b
    return html.replace("<script>", "<script>\n" + block, 1)


if __name__ == "__main__":
    html = open(HTML, encoding="utf-8").read()
    rows = load_tsv()
    miss, unused, empty = check(html, rows)
    if "--write" in sys.argv:
        open(HTML, "w", encoding="utf-8").write(build(html, rows))
        print("written;", len(rows), "entries")
    for k in miss:
        print("MISSING:", k)
    for k in unused:
        print("unused:", k)
    for k, l in empty:
        print("EMPTY:", l, k)
    sys.exit(1 if miss or empty else 0)
