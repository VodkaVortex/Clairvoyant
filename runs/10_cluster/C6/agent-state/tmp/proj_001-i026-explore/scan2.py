#!/usr/bin/env python3
"""Robust per-file function extraction via brace matching from line 0,
then list functions containing head-relocating calls, with the call line numbers."""
import os, re, sys

ROOT = "."
RELOC = re.compile(r"\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|ip_mc_may_pull|ipv6_mc_may_pull)\s*\(")
KW = {"if","for","while","switch","return","sizeof","else","do","case","__init","EXPORT_SYMBOL","EXPORT_SYMBOL_GPL","MODULE","DEFINE"}

def parse(text):
    """Return list of (name, startline, endline) where the function name may be None."""
    n = len(text)
    i = 0
    out = []
    # Precompute line starts
    line_starts = [0]
    for k in range(n):
        if text[k] == "\n":
            line_starts.append(k+1)
    def lineof(pos):
        import bisect
        return bisect.bisect_right(line_starts, pos)
    while i < n:
        b = text.find("{", i)
        if b == -1:
            break
        # find preceding text for signature: from last ';' or '}' or start before b
        start_sig = max(text.rfind(";", i-2, b), text.rfind("}", i-2, b), text.rfind("{", i-2, b))
        # actually search backwards from b over preceding lines up to 400 chars for '('
        lo = max(0, b - 400)
        sig = text[lo:b]
        # last newline before b:
        nl = sig.rfind("\n")
        # gather signature lines: from the line that contains the first '(' going back while lines look like continuation
        sig_lines = []
        pos = b - 1
        # walk back to capture up to 5 lines that are part of signature (contain identifiers/parens, end with ')')
        # Simple approach: take text from the last occurrence of ")\n" before b plus following line
        m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text[lo:b])
        # take last identifier followed by ( in the sig region
        names = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text[lo:b])
        names = [x for x in names if x not in KW]
        fname = names[-1] if names else None
        # brace match
        depth = 0
        k = b
        while k < n:
            c = text[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append((fname, lineof(b), lineof(k)))
                    i = k + 1
                    break
            k += 1
        else:
            break
        if k >= n:
            break
    return out

files = []
for base in ("net", "drivers"):
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, base)):
        for f in filenames:
            if f.endswith(".c"):
                files.append(os.path.join(dirpath, f))

out = open(sys.argv[1], "w")
cnt = 0
for path in files:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    # strip comments/strings crudely to avoid brace confusion? keep simple; risk minor misparse
    funcs = parse(text)
    for (name, s, e) in funcs:
        body_lines = text.split("\n")[s-1:e]
        calls = []
        for idx, ln in enumerate(body_lines):
            if RELOC.search(ln):
                calls.append(s + idx)
        if calls and name:
            cnt += 1
            out.write(f"{path}\t{name}\t{s}\t{e}\t{','.join(map(str,calls))}\n")
out.close()
print(cnt, "functions")
