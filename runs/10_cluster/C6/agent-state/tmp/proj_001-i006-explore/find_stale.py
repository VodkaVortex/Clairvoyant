#!/usr/bin/env python3
"""Find candidate RX-path stale-header-pointer-after-pull bugs.

Heuristic: within each function body of net/*.c files that call a
pull/linearize API, find:
  1) a capture of a pointer from skb->data / skb_header_pointer /
     <hdr accessor>(skb) / skb_network_header etc, assigned to a variable
  2) a later pull call (pskb_may_pull / pskb_pull / __pskb_pull_tail /
     skb_linearize / pskb_pull_reserve / pskb_may_pull)
  3) a later dereference of the captured variable (var->field or var[...]
     or *var or var passed as arg to some calls)
where the deref occurs AFTER the pull and there is no re-assignment of the
variable between pull and deref.
"""
import re, os, sys, subprocess

ROOT = "net"
PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|pskb_pull_reserve|skb_linearize)\s*\(')
CAPTURE_RE = re.compile(
    r'^\s*(?:const\s+)?(?:struct\s+)?[\w]+\s*\*+\s*(\w+)\s*=\s*'
    r'(.*(?:skb_header_pointer|skb->data|_hdr\s*\(\s*skb|_header\s*\(\s*skb).*)$')
DEREF_RE = re.compile(r'(\w+)\s*(->|\[)')
IDENT_RE = re.compile(r'\b(\w+)\b')

def func_iter(src):
    """Yield (name, startline_idx, body_lines) using brace matching."""
    lines = src.split('\n')
    funcstart = re.compile(r'^(\w[\w \t\*]*)\(([^;]*)\)\s*\n?\{', re.M)
    for m in funcstart.finditer(src):
        # find opening brace
        bidx = src.find('{', m.start())
        # count braces
        depth = 0
        i = bidx
        while i < len(src):
            if src[i] == '{': depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[bidx:i+1]
        startline = src[:bidx].count('\n')
        name_m = re.match(r'\w[\w \t\*]*?(\w+)\s*\(', m.group(0))
        name = name_m.group(1) if name_m else '?'
        yield name, startline, body

def line_of(body, idx, offset):
    return offset + body[:idx].count('\n') + 1

def scan_file(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    out = []
    for fname, off, body in func_iter(src):
        if not PULL_RE.search(body):
            continue
        # collect captures with positions
        captures = []
        for m in re.finditer(r'(?m)^(.*)$', body):
            line = m.group(1)
            cm = CAPTURE_RE.match(line)
            if cm:
                captures.append((cm.group(1), m.start(), line.strip()))
        if not captures:
            continue
        # collect pull calls with positions
        pulls = [(m.start(), m.group(0)) for m in PULL_RE.finditer(body)]
        for var, cpos, cline in captures:
            # strip strings/comments crudely for deref scan
            for ppos, pcall in pulls:
                if ppos <= cpos:
                    continue
                # search for deref after pull, before any reassignment of var
                rest = body[ppos:]
                # find first reassignment of var
                reass = re.search(r'(?m)^\s*(?:.*[^\w&])' + re.escape(var) + r'\s*=[^=]', rest)
                reass_pos = reass.start() if reass else len(rest)
                # find derefs of var in rest before reass
                seg = rest[:reass_pos]
                dm = re.search(r'\b' + re.escape(var) + r'\s*(->|\[)', seg)
                if dm:
                    # skip self-reassignment-like capture
                    dline = off + body[:ppos].count('\n') + rest[:dm.start()].count('\n') + 1
                    out.append((path, fname, var, cline,
                                off + body[:cpos].count('\n') + 1,
                                pcall.split('(')[0], dline,
                                seg[max(0,dm.start()-60):dm.end()+60].replace('\n',' ')))
    return out

results = []
for dirpath, dirs, files in os.walk(ROOT):
    for f in files:
        if f.endswith('.c'):
            p = os.path.join(dirpath, f)
            try:
                results.extend(scan_file(p))
            except Exception as e:
                print(f"ERR {p}: {e}", file=sys.stderr)

for r in results:
    print(f"{r[0]} :: {r[1]} :: var={r[2]}")
    print(f"   capture L{r[4]}: {r[3][:150]}")
    print(f"   pull: {r[5]} -> stale deref L{r[6]}: ...{r[7]}...")
    print()
