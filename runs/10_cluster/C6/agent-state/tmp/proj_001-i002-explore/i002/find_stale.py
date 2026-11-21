#!/usr/bin/env python3
"""Find candidate rx-pull-stale-hdr bugs: header pointer captured before a
reallocating pull (pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize/
pskb_pull_reserve) and dereferenced after it in the same function."""
import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"
SEARCH_DIRS = ["net", "drivers"]
PULL = re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|pskb_pull_reserve|pskb_may_pull_fragile)\s*\(')
CAPTURE = re.compile(r'^\s*(?:static\s+)?(?:const\s+)?(?:struct\s+|union\s+|enum\s+)?(\w+)\s*\*\s*(\w+)\s*=')

def func_iter(path):
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].rstrip('\n')
        # kernel style: signature line(s) ending with ')' then '{' on its own line
        sig = None
        if line == '{' and i > 0:
            prev = lines[i-1].rstrip('\n').rstrip()
            if prev.endswith(')') and not re.match(r'^\s*(if|for|while|switch|do|else|return)\b', prev):
                sig = prev
        elif re.match(r'^[A-Za-z_].*\)\s*\{\s*$', line):
            sig = line
        if sig is not None:
            name_m = re.search(r'(\w+)\s*\(', sig)
            fname = name_m.group(1) if name_m else '?'
            depth = 1
            j = i + 1
            while j < n and depth > 0:
                l = lines[j]
                depth += l.count('{') - l.count('}')
                if depth <= 0:
                    break
                j += 1
            # function body starts at the '{' line (i)
            yield fname, i+1, j+1, lines[i:j+1]
            i = j + 1
        else:
            i += 1

def strip_code(l):
    return re.sub(r'/\*.*?\*/', '', l)

def main():
    results = []
    for sd in SEARCH_DIRS:
        base = os.path.join(ROOT, sd)
        for dirpath, dirnames, filenames in os.walk(base):
            if '/.git' in dirpath: continue
            for fn in filenames:
                if not fn.endswith('.c'): continue
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, ROOT)
                for fname, s, e, body in func_iter(p):
                    pulls = [(k, strip_code(body[k])) for k in range(len(body)) if PULL.search(strip_code(body[k]))]
                    if not pulls: continue
                    caps = []
                    for k in range(len(body)):
                        cl = strip_code(body[k])
                        m = CAPTURE.match(cl)
                        if m and 'skb' in cl:
                            ptype, var = m.groups()
                            caps.append((k, var, cl.strip()))
                        if 'skb_header_pointer' in cl:
                            m2 = re.search(r'(\w+)\s*=\s*skb_header_pointer', cl)
                            if m2:
                                caps.append((k, m2.group(1), cl.strip()))
                    for pk, pline in pulls:
                        for ck, var, cline in caps:
                            if ck < pk:
                                uses = []
                                for k in range(pk+1, len(body)):
                                    cl = strip_code(body[k])
                                    m3 = re.match(r'^\s*(?:.*?\*)?\s*' + re.escape(var) + r'\s*=', cl)
                                    if m3:
                                        break
                                    if re.search(r'\b' + re.escape(var) + r'\s*->', cl) or re.search(r'\(\s*' + re.escape(var) + r'\s*\)', cl) or re.search(r'[^->]\*\s*' + re.escape(var) + r'\b', cl):
                                        uses.append((k+1, cl.strip()))
                                if uses:
                                    results.append({
                                        "file": rel, "func": fname,
                                        "pull_line": s+pk, "pull": pline.strip()[:120],
                                        "cap_line": s+ck, "cap": cline[:150],
                                        "var": var,
                                        "uses": [(s+u[0]-1, u[1][:120]) for u in uses[:6]],
                                    })
    print(json.dumps(results, indent=1))
    print(f"TOTAL {len(results)}", file=sys.stderr)

main()
