#!/usr/bin/env python3
# Find loops containing pskb pulls and capture-then-pull-then-use patterns in net/ and drivers/
import os, re, sys, subprocess

S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s02"

PULLS = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_expand_head|skb_cow_head|skb_cow|skb_unclone)\s*\(')
CAPTURE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+\w+|u8|u16|u32|unsigned char|char|void)\s*\*+\s*(\w+)\s*=')

def files():
    for root in ("net", "drivers"):
        base = os.path.join(S, root)
        for dirpath, dirnames, filenames in os.walk(base):
            for fn in filenames:
                if fn.endswith(('.c', '.h')):
                    yield os.path.join(dirpath, fn)

def find_function_bounds(lines, idx):
    """Find enclosing function start/end via brace matching from a '{' near idx going backwards."""
    # find function start: search backwards for line ending with '{' at col0-ish
    start = None
    for i in range(idx, -1, -1):
        stripped = lines[i].rstrip()
        if stripped.endswith('{') and not stripped.startswith((' ', '\t', '}')):
            start = i
            break
        # also handle 'func(...)' definitions where the signature is at col 0
    if start is None:
        return None
    # brace match forward
    depth = 0
    for j in range(start, len(lines)):
        depth += lines[j].count('{') - lines[j].count('}')
        if depth == 0 and j > start:
            return (start, j)
        if depth <= 0 and j == start and lines[start].count('{') == 0:
            return None
    return (start, len(lines) - 1)

results = []
for path in files():
    try:
        with open(path, 'r', errors='replace') as f:
            text = f.read()
    except Exception:
        continue
    if 'pskb_may_pull' not in text and 'pskb_pull' not in text and '__pskb_pull_tail' not in text and 'skb_linearize' not in text:
        continue
    lines = text.split('\n')
    # locate pull lines
    for i, line in enumerate(lines):
        m = PULLS.search(line)
        if not m:
            continue
        fnb = find_function_bounds(lines, i)
        if fnb is None:
            continue
        fs, fe = fnb
        fbody = lines[fs:fe+1]
        # find loops in function: while / for / do
        has_loop = any(re.match(r'\s*(while|for|do)\b', l) for l in fbody)
        if not has_loop:
            continue
        # capture of pointer into skb before pull within same function
        caps = []
        for k in range(fs, i):
            cm = CAPTURE.match(lines[k])
            if cm:
                var = cm.group(1)
                rhs = lines[k].split('=', 1)[1] if '=' in lines[k] else ''
                if any(tok in rhs for tok in ('skb->data', 'skb_network_header', 'skb_transport_header', 'skb_mac_header', 'skb_header_pointer', 'skb_tail_pointer', 'skb->head')):
                    # var used after pull line?
                    used_after = False
                    for k2 in range(i+1, fe+1):
                        if re.search(r'\b' + re.escape(var) + r'\b', lines[k2]) and not re.match(r'\s*' + re.escape(var) + r'\s*=', lines[k2]):
                            used_after = True
                            break
                    # refetch? var = ... after pull
                    refetch = any(re.match(r'.*\b' + re.escape(var) + r'\s*=', lines[k2]) for k2 in range(i+1, fe+1))
                    caps.append((k+1, var, used_after, refetch))
        for (cl, var, used_after, refetch) in caps:
            if used_after:
                rel = os.path.relpath(path, S)
                results.append((rel, fs+1, fe+1, cl, var, i+1, refetch))

for r in sorted(set(results)):
    print("%s:%s fn[%s-%s] capture@%s var=%s pull@%s refetch_after=%s" % (r[0], r[1], r[1], r[2], r[3], r[4], r[5], r[6]))
