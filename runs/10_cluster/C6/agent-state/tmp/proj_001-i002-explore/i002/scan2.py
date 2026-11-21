#!/usr/bin/env python3
import re, os, sys

SNAP = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"

PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|__pskb_pull)\s*\(')
CAPTURE_RE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?(\w+)\s*\*\s*(\w+)\s*=\s*(.+?);')

def strip_comments_strings(line):
    return re.sub(r'/\*.*?\*/', '', line)

def scan_file(path):
    full = os.path.join(SNAP, path)
    try:
        with open(full, errors='replace') as f:
            src = f.read()
    except Exception:
        return []
    lines = src.split('\n')
    n = len(lines)
    results = []
    i = 0
    while i < n:
        line = lines[i]
        if re.match(r'^[A-Za-z_]', line):
            # find first '{' within next 5 lines
            j = i
            found = False
            while j < min(i+6, n):
                if '{' in lines[j]:
                    found = True
                    break
                if ';' in lines[j] and j > i:
                    break
                j += 1
            if found:
                # brace match from j
                depth = 0
                k = j
                end = None
                while k < n:
                    for ch in lines[k]:
                        if ch == '{': depth += 1
                        elif ch == '}':
                            depth -= 1
                            if depth == 0:
                                end = k
                                break
                    if end is not None:
                        break
                    k += 1
                if end is not None and end - i < 400:
                    body = lines[i:end+1]
                    results.extend(check_body(path, i, body))
                    i = end + 1
                    continue
        i += 1
    return results

def check_body(path, base, body):
    out = []
    for k, bl in enumerate(body):
        blc = strip_comments_strings(bl)
        m = CAPTURE_RE.match(blc)
        if not m:
            continue
        var = m.group(2)
        expr = m.group(3)
        if 'skb' not in expr and 'skb' not in var:
            continue
        # require skb data source in expr
        if not re.search(r'skb|hdr|data|frag', expr):
            continue
        # find first pull after
        pull_idx = None
        for k2 in range(k+1, len(body)):
            if PULL_RE.search(strip_comments_strings(body[k2])):
                pull_idx = k2
                break
        if pull_idx is None:
            continue
        # walk after pull; stop at reassignment of var
        stale = []
        for k3 in range(pull_idx+1, len(body)):
            b3 = strip_comments_strings(body[k3])
            if re.search(r'\b' + re.escape(var) + r'\s*=(?!=)', b3):
                break
            dm = re.search(r'\b' + re.escape(var) + r'\s*(?:->|\.)\s*\w', b3)
            if dm:
                stale.append((base+k3+1, b3.strip()[:110]))
        if stale:
            out.append((path, base+k+1, bl.strip()[:110], base+pull_idx+1, body[pull_idx].strip()[:90], stale[:8]))
    return out

files = [l.strip() for l in open(os.path.join(os.environ.get('TMPDIR','/tmp'), 'i002', 'i002_pull_files.txt')) if l.strip()]
all_res = []
for f in files:
    all_res.extend(scan_file(f))
print("PATH\tCAPTURE_LINE\tCAPTURE\tPULL_LINE\tPULL\tSTALE_USES")
for r in all_res:
    uses = " || ".join(f"{l}:{t[:90]}" for l, t in r[5])
    print(f"{r[0]}\t{r[1]}\t{r[2][:70]}\t{r[3]}\t{r[4][:55]}\t{uses[:500]}")
