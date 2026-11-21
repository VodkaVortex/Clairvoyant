#!/usr/bin/env python3
"""Heuristic scanner v2: stale-pointer-across-pull, incl. capture via
skb_header_pointer into temp then alias; also flag pull-INSIDE-loop with
pointer deref in later iterations."""
import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s02"

PULL_RE = re.compile(r'\b(?:pskb_may_pull_reason|pskb_may_pull|pskb_pull|__pskb_pull|__pskb_pull_tail|skb_linearize|skb_linearize_rcsum|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone|skb_share_check)\b')

CAPTURE_RE = re.compile(r'''
    (?P<var>\w+)\s*=\s*(?:
        skb_header_pointer\s*\( |
        (?:\([^)]*[*^]\s*[\w\s]+\)\s*)?skb->(?:data|head)(?:\s*\+\s*[^;,]*)? |
        \w+->(?:data|head)(?:\s*\+\s*[^;,]*)? |
        skb_pull_data\s*\( |
        skb_network_header\s*\(\s*\w+| skb_mac_header\s*\(\s*\w+| skb_transport_header\s*\(\s*\w+
    )
''', re.X)

def split_functions(src):
    funcs = []
    lines = src.split('\n')
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if (not line.startswith(('\t', ' ', '#', '*', '/*', ' */', '}'))
                and re.search(r'[A-Za-z_]\w*\s*\(', line)
                and not re.match(r'\s*(if|for|while|switch|return|else|case|default|do)\b', line)
                and '=' not in line.split('(')[0]
                and not line.rstrip().endswith(';')
                and (line.rstrip().endswith('{')
                     or (i+1 < n and lines[i+1].strip() == '{'))):
            depth = 0; body = []; j = i; started = False
            while j < n:
                l = lines[j]
                depth += l.count('{') - l.count('}')
                body.append(l)
                if '{' in l: started = True
                if started and depth <= 0: break
                j += 1
            m = re.search(r'([A-Za-z_]\w*)\s*\(', line)
            if m and started and depth <= 0:
                funcs.append((m.group(1), i+1, body))
            i = j + 1
        else:
            i += 1
    return funcs

def scan():
    hits, loop_hits = [], []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d != '.git']
        for fn in filenames:
            if not fn.endswith(('.c', '.h')): continue
            path = os.path.join(dirpath, fn)
            try: src = open(path, errors='replace').read()
            except OSError: continue
            if not PULL_RE.search(src): continue
            for (fname, fline, body) in split_functions(src):
                text = '\n'.join(body)
                if not PULL_RE.search(text): continue
                pulls = [li for li, l in enumerate(body) if PULL_RE.search(l)]
                first_pull = pulls[0]
                # capture vars
                capvars = {}
                for li, l in enumerate(body):
                    if li >= first_pull: break
                    for m in CAPTURE_RE.finditer(l):
                        v = m.group('var')
                        if v and v not in ('if','while','for','return','sizeof'):
                            capvars.setdefault(v, li)
                for v, cli in capvars.items():
                    uses = []
                    for li in range(first_pull+1, len(body)):
                        l = body[li]
                        if re.search(r'(?<![\w.>])' + re.escape(v) + r'\s*(?:->|\.\w|\[)', l) or \
                           re.search(r'\*\s*' + re.escape(v) + r'\b', l) or \
                           re.search(r'\(\s*' + re.escape(v) + r'\s*[,)]', l):
                            uses.append(li)
                    if uses:
                        hits.append((os.path.relpath(path, ROOT), fname, fline, v, cli, first_pull, tuple(uses[:10])))
                # loop-with-interior-pull detection: while/for at line k, pull inside
                # lines k..k+60 at deeper indent, and any pointer deref of a var
                # captured before the loop inside the loop
                for li, l in enumerate(body):
                    lm = re.match(r'\s*(?:while|for)\s*\(', l)
                    if not lm: continue
                    # loop body extent: brace matching from this line
                    depth = 0; started = False; k = li
                    while k < len(body):
                        depth += body[k].count('{') - body[k].count('}')
                        if '{' in body[k]: started = True
                        if started and depth <= 0: break
                        k += 1
                    if k >= len(body): k = len(body) - 1
                    if k < li: k = li
                    inner = list(range(li, min(k+1, len(body))))
                    pull_in = [x for x in inner if PULL_RE.search(body[x])]
                    if not pull_in: continue
                    # vars captured before loop start
                    for m2 in CAPTURE_RE.finditer('\n'.join(body[:li])):
                        v = m2.group('var')
                        if not v or v in ('if','while','for','return','sizeof'): continue
                        # use inside loop after first interior pull
                        for x in range(pull_in[0], k+1):
                            if re.search(r'(?<![\w.>])' + re.escape(v) + r'\s*(?:->|\.\w|\[)', body[x]) or \
                               re.search(r'\*\s*' + re.escape(v) + r'\b', body[x]):
                                loop_hits.append((os.path.relpath(path, ROOT), fname, fline, v, li, pull_in[0], x))
                                break
    return hits, loop_hits

if __name__ == '__main__':
    hits, loop_hits = scan()
    print(f"A) capture-before-pull + use-after-pull (same function): {len(hits)}")
    for r in sorted(set(hits), key=lambda x: (x[0], x[2], x[3])):
        print(f"  {r[0]}:{r[2]} fn={r[1]} var={r[3]} cap_off={r[4]} pull_off={r[5]} use_offs={r[6]}")
    print(f"B) loop with interior pull + pre-loop var used inside loop after pull: {len(loop_hits)}")
    for r in sorted(set(loop_hits), key=lambda x: (x[0], x[2], x[3])):
        print(f"  {r[0]}:{r[2]} fn={r[1]} var={r[3]} loop_off={r[4]} pull_off={r[5]} use_off={r[6]}")
