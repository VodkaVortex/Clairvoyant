#!/bin/bash
# Build callee census: functions containing head-relocating ops with an skb parameter
cd /mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01
python3 - << 'PYEOF'
import re, os, sys

RELOC = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|__pskb_expand_head|skb_unclone|skb_share_check|skb_header_pointer)\s*\(')

def functions(text):
    # crude function finder: lines at col 0 ending with '{'
    lines = text.split('\n')
    starts = []
    for i, l in enumerate(lines):
        if re.match(r'^[A-Za-z_].*\)\s*\{?\s*$', l) and not l.startswith(('#', '/', '*')):
            starts.append(i)
    return starts, lines

count = 0
census = []
for root, dirs, files in os.walk('net'):
    for f in files:
        if not f.endswith('.c') and not f.endswith('.h'):
            continue
        p = os.path.join(root, f)
        try:
            text = open(p, encoding='utf-8', errors='replace').read()
        except:
            continue
        lines = text.split('\n')
        # find function spans by brace tracking from col-0 '{'
        i = 0
        n = len(lines)
        while i < n:
            l = lines[i]
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_ *]*?)\b([a-zA-Z0-9_]+)\s*\(', l)
            if l and not l[0] in (' ', '\t', '#', '/', '*', '}') and '{' in ''.join(lines[i:i+3]):
                # find name
                nm = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', l)
                if nm:
                    name = nm.group(1)
                    # span: brace matching
                    depth = 0
                    started = False
                    j = i
                    end = None
                    while j < n and j < i + 2000:
                        for ch in lines[j]:
                            if ch == '{':
                                depth += 1
                                started = True
                            elif ch == '}':
                                depth -= 1
                                if started and depth == 0:
                                    end = j
                                    break
                        if end is not None:
                            break
                        j += 1
                    if end is not None and end > i:
                        body = '\n'.join(lines[i:end+1])
                        for mm in RELOC.finditer(body):
                            # line number of the match
                            ln = i + body[:mm.start()].count('\n')
                            census.append((p, name, i+1, mm.group(1), ln+1))
                    i = end if end else i+1
                    continue
            i += 1
print(len(census))
import json
json.dump(census, open(os.environ['TMPDIR']+'/i022/census_net.json','w'))
PYEOF
