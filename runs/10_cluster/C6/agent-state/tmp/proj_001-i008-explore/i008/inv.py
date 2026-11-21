#!/usr/bin/env python3
# Inventory: functions containing pskb pulls AND loops; report pull lines and loop lines.
import os, re

S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s02"

PULLS = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_expand_head|skb_cow_head|skb_cow|skb_unclone|skb_share_check)\s*\(')
LOOP = re.compile(r'^\s*(while|for|do)\b')
FUNC_START = re.compile(r'^[A-Za-z_].*\)\s*$|^[A-Za-z_].*\)\s*\{|^[A-Za-z_].*\{$')

def functions(path):
    with open(path, 'r', errors='replace') as f:
        lines = f.read().split('\n')
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        # heuristic function start: line beginning at col 0 with '(' and body '{' within a few lines
        if line and not line[0].isspace() and '(' in line and not line.startswith(('#', '}', '/', '*', '|', '\\')):
            j = i
            sig = ''
            while j < n and j <= i + 6:
                sig += lines[j]
                if '{' in lines[j]:
                    # find matching close
                    depth = 0
                    k = j
                    while k < n:
                        depth += lines[k].count('{') - lines[k].count('}')
                        if depth == 0:
                            return_candidate = (i, k)
                            yield return_candidate, lines
                            i = k + 1
                            break
                        k += 1
                    else:
                        i = j
                        break
                    break
                if ';' in lines[j]:
                    break
                j += 1
            else:
                i += 1
                continue
            if k >= n or depth != 0:
                i = j + 1
        else:
            i += 1

for root in ("net", "drivers/net", "drivers/staging", "net/mac80211", "fs"):
    base = os.path.join(S, root)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        for fn in filenames:
            if not fn.endswith('.c'):
                continue
            p = os.path.join(dirpath, fn)
            try:
                txt = open(p, 'r', errors='replace').read()
            except Exception:
                continue
            if not PULLS.search(txt):
                continue
            try:
                for (fs, fe), lines in functions(p):
                    pull_lines = []
                    loop_lines = []
                    for idx in range(fs, fe+1):
                        if PULLS.search(lines[idx]):
                            pull_lines.append(idx+1)
                        if LOOP.match(lines[idx]):
                            loop_lines.append(idx+1)
                    if pull_lines and loop_lines:
                        # is a pull inside a loop body? crude: pull line > min loop line and < fe
                        rel = os.path.relpath(p, S)
                        print(f"{rel}:{fs+1}-{fe+1} pulls={pull_lines} loops={loop_lines}")
            except Exception as e:
                pass
