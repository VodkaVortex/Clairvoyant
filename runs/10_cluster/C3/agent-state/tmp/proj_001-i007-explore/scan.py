#!/usr/bin/env python3
"""Find netlink attribute slot dereferences without presence guards."""
import re, os, sys, json

SNAP = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/public/snapshots/s02"
OUT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/tmp/proj_001-i007-explore"

USE_RE = re.compile(r'\b((?:info->)?attrs|tb[a-zA-Z0-9_]*)\[\s*([A-Z][A-Z0-9_]*)\s*\]')

def functions(src):
    lines = src.split('\n')
    funcs = []
    i = 0
    n = len(lines)
    head_re = re.compile(r'^(?:static\s+)?(?:inline\s+)?(?:[A-Za-z_][A-Za-z0-9_\*\s]+?)\s+\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    while i < n:
        line = lines[i]
        m = head_re.match(line)
        if m and (not line.strip().endswith(';')):
            j = i
            found = None
            while j < min(i+6, n):
                if '{' in lines[j]:
                    found = j
                    break
                if lines[j].strip().endswith(';'):
                    break
                j += 1
            if found is not None:
                name = m.group(1)
                k = found
                while k < n and lines[k][:1] != '}':
                    k += 1
                funcs.append((i, k, name, lines[i:k+1]))
                i = k + 1
                continue
        i += 1
    return funcs

def analyze(path):
    src = open(path, errors='replace').read()
    results = []
    for (fs, fe, name, body) in functions(src):
        uses = []
        for idx, ln in enumerate(body):
            for m in USE_RE.finditer(ln):
                arr, attr = m.group(1), m.group(2)
                uses.append((idx, arr, attr, ln))
        if not uses:
            continue
        cond_lines = []
        for idx, ln in enumerate(body):
            stripped = ln.strip()
            if re.search(r'\b(if|while|else if)\b.*\(', stripped):
                cond_lines.append((idx, stripped))
        attr_checked = {}
        for (idx, arr, attr, ln) in uses:
            key = (arr, attr)
            guarded = False
            guard_kind = None
            for (cidx, ctext) in cond_lines:
                if cidx >= idx:
                    continue
                if re.search(r'[^A-Za-z0-9_]' + re.escape(arr) + r'\[\s*' + re.escape(attr) + r'\s*\]', ctext):
                    guarded = True
                    guard_kind = ctext
                    break
            if not guarded:
                for pidx in range(idx):
                    pl = body[pidx]
                    if re.search(r'[^A-Za-z0-9_]' + re.escape(arr) + r'\[\s*' + re.escape(attr) + r'\s*\]', pl):
                        guarded = 'weak'
                        guard_kind = pl.strip()
                        break
            attr_checked.setdefault(key, []).append((idx, guarded, guard_kind, ln.strip()))
        for key, lst in attr_checked.items():
            for (idx, guarded, gk, ln) in lst:
                if guarded is not True:
                    results.append({
                        'file': path.replace(SNAP + '/', ''),
                        'func': name,
                        'func_start': fs + 1,
                        'line': fs + 1 + idx,
                        'array': key[0],
                        'attr': key[1],
                        'guarded': guarded,
                        'guard': gk,
                        'use': ln,
                    })
    return results

all_res = []
for root, dirs, files in os.walk(SNAP):
    for f in files:
        if f.endswith('.c'):
            p = os.path.join(root, f)
            try:
                all_res.extend(analyze(p))
            except Exception as e:
                print(f"ERR {p}: {e}", file=sys.stderr)

json.dump(all_res, open(os.path.join(OUT, 'unguarded_uses.json'), 'w'), indent=1)
print(f"total flagged uses: {len(all_res)}")
byfile = {}
for r in all_res:
    byfile.setdefault(r['file'], []).append(r)
for f in sorted(byfile):
    print(f"\n== {f} ({len(byfile[f])})")
    for r in byfile[f]:
        g = 'CONDFREE' if r['guarded'] is False else 'EARLIER-USE'
        print(f"  L{r['line']} {r['func']}() [{r['array']}][{r['attr']}] {g}: {r['use'][:100]}")
