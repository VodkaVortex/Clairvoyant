#!/usr/bin/env python3
"""Cross-index handler-plain locks with plain spin_lock sites elsewhere in the same file (outside the handler function)."""
import re, os, json, collections

W = os.path.dirname(os.path.abspath(__file__))
S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s08"
pairs = json.load(open(os.path.join(W, "handler_plain_locks.json")))

filecache = {}
def get_file(path):
    if path not in filecache:
        with open(os.path.join(S, path), errors='replace') as f:
            filecache[path] = f.read().splitlines()
    return filecache[path]

lock_acq = re.compile(r'\bspin_lock\s*\(\s*([^);]+?)\s*\)')
lock_irq = re.compile(r'\bspin_lock_irq(?:save)?\s*\(')
lock_bh  = re.compile(r'\bspin_lock_bh\s*\(')

# normalize lock expression: strip whitespace
def norm(e):
    return re.sub(r'\s+', '', e)

by_file = collections.defaultdict(list)
for p in pairs:
    by_file[p['path']].append(p)

rows = []
for path, ps in by_file.items():
    lines = get_file(path)
    handler_ranges = set((p['handler'], p['func_start'], p['func_end']) for p in ps)
    hlocks = set(norm(p['lock']) for p in ps)
    hfuncs = set(p['handler'] for p in ps)
    # find all plain spin_lock sites outside handler bodies
    other_plain = []
    n = len(lines)
    # compute function ranges per line using simple heuristic: track via find_funcs for all handlers only; for other lines, classify by context markers
    for ln in range(1, n + 1):
        l = lines[ln - 1]
        if lock_irq.search(l) or lock_bh.search(l):
            continue
        for m in lock_acq.finditer(l):
            e = norm(m.group(1))
            if e in hlocks:
                in_handler = False
                for (h, a, b) in handler_ranges:
                    if a <= ln <= b:
                        in_handler = True
                        break
                if not in_handler:
                    other_plain.append((ln, e, l.strip()))
    if other_plain:
        rows.append({'path': path, 'handler_locks': sorted(hlocks), 'handlers': sorted(hfuncs),
                     'handler_sites': [(p['handler'], p['acq_line'], p['lock'], p['regline'], p['kind']) for p in ps],
                     'other_plain': other_plain})

rows.sort(key=lambda r: -len(r['other_plain']))
with open(os.path.join(W, "cross.tsv.json"), "w") as f:
    json.dump(rows, f, indent=1)
for r in rows[:40]:
    print(f"{r['path']} handlers={r['handlers']} hlocks={r['handler_locks']} other_plain={len(r['other_plain'])}")
print("files with candidate pairs:", len(rows))
