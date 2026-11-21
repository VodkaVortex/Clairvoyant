import re, subprocess, json, sys

ROOT = "/mnt/raid/home/yangning_placeholder"
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11"

# candidate (file, lockexpr) pairs from tasklet & napi scans
softirq_sides = json.load(open(sys.argv[1]))
out = {}
for f, entries in softirq_sides.items():
    rel = f[len(ROOT)+1:]
    src = open(f, errors="replace").read()
    # map lock expr -> all spin_lock-like sites
    locknames = {}
    for e in entries:
        for ln, expr in e.get("plain_locks", []):
            locknames.setdefault(expr, set()).add(e.get("callback") or e.get("poll"))
    for expr, cbs in locknames.items():
        # extract lock base name from &a->b.c
        base = expr.lstrip('&').split('->')[-1].split('.')[-1].strip()
        # find all acquisitions in file
        sites = []
        for m in re.finditer(r'(spin_lock(?:_bh|_irqsave|_irq|_save)?)(?:_lock)?\s*\(\s*([^;()]+?)\s*[,)]', src):
            if base in m.group(2):
                line = src[:m.start()].count('\n')+1
                sites.append((line, m.group(1), m.group(2).strip()))
        out.setdefault(rel, []).append({"lock": expr, "base": base, "softirq_cbs": sorted(cbs), "sites": sites})

print(json.dumps(out, indent=1))
