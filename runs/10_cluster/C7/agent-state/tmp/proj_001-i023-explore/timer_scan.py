import re, os, sys

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s08"
dirs = ["drivers", "net"]

# find function definitions whose parameter is struct timer_list * or struct hrtimer *
funcdef = re.compile(r'^(?:static\s+)?(?:inline\s+)?(?:[A-Za-z_][\w]*\s+)+(\w+)\s*\(\s*struct\s+(timer_list|hrtimer)\s*\*[^)]*\)', re.M)

results = []
for d in dirs:
    for dirpath, _, files in os.walk(os.path.join(root, d)):
        for fn in files:
            if not fn.endswith('.c'):
                continue
            path = os.path.join(dirpath, fn)
            try:
                src = open(path, encoding='utf-8', errors='replace').read()
            except Exception:
                continue
            lines = src.split('\n')
            for m in funcdef.finditer(src):
                name, kind = m.group(1), m.group(2)
                # find body start: next '{' after m.end() within reasonable distance
                idx = src.find('{', m.end())
                if idx == -1 or idx - m.end() > 200:
                    continue
                # balanced braces
                depth = 0; j = idx
                while j < len(src):
                    if src[j] == '{': depth += 1
                    elif src[j] == '}':
                        depth -= 1
                        if depth == 0: break
                    j += 1
                body = src[idx:j]
                if 'spin_lock(' in body or 'spin_lock_bh' in body or 'spin_lock_irqsave' in body:
                    line_no = src[:m.start()].count('\n') + 1
                    locks = re.findall(r'spin_lock(?:_bh|_irqsave|_irq|_irqrestore)?\s*\(&?([^);]+?)\s*\)', body)
                    results.append((os.path.relpath(path, root), line_no, name, kind, sorted(set(locks))))

for r in results:
    print(f"{r[0]}:{r[1]} {r[3]} {r[2]} locks={r[4]}")
print(f"TOTAL={len(results)}")
