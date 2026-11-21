import os, re, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"
DIRS = ["drivers", "sound", "net", "fs", "arch", "kernel"]

irq_re = re.compile(r'\b(?:devm_)?request(?:_threaded|_any_context|_percpu)?_irq\s*\(')
plain_re = re.compile(r'\bspin_lock\s*\(\s*&?\s*([A-Za-z0-9_>\.\[\]()]+?)\s*\)')
irqs_re = re.compile(r'\bspin_lock_irq(?:save)?\s*\(')

results = []
for d in DIRS:
    base = os.path.join(ROOT, d)
    for dirpath, dirnames, filenames in os.walk(base):
        for fn in filenames:
            if not fn.endswith('.c'):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, 'r', errors='replace') as f:
                    lines = f.readlines()
            except Exception:
                continue
            irq_sites = []
            for i, l in enumerate(lines):
                if not irq_re.search(l):
                    continue
                joined = l
                j = i
                while j < min(i + 8, len(lines) - 1):
                    j += 1
                    joined += lines[j]
                am = re.search(r'_irq\s*\(\s*[^,]+,\s*([A-Za-z0-9_]+)', joined)
                threaded = 'request_threaded_irq' in joined
                if am:
                    irq_sites.append((i + 1, am.group(1), threaded))
            if not irq_sites:
                continue
            def find_body(name):
                defre = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?\b\**' + re.escape(name) + r'\s*\(')
                for i, l in enumerate(lines):
                    if defre.match(l) and not l.strip().endswith(';'):
                        k = i
                        depth = 0
                        started = False
                        while k < len(lines) and k < i + 80:
                            depth += lines[k].count('{') - lines[k].count('}')
                            if '{' in lines[k]:
                                started = True
                            if started and depth <= 0:
                                return (i + 1, k + 1)
                            if not started and depth < 0:
                                return None
                            k += 1
                        return None
                return None
            for (ln, h, threaded) in irq_sites:
                body = find_body(h)
                if body is None:
                    continue
                s, e = body
                body_txt = ''.join(lines[s-1:e])
                plain = plain_re.findall(body_txt)
                if plain:
                    results.append({'file': os.path.relpath(path, ROOT), 'reg_line': ln,
                                    'handler': h, 'threaded': threaded,
                                    'body': (s, e), 'plain_locks': sorted(set(plain)),
                                    'has_irqsave': bool(irqs_re.search(body_txt))})
with open('hardirq_plain.json', 'w') as f:
    json.dump(results, f, indent=1)
print(len(results), "handlers with plain spin_lock")
