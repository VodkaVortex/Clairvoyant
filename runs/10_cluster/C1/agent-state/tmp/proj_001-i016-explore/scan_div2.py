import re, os

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/public/snapshots/s03"

results = []
# Pattern: / identifier or / (expression starting with identifier or number*identifier etc.
divre = re.compile(r'(?<![\w/\\])(?<!\*/)[/%]\s*(\([A-Za-z0-9_\-+*/<> ()]*\)|[A-Za-z_][A-Za-z0-9_]*)')

for dirpath, dirnames, files in os.walk(os.path.join(ROOT,'drivers')):
    rel = os.path.relpath(dirpath, ROOT)
    if 'gpu' in rel or rel == 'drivers':  # skip gpu for now, focus non-DRM
        pass
    for fn in files:
        if not fn.endswith('.c'):
            continue
        path = os.path.join(dirpath, fn)
        rpath = os.path.relpath(path, ROOT)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except OSError:
            continue
        in_comment = False
        for i, line in enumerate(lines, 1):
            ls = line.strip()
            if ls.startswith('#'):
                continue
            for m in divre.finditer(line):
                den = m.group(1)
                # strip quotes-in-line heuristics: skip format strings
                if '"' in line and '%' in line and 'pr_' in line or 'printk' in line:
                    continue
                # ignore if inside comment
                code_before = line.split('/*')[0]
                if m.start() >= len(line) - len(line.lstrip()):
                    pass
                # skip when denominator purely constant digits and known constants
                if re.fullmatch(r'[0-9]+|0x[0-9a-fA-F]+', den):
                    continue
                if den in ('sizeof','PAGE_SIZE','ARRAY_SIZE','2','4','8','1000','NULL'):
                    continue
                results.append((rpath, i, ls[:200]))

for rpath, i, line in results:
    print(f"{rpath}:{i}: {line}")
print("TOTAL", len(results))
