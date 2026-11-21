import re, os

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/public/snapshots/s03"
results = []
# variable denominator, code lines only
divre = re.compile(r'(?<![\w/\\])(?<!\*/)[/%]\s*(\([A-Za-z0-9_\-+*/<> ()]*\)|[A-Za-z_][A-Za-z0-9_]*)')

for dirpath, dirnames, files in os.walk(os.path.join(ROOT,'drivers')):
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
        for i, line in enumerate(lines, 1):
            ls = line.strip()
            if not ls or ls.startswith(('#','*','/*','//')):
                continue
            if re.search(r'pr_(err|warn|info|debug|emerg|notice|alert)|printk|dev_(err|warn|info|dbg)|_dbg\(|_err\(|_info\(|_warn\(|printf|snprintf|sprintf|sysfs_emit|seq_printf|dev_err_probe', line):
                continue
            if '"' in line:
                continue
            for m in divre.finditer(line):
                den = m.group(1)
                if re.fullmatch(r'[0-9]+|0[xX][0-9a-fA-F]+', den):
                    continue
                if den in ('sizeof',):
                    continue
                # keep only when denominator is not trivially nonzero-checked on same line? keep all
                results.append((rpath, i, ls[:200]))

for rpath, i, line in results:
    print(f"{rpath}:{i}: {line}")
print("TOTAL", len(results))
