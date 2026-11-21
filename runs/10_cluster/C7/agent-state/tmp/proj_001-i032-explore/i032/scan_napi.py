import re, os, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
cfiles = []
for base in ["drivers", "net"]:
    for dirpath, dirs, files in os.walk(os.path.join(ROOT, base)):
        for f in files:
            if f.endswith(".c"):
                cfiles.append(os.path.join(dirpath, f))

netif_re = re.compile(r'netif_napi_add\s*\(\s*[^,]+,\s*&?([A-Za-z0-9_\.\->]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
# old style netif_napi_add(dev, &priv->napi, poll, weight)
# also napi_schedule(&x) usage

def find_body(src, name):
    pat = re.compile(r'\b' + re.escape(name) + r'\s*\([^;{]*?\)\s*\{', re.S)
    for m in pat.finditer(src):
        start = m.end(); depth = 1; i = start
        while i < len(src) and depth > 0:
            c = src[i]
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            i += 1
        line = src[:m.start()].count("\n") + 1
        return src[m.start():i], line
    return None, None

polls = {}
for cf in cfiles:
    try:
        with open(cf, "r", errors="replace") as fh: src = fh.read()
    except OSError: continue
    for m in netif_re.finditer(src):
        polls.setdefault(m.group(2), set()).add(os.path.relpath(cf, ROOT))

print("NAPI poll callbacks:", len(polls), file=sys.stderr)
results = []
for fname, files in polls.items():
    for cf in files:
        path = os.path.join(ROOT, cf)
        try:
            with open(path, "r", errors="replace") as fh: src = fh.read()
        except OSError: continue
        body, defline = find_body(src, fname)
        if body is None: continue
        if re.search(r'\bspin_lock\s*\(', body):
            locks = sorted(set(re.findall(r'spin_lock\s*\(\s*&?([^)]+)\)', body)))
            locks = [l.split(',')[-1].strip() for l in locks]
            results.append((cf, defline, fname, sorted(set(locks))))
        break
print("=== NAPI poll functions taking plain spin_lock ===")
for cf, defline, fname, locks in sorted(results):
    print(f"{cf}:{defline} func={fname} locks={locks}")
print("total:", len(results))
