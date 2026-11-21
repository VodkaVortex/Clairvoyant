import os, re, sys, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s04"
EXCLUDE = ("/tools/", "/Documentation/", "/samples/", "/scripts/", "/rust/")
# terminator write:  buf[IDX] = '\0';  or  buf[IDX] = 0;
term_re = re.compile(r"(\w+)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*=\s*'(?:\\0|0)'|(\w+)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*=\s*0\s*;")
# clamp assignment: len = min_t(T, count, sizeof(buf));  len = min(count, sizeof(buf));  len = count;
clamp_re = re.compile(r"(\w+)\s*=\s*(min_t\s*\([^)]*|min\s*\([^)]*\)|count|size|cnt|nbytes|copied|len)\s*[;,]")
guard_re = re.compile(r"if\s*\(\s*(\w+)\s*>=?\s*sizeof\s*\(\s*(\w+)\s*\)|if\s*\(\s*sizeof\s*\(\s*(\w+)\s*\)\s*[-<]")

results = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    if any(x in dirpath for x in EXCLUDE):
        dirnames[:] = []
        continue
    for fn in filenames:
        if not fn.endswith(".c"):
            continue
        path = os.path.join(dirpath, fn)
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            m = term_re.search(line)
            if not m:
                continue
            arr = m.group(1) or m.group(3)
            idx = m.group(2) or m.group(4)
            if idx in ("0",):
                continue
            # look backwards up to 20 lines for how idx got its value and any guard
            ctx = lines[max(0, i-20):i+1]
            src = "\n".join(ctx)
            how = None
            for j in range(len(ctx)-1, -1, -1):
                cm = re.match(r"\s*(%s)\s*=\s*(.+)" % re.escape(idx), ctx[j])
                if cm and how is None:
                    how = (j + max(0, i-20) + 1, cm.group(2).strip())
            guard = None
            for j, cl in enumerate(ctx):
                gm = re.search(r"if\s*\(\s*(\w+)\s*([<>]=?)\s*sizeof\s*\(\s*(\w+)\s*\)\s*([-)]|\)|)", cl)
                if gm:
                    guard = (j + max(0, i-20) + 1, cl.strip())
            results.append({
                "path": os.path.relpath(path, ROOT),
                "term_line": i+1,
                "term_src": line.strip(),
                "array": arr, "index": idx,
                "idx_assign": how,
                "nearby_guard": guard,
            })
print(json.dumps(results, indent=1))
print("TOTAL terminator-write sites:", len(results), file=sys.stderr)
