#!/usr/bin/env python3
import os, re, sys, json, hashlib

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/public/snapshots/s02"
EXCLUDE_DIRS = {'tools', 'samples', 'Documentation', 'scripts'}

fetch_call_re = re.compile(r'\b(get_user|__get_user|unsafe_get_user|copy_from_user|__copy_from_user|copy_from_iter|strndup_user|strncpy_from_user|memdup_user|vmemdup_user)\s*\(')

def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        parts = rel.split(os.sep)
        if parts[0] in EXCLUDE_DIRS:
            dirnames[:] = []
            continue
        for fn in filenames:
            if fn.endswith(('.c', '.h')):
                yield os.path.join(dirpath, fn)

results = []
nfiles = 0
for path in iter_files():
    nfiles += 1
    try:
        with open(path, 'r', errors='replace') as f:
            src = f.read()
    except OSError:
        continue
    if 'copy_from_user' not in src and 'get_user' not in src and 'memdup_user' not in src and 'strndup_user' not in src:
        continue
    lines = src.split('\n')
    # find function-ish regions: simple approach - collect line numbers of fetch calls
    fetch_lines = []
    for i, line in enumerate(lines):
        m = fetch_call_re.search(line)
        if m:
            fetch_lines.append((i, m.group(1), line))
    if len(fetch_lines) < 2:
        continue
    # group into windows of 120 lines, need >=3 fetch calls to be a "dense" handler
    windows = []
    cur = [fetch_lines[0]]
    for fl in fetch_lines[1:]:
        if fl[0] - cur[-1][0] <= 150:
            cur.append(fl)
        else:
            windows.append(cur)
            cur = [fl]
    windows.append(cur)
    for w in windows:
        if len(w) >= 3:
            results.append({
                'file': os.path.relpath(path, ROOT),
                'start_line': w[0][0] + 1,
                'end_line': w[-1][0] + 1,
                'n_fetches': len(w),
                'kinds': sorted(set(x[1] for x in w)),
                'first_snippet': w[0][2].strip()[:120],
            })

results.sort(key=lambda r: -r['n_fetches'])
out = {'n_files_scanned': nfiles, 'n_windows': len(results), 'windows': results}
with open(os.path.join(os.environ['TMPDIR'], 'fetch_windows.json'), 'w') as f:
    json.dump(out, f, indent=1)
print("files", nfiles, "windows", len(results))
for r in results[:60]:
    print(f"{r['n_fetches']:3d} {r['file']}:{r['start_line']}-{r['end_line']} kinds={r['kinds']}")
