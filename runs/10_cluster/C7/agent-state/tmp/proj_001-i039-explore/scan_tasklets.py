import re, os, sys

root = os.getcwd()
tasklet_files = [l.strip() for l in open(os.environ['TMPDIR']+'/tasklet_files.txt') if l.strip()]

# collect tasklet_init(func) callback names per file
cb_re = re.compile(r'tasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)')
hi_re = re.compile(r'tasklet_hi_schedule\s*\(\s*&?([A-Za-z_0-9>\.\-]+)')
sch_re = re.compile(r'tasklet_schedule\s*\(\s*&?([A-Za-z_0-9>\.\-]+)')

results = []
for f in tasklet_files:
    p = os.path.join(root, f)
    try:
        src = open(p, errors='replace').read()
    except Exception:
        continue
    cbs = set(cb_re.findall(src))
    if not cbs:
        continue
    # find callback body and check for spin_lock in the body (coarse: 80 lines after def)
    for cb in cbs:
        m = re.search(r'(?:^|\n)[A-Za-z_0-9 \*]+\b' + re.escape(cb) + r'\s*\(', src)
        if not m:
            continue
        start = m.start()
        body = src[m.end():m.end()+4000]
        # naive: find next function definition at col 0
        nxt = re.search(r'\n[A-Za-z_0-9 \*]+\([^;]*\)\s*\n\{', body)
        seg = body[:nxt.start()] if nxt else body[:3000]
        if re.search(r'spin_lock\s*\(', seg):
            results.append((f, cb, src[:m.end()].count('\n')+1))

for f, cb, line in results:
    print(f"{f}:{line}: tasklet cb {cb} takes spin_lock in body")
print(f"--- total {len(results)}")
