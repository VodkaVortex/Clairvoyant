import re, os

root = os.getcwd()
tasklet_files = [l.strip() for l in open(os.environ['TMPDIR']+'/tasklet_files.txt') if l.strip()]
cb_re = re.compile(r'tasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)')

# For each tasklet callback that takes a plain spin_lock, identify the lock expression
lock_re = re.compile(r'spin_lock\s*\(\s*([^)]+?)\s*\)')

for f in tasklet_files:
    p = os.path.join(root, f)
    try:
        src = open(p, errors='replace').read()
    except Exception:
        continue
    for cb in set(cb_re.findall(src)):
        m = re.search(r'(?:^|\n)[A-Za-z_0-9 \*]+\b' + re.escape(cb) + r'\s*\(', src)
        if not m:
            continue
        body = src[m.end():m.end()+4000]
        nxt = re.search(r'\n[A-Za-z_0-9 \*]+\([^;]*\)\s*\n\{', body)
        seg = body[:nxt.start()] if nxt else body[:3000]
        locks = lock_re.findall(seg)
        if locks:
            # find whether the same lock is taken with _bh or _irqsave elsewhere in the same file
            for L in set(x.strip() for x in locks):
                bh = len(re.findall(r'spin_lock_bh\s*\(\s*' + re.escape(L) + r'\s*\)', src))
                irqs = len(re.findall(r'spin_lock_irqsave\s*\(\s*' + re.escape(L), src))
                plain = len(re.findall(r'spin_lock\s*\(\s*' + re.escape(L) + r'\s*\)', src))
                print(f"{f}\t{cb}\tlock={L}\tplain={plain}\tbh={bh}\tirqsave={irqs}")
