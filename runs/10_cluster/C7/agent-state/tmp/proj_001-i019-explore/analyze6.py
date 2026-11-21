import re, os

root = os.getcwd()
entries = []
for l in open(os.environ['TMPDIR'] + '/timer_cb_with_locks.txt'):
    parts = l.rstrip('\n').split('\t')
    if len(parts) < 6:
        continue
    f, cb, reg, defspan, locks = parts[0], parts[1], parts[2], parts[3], parts[4]
    entries.append((f, cb, defspan, locks.split(',')))

out = open(os.environ['TMPDIR'] + '/candidates_v2.txt', 'w')
count = 0
for f, cb, defspan, locks in entries:
    path = os.path.join(root, f)
    try:
        text = open(path, errors='replace').read()
    except Exception:
        continue
    for lock in locks:
        # normalize: strip leading struct-component chains to last identifier group for loose matching
        m = re.search(r'([A-Za-z_0-9]+)$', lock)
        if not m:
            continue
        # plain lock usage anywhere in file: spin_lock(&...lock) exact expr
        pat = re.compile(r'spin_lock\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        bh_pat = re.compile(r'spin_lock_bh\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        if pat.search(text) and not bh_pat.search(text):
            count += 1
            out.write(f"{f}\t{cb}\t{defspan}\t{lock}\n")
            break
out.close()
print("count:", count)
