import re, os

root = os.getcwd()
entries = []
for l in open(os.environ['TMPDIR'] + '/timer_cb_with_locks.txt'):
    parts = l.rstrip('\n').split('\t')
    if len(parts) < 6:
        continue
    f, cb, reg, defspan, locks = parts[0], parts[1], parts[2], parts[3], parts[4]
    entries.append((f, cb, defspan, locks.split(',')))

# For each file, check whether the same lock expression appears with plain spin_lock( elsewhere
out = open(os.environ['TMPDIR'] + '/candidates_plain.txt', 'w')
count = 0
for f, cb, defspan, locks in entries:
    path = os.path.join(root, f)
    try:
        text = open(path, errors='replace').read()
        lines = text.splitlines()
    except Exception:
        continue
    for lock in locks:
        # plain spin_lock(&lock) or spin_lock(lock)
        pat = re.compile(r'spin_lock\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        bh_pat = re.compile(r'spin_lock_bh\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        irq_pat = re.compile(r'spin_lock_irq(?:save)?\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        if pat.search(text) and not bh_pat.search(text):
            count += 1
            out.write(f"{f}\t{cb}\t{defspan}\t{lock}\n")
            break
out.close()
print("timer callbacks with lock also plain-locked elsewhere and never _bh:", count)
