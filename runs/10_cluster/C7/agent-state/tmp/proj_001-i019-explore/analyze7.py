import re, os

root = os.getcwd()
entries = []
for l in open(os.environ['TMPDIR'] + '/timer_cb_with_locks.txt'):
    parts = l.rstrip('\n').split('\t')
    if len(parts) < 6:
        continue
    f, cb, reg, defspan, locks = parts[0], parts[1], parts[2], parts[3], parts[4]
    entries.append((f, cb, defspan, locks.split(',')))

rows = []
for f, cb, defspan, locks in entries:
    path = os.path.join(root, f)
    try:
        text = open(path, errors='replace').read()
        lines = text.splitlines()
    except Exception:
        continue
    for lock in locks:
        pat = re.compile(r'spin_lock\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        bh_pat = re.compile(r'spin_lock_bh\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        irq_pat = re.compile(r'spin_lock_irq\w*\s*\(\s*&?\s*' + re.escape(lock) + r'\s*\)')
        n_plain = len(pat.findall(text))
        n_bh = len(bh_pat.findall(text))
        n_irq = len(irq_pat.findall(text))
        # count plain sites outside the callback def span
        s, e = defspan.replace('def ', '').split('-')
        s, e = int(s), int(e)
        outside_plain = []
        for m in pat.finditer(text):
            ln = text[:m.start()].count('\n') + 1
            if not (s <= ln <= e):
                outside_plain.append(ln)
        if n_plain > 0:
            rows.append((f, cb, lock, n_plain, n_bh, n_irq, outside_plain[:10]))

rows.sort(key=lambda r: (-r[4] if False else 0))
print("locks with ANY plain spin_lock usage in same file:", len(rows))
for r in rows:
    print(f"{r[0]}\t{r[1]}\t{r[2]}\tplain={r[3]} bh={r[4]} irq={r[5]} plain_outside_cb={r[6]}")
with open(os.environ['TMPDIR'] + '/candidates_v3.txt','w') as o:
    for r in rows:
        o.write('\t'.join(map(str, r[:6])) + '\n')
