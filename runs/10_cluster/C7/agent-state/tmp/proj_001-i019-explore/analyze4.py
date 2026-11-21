import re, os, sys

root = os.getcwd()
entries = []
for l in open(os.environ['TMPDIR'] + '/timer_callbacks3.txt'):
    parts = l.rstrip('\n').split('\t')
    if len(parts) >= 3:
        f, cb, lns = parts[0], parts[1], parts[2]
        if cb == 'NULL':
            continue
        entries.append((f, cb, lns))

def read(p):
    try:
        return open(os.path.join(root, p), errors='replace').read().splitlines()
    except Exception:
        return []

# find function definition spans for each callback, then look for spin_lock inside
def find_def(lines, cb):
    # definition patterns
    pats = [
        re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:void|unsigned long|int|long|bool)\s+' + re.escape(cb) + r'\s*\('),
        re.compile(r'^\s*(?:static\s+)?[A-Za-z_][A-Za-z_0-9 \*]*\*' + re.escape(cb) + r'\s*\('),
    ]
    for i, ln in enumerate(lines):
        for p in pats:
            if p.search(ln):
                return i
    return None

def func_span(lines, start):
    # from start line, find first '{' then match braces
    depth = 0
    began = False
    for i in range(start, min(start+400, len(lines))):
        for ch in lines[i]:
            if ch == '{':
                depth += 1
                began = True
            elif ch == '}':
                depth -= 1
                if began and depth == 0:
                    return (start, i)
    return (start, min(start+399, len(lines)-1))

hits = []
for f, cb, lns in entries:
    lines = read(f)
    if not lines:
        continue
    d = find_def(lines, cb)
    if d is None:
        continue
    s, e = func_span(lines, d)
    body = '\n'.join(lines[s:e+1])
    locks = re.findall(r'spin_lock(?:_irqsave|_irq|_bh)?\s*\(\s*&?([A-Za-z_0-9\.\>\[\]\-]+)', body)
    if locks:
        hits.append((f, cb, lns, s+1, e+1, sorted(set(locks))))

print("callbacks containing spinlock acquisitions:", len(hits))
with open(os.environ['TMPDIR'] + '/timer_cb_with_locks.txt', 'w') as out:
    for f, cb, lns, s, e, locks in hits:
        out.write(f"{f}\t{cb}\treg@{lns}\tdef {s}-{e}\t{','.join(locks)}\n")
