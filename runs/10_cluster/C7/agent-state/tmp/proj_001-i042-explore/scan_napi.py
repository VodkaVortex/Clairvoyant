import re, os

ROOT = os.getcwd()

def func_body(text, name):
    m = re.search(r'\n[A-Za-z_][\w\s\*,\(\)\[\]\-]*?\b%s\s*\(' % re.escape(name), text)
    if not m: return None, None
    start = m.start()+1
    bi = text.find('{', m.end())
    if bi == -1: return None, None
    if ';' in text[m.end():bi]: return None, None
    depth = 0
    for i in range(bi, len(text)):
        c = text[i]
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[start:i+1], (start, i)
    return None, None

def plain_locks(body):
    names = set()
    for m in re.finditer(r'spin_lock\s*\(\s*&?([A-Za-z_][\w\.\[\]>-]*)', body):
        names.add(m.group(1))
    return names

def line_of(text, off):
    return text.count('\n', 0, off) + 1

files = []
for dp, dn, fn in os.walk(ROOT):
    if '/drivers/net/' not in dp and not dp.startswith(ROOT+'/drivers/net/') and '/net/' not in dp.replace(ROOT+'/net/','x',1):
        # walk everything under drivers/net and net
        pass
    rel = os.path.relpath(dp, ROOT)
    if rel.startswith('drivers/net') or rel.startswith('net/') or rel == 'net':
        for f in fn:
            if f.endswith('.c'):
                files.append(os.path.join(dp, f))

results = []
for p in files:
    try: text = open(p, errors='ignore').read()
    except: continue
    polls = set()
    for m in re.finditer(r'netif_napi_add(?:_weight)?(?:_exclusive)?\s*\([^;]*?,\s*([A-Za-z_]\w*)\s*,', text):
        polls.add(m.group(1))
    for m in re.finditer(r'netif_napi_add_tx\s*\([^,]+,\s*([A-Za-z_]\w*)\s*,', text):
        polls.add(m.group(1))
    for cb in polls:
        body, span = func_body(text, cb)
        if body is None: continue
        names = plain_locks(body)
        if not names: continue
        rel = os.path.relpath(p, ROOT)
        for lk in names:
            sites = [line_of(text, m.start()) for m in re.finditer(r'spin_lock\s*\(\s*&?%s\s*\)' % re.escape(lk), text)]
            bh = [line_of(text, m.start()) for m in re.finditer(r'spin_lock_bh\s*\(\s*&?%s\s*\)' % re.escape(lk), text)]
            irq = [line_of(text, m.start()) for m in re.finditer(r'spin_lock_irq(?:save)?\s*\(\s*&?%s\s*[,)]' % re.escape(lk), text)]
            results.append((rel, cb, lk, line_of(text, span[0]), sites, bh, irq))

for r in sorted(results):
    print(r)
