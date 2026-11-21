import re, os, subprocess, sys

ROOT = os.getcwd()  # snapshots/s13
def files_with(pat, subdirs):
    out = []
    for sd in subdirs:
        for dp, dn, fn in os.walk(os.path.join(ROOT, sd)):
            for f in fn:
                if f.endswith('.c'):
                    p = os.path.join(dp, f)
                    try:
                        t = open(p, errors='ignore').read()
                    except: continue
                    if re.search(pat, t):
                        out.append((p, t))
    return out

def func_body(text, name):
    # find definition: name( ... ) { ... }  (static or not), naive brace matching
    m = re.search(r'\n[A-Za-z_][\w\s\*,\(\)\[\]\-]*?\b%s\s*\(' % re.escape(name), text)
    if not m: return None, None
    start = m.start()+1
    # find opening brace after signature
    bi = text.find('{', m.end())
    if bi == -1: return None, None
    # make sure no ';' between m.end() and bi
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

def lock_uses(body):
    # returns set of lock expression names taken with plain spin_lock (not _bh/_irq/_irqsave)
    uses = {}
    for m in re.finditer(r'spin_lock\s*\(\s*&?([^)]+?)\s*\)', body):
        uses[m.group(1)] = 'plain'
    for m in re.finditer(r'spin_lock_bh\s*\(\s*&?([^)]+?)\s*\)', body):
        uses[m.group(1)] = 'bh'
    for m in re.finditer(r'spin_lock_irq(?:save)?\s*\(\s*&?([^,)]+?)\s*[,)]', body):
        uses[m.group(1)] = 'irq'
    return uses

def line_of(text, off):
    return text.count('\n', 0, off) + 1

tasklet_files = files_with(r'tasklet_init\s*\(|tasklet_setup\s*\(|DECLARE_TASKLET', ['drivers/net', 'drivers/staging', 'net', 'drivers/usb', 'sound', 'drivers/dma', 'drivers/crypto', 'drivers/mmc', 'drivers/scsi', 'drivers/infiniband', 'drivers/tty', 'drivers/char', 'drivers/media', 'drivers/isdn'])
print("TASKLET FILES:", len(tasklet_files))

results = []
for p, text in tasklet_files:
    # extract tasklet callback names
    cbs = set()
    for m in re.finditer(r'tasklet_init\s*\([^,]+,\s*([A-Za-z_]\w*)\s*,', text):
        cbs.add(m.group(1))
    for m in re.finditer(r'tasklet_setup\s*\([^,]+,\s*([A-Za-z_]\w*)\s*\)', text):
        cbs.add(m.group(1))
    for m in re.finditer(r'DECLARE_TASKLET\s*\([^,]+,\s*([A-Za-z_]\w*)\s*,', text):
        cbs.add(m.group(1))
    for cb in cbs:
        body, span = func_body(text, cb)
        if body is None: continue
        uses = lock_uses(body)
        for lk, kind in uses.items():
            if kind == 'plain':
                # find plain spin_lock sites of same lock elsewhere in file (outside the callback)
                sites = []
                for m in re.finditer(r'spin_lock\s*\(\s*&?%s\s*\)' % re.escape(lk), text):
                    ln = line_of(text, m.start())
                    sites.append(ln)
                results.append((p.replace(ROOT+'/',''), cb, lk, line_of(text, span[0]), sites))

for r in sorted(map(tuple, results)):
    print(r)
