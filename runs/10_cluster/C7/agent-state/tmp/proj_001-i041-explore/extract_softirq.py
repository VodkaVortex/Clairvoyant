import re, os, subprocess, json, sys
from collections import defaultdict

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"

# gather all C files
cfiles = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    if '/Documentation' in dirpath: continue
    for f in filenames:
        if f.endswith('.c') or f.endswith('.h'):
            cfiles.append(os.path.join(dirpath, f))
cfiles.sort()

filecache = {}
def get_lines(path):
    if path not in filecache:
        try:
            with open(path, 'r', errors='replace') as fh:
                filecache[path] = fh.readlines()
        except Exception:
            filecache[path] = None
    return filecache[path]

# symbol table: function name -> (file, line index of definition start)
defs = {}
def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
for p in cfiles:
    lines = get_lines(p)
    if not lines: continue
    for i, ln in enumerate(lines):
        m = def_re.match(ln)
        if m and not ln.lstrip().startswith(('#', '//', '*', '/*')):
            name = m.group(1)
            defs.setdefault(name, (p, i))

def find_body_end(lines, start):
    # find first '{' from start, then match braces
    i = start
    depth = 0
    opened = False
    while i < len(lines):
        ln = lines[i]
        j = 0
        while j < len(ln):
            c = ln[j]
            if c == '{':
                depth += 1
                opened = True
            elif c == '}':
                depth -= 1
                if opened and depth == 0:
                    return i
            elif c == '"' or c == "'":
                q = c; j += 1
                while j < len(ln) and ln[j] != q:
                    if ln[j] == '\\': j += 1
                    j += 1
            elif ln.startswith('//', j):
                break
            j += 1
        if opened and depth == 0:
            return i
        i += 1
    return min(start + 400, len(lines) - 1)

lock_re = re.compile(r'spin_(lock|unlock|lock_irqsave|unlock_irqrestore|lock_irq|unlock_irq|lock_bh|unlock_bh|trylock)\s*\(\s*&?\s*([^),]+)')

def scan_function(fname):
    """return (file, startline, endline, list of (lineno, lockexpr, macro))"""
    if fname not in defs: return None
    p, i = defs[fname]
    lines = get_lines(p)
    end = find_body_end(lines, i)
    hits = []
    for k in range(i, end + 1):
        for m in lock_re.finditer(lines[k]):
            hits.append((k + 1, m.group(2).strip(), m.group(1)))
    return (p, i + 1, end + 1, hits)

# --- collect tasklet callbacks ---
tasklet_cbs = {}
pat_init = re.compile(r'tasklet_init\s*\(\s*&?[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
pat_decl = re.compile(r'DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
pat_assign = re.compile(r'(?:->|\.)func\s*=\s*([A-Za-z_][A-Za-z0-9_]*)')
for p in cfiles:
    lines = get_lines(p)
    if not lines: continue
    txt = ''.join(lines)
    for m in pat_init.finditer(txt):
        tasklet_cbs.setdefault(m.group(1), []).append((p, 'tasklet_init'))
    for m in pat_decl.finditer(txt):
        tasklet_cbs.setdefault(m.group(1), []).append((p, 'DECLARE_TASKLET'))
# only .func= assignments that mention tasklet nearby are ambiguous; skip unless near 'tasklet'
for p in cfiles:
    lines = get_lines(p)
    if not lines: continue
    for i, ln in enumerate(lines):
        if 'tasklet' in ln.lower() and ('.func' in ln or '->func' in ln):
            for m in pat_assign.finditer(ln):
                tasklet_cbs.setdefault(m.group(1), []).append((p, 'tasklet.func=%d' % (i+1)))

# --- collect NAPI poll functions ---
napi_polls = {}
pat_napi = re.compile(r'netif_napi_add\s*\(\s*[^,]+,\s*([^,]+?)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
for p in cfiles:
    lines = get_lines(p)
    if not lines: continue
    txt = ''.join(lines)
    for m in pat_napi.finditer(txt):
        napi_polls.setdefault(m.group(2), []).append((p, 'netif_napi_add'))
# also multi-line variants: netif_napi_add(dev, &x->napi,\n  poll_fn,
for p in cfiles:
    lines = get_lines(p)
    if not lines: continue
    for i, ln in enumerate(lines):
        if 'netif_napi_add' in ln:
            window = ''.join(lines[i:i+3])
            for m in pat_napi.finditer(window):
                napi_polls.setdefault(m.group(2), []).append((p, 'netif_napi_add_ml@%d' % (i+1)))

results = {'tasklet': {}, 'napi': {}}
for cb, regs in sorted(tasklet_cbs.items()):
    r = scan_function(cb)
    if r is None: continue
    p, s, e, hits = r
    if not hits: continue
    results['tasklet'][cb] = {'file': os.path.relpath(p, ROOT), 'start': s, 'end': e,
                              'regs': [os.path.relpath(rp, ROOT) + ':' + tag for rp, tag in regs],
                              'locks': [{'line': l, 'lock': lk, 'kind': k} for l, lk, k in hits]}
for cb, regs in sorted(napi_polls.items()):
    r = scan_function(cb)
    if r is None: continue
    p, s, e, hits = r
    if not hits: continue
    results['napi'][cb] = {'file': os.path.relpath(p, ROOT), 'start': s, 'end': e,
                           'regs': [os.path.relpath(rp, ROOT) + ':' + tag for rp, tag in regs],
                           'locks': [{'line': l, 'lock': lk, 'kind': k} for l, lk, k in hits]}

with open(os.path.join(os.environ['TMPDIR'], 'softirq_locks.json'), 'w') as fh:
    json.dump(results, fh, indent=1)

n_t = len(results['tasklet']); n_n = len(results['napi'])
plain_t = {cb: v for cb, v in results['tasklet'].items() if any(h['kind'] == 'lock' for h in v['locks'])}
plain_n = {cb: v for cb, v in results['napi'].items() if any(h['kind'] == 'lock' for h in v['locks'])}
print(f"tasklet cbs with spinlock ops: {n_t}, with plain spin_lock: {len(plain_t)}")
print(f"napi polls with spinlock ops: {n_n}, with plain spin_lock: {len(plain_n)}")
for cb, v in plain_t.items():
    print(f"TASKLET {cb} ({v['file']}:{v['start']}-{v['end']}) regs={v['regs'][:2]}")
    for h in v['locks']:
        if h['kind'] in ('lock', 'trylock'):
            print(f"   plain@{h['line']}: {h['lock']}")
for cb, v in plain_n.items():
    print(f"NAPI {cb} ({v['file']}:{v['start']}-{v['end']}) regs={v['regs'][:2]}")
    for h in v['locks']:
        if h['kind'] in ('lock', 'trylock'):
            print(f"   plain@{h['line']}: {h['lock']}")
