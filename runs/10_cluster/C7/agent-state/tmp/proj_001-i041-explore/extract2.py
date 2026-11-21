import re, os, json
from collections import defaultdict

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
cfiles = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    if '/Documentation' in dirpath: continue
    for f in filenames:
        if f.endswith(('.c', '.h')):
            cfiles.append(os.path.join(dirpath, f))
cfiles.sort()

src = {}
for p in cfiles:
    try:
        src[p] = open(p, errors='replace').read()
    except Exception:
        pass

def find_name_in(fname, txt):
    # find "fname(" where preceding char is not [A-Za-z0-9_]
    out = []
    start = 0
    while True:
        i = txt.find(fname + '(', start)
        if i < 0: break
        j = i + len(fname)
        if i == 0 or not (txt[i-1].isalnum() or txt[i-1] == '_'):
            # count newlines before
            line = txt.count('\n', 0, i) + 1
            out.append((i, line))
        start = i + 1
    return out

def find_body_end(txt, pos):
    i = txt.find('{', pos)
    if i < 0: return -1
    depth = 0
    j = i
    n = len(txt)
    while j < n:
        c = txt[j]
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return j
        elif c == '"':
            j += 1
            while j < n and txt[j] != '"':
                if txt[j] == '\\': j += 1
                j += 1
        elif c == "'":
            j += 1
            while j < n and txt[j] != "'":
                if txt[j] == '\\': j += 1
                j += 1
        elif c == '/' and j+1 < n and txt[j+1] == '*':
            j = txt.find('*/', j+2)
            if j < 0: return -1
        elif c == '/' and j+1 < n and txt[j+1] == '/':
            j = txt.find('\n', j)
            if j < 0: return -1
        j += 1
    return -1

lock_re = re.compile(r'spin_(lock|unlock|lock_irqsave|unlock_irqrestore|lock_irq|unlock_irq|lock_bh|unlock_bh|trylock)\s*\(\s*&?\s*([^),]+)')

def body_bounds(fname, txt):
    """Locate the definition body (identifier followed by '(' preceded by type-ish text and NOT '->'/'.'); return (start_idx, brace_start, brace_end)."""
    for pos, line in find_name_in(fname, txt):
        # look backwards to line start; must look like definition: previous char sequence from line start
        ls = txt.rfind('\n', 0, pos) + 1
        prefix = txt[ls:pos].strip()
        # a definition: prefix like "static void", "int", "static inline struct foo *", or empty (macro continuation) — reject if prefix contains '}' or ';' at end (i.e., a call statement or assignment)
        if prefix.endswith('=') or prefix.endswith(';') or prefix.endswith('}'):
            continue
        # reject if within prefix there's a control keyword ending
        # check for "if", "else if", "while", "switch", "return" directly preceding (would be part of same prefix ending with keyword)
        # find brace after pos within same statement (before next ';')
        semi = txt.find(';', pos)
        brace = txt.find('{', pos)
        if brace >= 0 and (semi < 0 or brace < semi):
            end = find_body_end(txt, pos)
            if end > brace:
                return pos, brace, end
    return None

def scan_function(fname):
    if fname not in defs: return None
    p = defs[fname]
    txt = src.get(p)
    if txt is None: return None
    r = body_bounds(fname, txt)
    if not r: return None
    pos, b0, b1 = r
    body = txt[b0:b1]
    hits = []
    off = b0
    for m in lock_re.finditer(body):
        line = txt.count('\n', 0, off + m.start()) + 1
        hits.append((line, m.group(2).strip(), m.group(1)))
    sline = txt.count('\n', 0, pos) + 1
    eline = txt.count('\n', 0, b1) + 1
    return p, sline, eline, hits

# tasklet callbacks
pat_init = re.compile(r'tasklet_init\s*\(\s*&?\s*[^,()]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
pat_decl = re.compile(r'DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*[^,()]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
tasklet_cbs = {}
for p in cfiles:
    txt = src.get(p)
    if txt is None: continue
    for m in pat_init.finditer(txt):
        tasklet_cbs.setdefault(m.group(1), []).append((p, 'tasklet_init@%d' % (txt.count('\n',0,m.start())+1)))
    for m in pat_decl.finditer(txt):
        tasklet_cbs.setdefault(m.group(1), []).append((p, 'DECLARE_TASKLET@%d' % (txt.count('\n',0,m.start())+1)))

napi_polls = {}
pat_napi = re.compile(r'netif_napi_add\s*\(\s*[^,()]+,\s*([^,()]+?)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
for p in cfiles:
    txt = src.get(p)
    if txt is None: continue
    for m in pat_napi.finditer(txt):
        napi_polls.setdefault(m.group(2), []).append((p, 'netif_napi_add@%d' % (txt.count('\n',0,m.start())+1)))

# build defs: name -> first file defining it (prefer same file as registration)
def build_defs_for(names):
    global defs
    defs = {}
    for nm in names:
        for p in cfiles:
            txt = src.get(p)
            if txt is None: continue
            if nm + '(' not in txt: continue
            r = body_bounds(nm, txt)
            if r:
                defs[nm] = p
                break

results = {'tasklet': {}, 'napi': {}}
for kind, cbs in (('tasklet', tasklet_cbs), ('napi', napi_polls)):
    build_defs_for(list(cbs.keys()))
    for cb, regs in sorted(cbs.items()):
        r = scan_function(cb)
        if r is None: continue
        p, s, e, hits = r
        if not hits: continue
        results[kind][cb] = {'file': os.path.relpath(p, ROOT), 'start': s, 'end': e,
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
    print(f"TASKLET {cb} ({v['file']}:{v['start']}-{v['end']})")
    for h in v['locks']:
        print(f"   {h['kind']:8s}@{h['line']}: {h['lock']}")
print('====NAPI====')
for cb, v in plain_n.items():
    print(f"NAPI {cb} ({v['file']}:{v['start']}-{v['end']})")
    for h in v['locks']:
        print(f"   {h['kind']:8s}@{h['line']}: {h['lock']}")
