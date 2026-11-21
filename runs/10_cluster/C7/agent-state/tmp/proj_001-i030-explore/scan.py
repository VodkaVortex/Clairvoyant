import re, os, sys, collections

ROOT = 'snapshots/s01'
DIRS = ['drivers/net', 'drivers/staging', 'drivers/usb', 'drivers/atm', 'net']

files = []
for d in DIRS:
    for dp, dn, fns in os.walk(os.path.join(ROOT, d)):
        for fn in fns:
            if fn.endswith('.c'):
                files.append(os.path.join(dp, fn))

tasklet_res = [
    re.compile(r'tasklet_setup\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*\)'),
    re.compile(r'tasklet_init\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,'),
    re.compile(r'DECLARE_TASKLET(?:_OLD)?\(\s*\w+\s*,\s*([A-Za-z_]\w*)'),
]
napi_re = re.compile(r'\bnetif_napi_add\w*\s*\(')

def find_close_paren(text, start):
    depth = 0; i = start
    while i < len(text):
        c = text[i]
        if c == '(': depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0: return i
        i += 1
    return -1

def split_args(s):
    args = []; depth = 0; cur = ''
    for c in s:
        if c in '([': depth += 1
        elif c in ')]': depth -= 1
        if c == ',' and depth == 0:
            args.append(cur.strip()); cur = ''
        else: cur += c
    if cur.strip(): args.append(cur.strip())
    return args

filedata = {}
for f in files:
    try:
        t = open(f, encoding='utf8', errors='replace').read()
    except Exception:
        continue
    filedata[f] = t

def line_of(text, pos):
    return text.count('\n', 0, pos) + 1

def find_func_def(text, name):
    m = re.search(r'^[A-Za-z_][\w\s\*]*?\b' + re.escape(name) + r'\s*\(', text, re.M)
    if not m: return None
    cp = find_close_paren(text, m.end()-1)
    if cp < 0: return None
    brace = text.find('{', cp)
    if brace < 0 or brace - cp > 200: return None
    depth = 0; i = brace
    while i < len(text):
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0: return (m.start(), brace, i)
        i += 1
    return None

keywords = set('if for while switch sizeof return else do case'.split())
def callees_in_file(text, body, fname_defs):
    out = set()
    for m in re.finditer(r'\b([a-z_][a-z0-9_]*)\s*\(', body):
        n = m.group(1)
        if n in keywords or n in ('spin_lock','spin_unlock'): continue
        if n in fname_defs and n not in out:
            out.add(n)
    return out

plain_re = re.compile(r'spin_lock(?:_nested)?\s*\(\s*&?\s*([^,;()]+?)\s*[,)]')
anylock_re = re.compile(r'spin_(lock|unlock)\w*')

results = []
for f, text in filedata.items():
    lines = text.split('\n')
    # collect softirq entry funcs
    soft_entries = {}  # funcname -> kind
    for tr in tasklet_res:
        for m in tr.finditer(text):
            soft_entries[m.group(1)] = 'tasklet'
    for m in napi_re.finditer(text):
        cp = find_close_paren(text, m.end()-1)
        if cp < 0: continue
        args = split_args(text[m.end():cp])
        if len(args) >= 3:
            nm = args[2].strip()
            nm = re.sub(r'^&', '', nm).strip()
            if re.match(r'^[A-Za-z_]\w*$', nm):
                soft_entries[nm] = 'napi'
    if not soft_entries: continue
    # function definitions present in this file
    defs = {}
    for m in re.finditer(r'^[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\(', text, re.M):
        nm = m.group(1)
        if nm not in defs:
            d = find_func_def(text, nm)
            if d: defs[nm] = d
    # expand softirq func set (depth 2 within file)
    softset = dict(soft_entries)
    for nm, kind in list(soft_entries.items()):
        d = defs.get(nm)
        if not d: continue
        body = text[d[1]:d[2]]
        for c in callees_in_file(text, body, defs):
            if c not in softset: softset[c] = kind + '-callee'
            d2 = defs.get(c)
            if d2:
                body2 = text[d2[1]:d2[2]]
                for c2 in callees_in_file(text, body2, defs):
                    if c2 not in softset: softset[c2] = kind + '-callee2'
    # find plain lock acquisitions inside softirq funcs
    for nm, kind in softset.items():
        d = defs.get(nm)
        if not d: continue
        body = text[d[1]:d[2]]
        for pm in plain_re.finditer(body):
            lock = pm.group(1).strip()
            if not lock or len(lock) > 60: continue
            ln = line_of(text, d[1] + pm.start())
            results.append((f, nm, kind, ln, lock))

# group by (file, lock); normalized lock key
groups = collections.defaultdict(list)
for f, fn, kind, ln, lock in results:
    key = re.sub(r'\s+', '', lock).lstrip('&')
    groups[(f, key)].append((fn, kind, ln, lock))

def enclosing_func(lines, li):
    # li is 1-based line number
    i = li - 1
    while i >= 0:
        L = lines[i]
        m = re.match(r'^[A-Za-z_].*\(', L)
        if m and not L.strip().startswith(('if','for','while','switch','return')):
            mm = re.search(r'([A-Za-z_]\w*)\s*\(', L)
            if mm: return mm.group(1)
        i -= 1
    return '?'

out = open(os.path.join(os.environ['TMPDIR'], 'scan.out'), 'w')
scored = []
for (f, key), sites in groups.items():
    text = filedata[f]; lines = text.split('\n')
    softnames = set(fn for fn, kind, ln, lock in sites)
    # find all acquisition sites of this lock in the file
    others = []
    for i, L in enumerate(lines):
        if 'spin_lock' not in L and 'spin_unlock' not in L: continue
        if key not in L: continue
        ln = i + 1
        if any(ln == s_ln for fn, kind, s_ln, lock in sites): continue
        variant = 'plain' if re.search(r'spin_lock(?:_nested)?\s*\(', L) else ('bh' if '_bh' in L else ('irq*' if ('_irq' in L or 'irqsave' in L) else 'other'))
        encl = enclosing_func(lines, ln)
        others.append((ln, variant, encl, L.strip()[:110]))
    other_plain = [o for o in others if o[1] == 'plain' and o[2] not in softnames]
    bh_anywhere = any(o[1] == 'bh' for o in others)
    scored.append((len(other_plain), len(others), bh_anywhere, f, key, sites, others))

scored.sort(key=lambda x: (-x[0], -x[2], x[3]))
for np_, no, bh, f, key, sites, others in scored:
    if np_ == 0: continue
    out.write('='*100 + '\n')
    out.write('FILE %s  LOCK %s  (softirq-side sites below; other-plain=%d bh-in-file=%s)\n' % (f, key, np_, bh))
    for fn, kind, ln, lock in sites:
        out.write('  SOFTIRQ %-28s %-16s line %d : %s\n' % (fn, kind, ln, lock))
    for ln, variant, encl, L in others:
        if variant == 'plain':
            out.write('  OTHER  line %-6d %-10s in %-28s | %s\n' % (ln, variant, encl, L))
out.close()
# print summary
print('total softirq-side plain-lock candidates:', len(results))
print('groups with other plain sites:', sum(1 for s in scored if s[0] > 0))
print()
import subprocess
print(open(os.path.join(os.environ['TMPDIR'], 'scan.out')).read()[:14000])
