import os, re, json
from collections import defaultdict

TMP = os.environ['TMPDIR']
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"
d = json.load(open(os.path.join(TMP, 'step1.json')))
reg_sites = d['reg_sites']

files_c = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if fn.endswith('.c'):
            files_c.append(os.path.join(dirpath, fn))
files_c.sort()

CTRL = {'if','for','while','switch','return','sizeof','else','do','case','goto','defined'}
defname_re = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*\s+)?\**\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;]*)$')

handler_defs = {}  # name -> (rel, line)
for path in files_c:
    rel = os.path.relpath(path, ROOT)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().split('\n')
    except Exception:
        continue
    n = len(lines)
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s or s.startswith('#') or s.startswith('*') or s.startswith('/*') or s.startswith('//'):
            continue
        m = defname_re.match(s)
        if not m:
            continue
        name = m.group(1)
        if name in CTRL:
            continue
        # signature may span lines; join until we find the balancing ')' then check for '{'
        buf = s
        k = i
        ok = False
        while k < n and k - i < 20:
            if buf.count('(') <= buf.count(')'):
                break
            k += 1
            buf += ' ' + lines[k].strip()
        if buf.count('(') > buf.count(')'):
            continue
        # check for '{' after the closing paren
        tail = buf[buf.rindex(')')+1:].strip()
        if tail.startswith('{'):
            ok = True
        else:
            # look at following non-blank lines for '{' as first char
            kk = k + 1
            while kk < n and kk - k < 4:
                t = lines[kk].strip()
                if t == '':
                    kk += 1; continue
                if t.startswith('{'):
                    ok = True
                break
        if ok:
            handler_defs.setdefault(name, (rel, i+1))

print('handler defs:', len(handler_defs))

resolved, unresolved = [], []
for rel, ln, h in reg_sites:
    if h and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', h) and h in handler_defs:
        resolved.append((rel, ln, h, handler_defs[h][0], handler_defs[h][1]))
    else:
        unresolved.append((rel, ln, h))
print('resolved:', len(resolved), 'unresolved:', len(unresolved))

by_def = defaultdict(list)
for rel, ln, h, dfile, dline in resolved:
    by_def[(dfile, dline, h)].append((rel, ln))

cache = {}
def get_lines(rel):
    if rel not in cache:
        try:
            with open(os.path.join(ROOT, rel), 'r', encoding='utf-8', errors='replace') as f:
                cache[rel] = f.read().split('\n')
        except Exception:
            cache[rel] = []
    return cache[rel]

def brace_forward(lines, start):
    i = start; depth = 0; started = False; n = len(lines)
    while i < n:
        ln = lines[i]; j = 0; L = len(ln); in_s = in_c = False
        while j < L:
            c = ln[j]
            if in_c:
                if c == '*' and j+1 < L and ln[j+1] == '/': in_c = False; j += 2; continue
                j += 1; continue
            if in_s:
                if c == '\\': j += 2; continue
                if c == '"': in_s = False
                j += 1; continue
            if c == '/' and j+1 < L and ln[j+1] == '/': break
            if c == '/' and j+1 < L and ln[j+1] == '*': in_c = True; j += 2; continue
            if c == '"': in_s = True; j += 1; continue
            if c == "'":
                j += 1
                while j < L:
                    if ln[j] == '\\': j += 2; continue
                    if ln[j] == "'": break
                    j += 1
                j += 1; continue
            if c == '{': depth += 1; started = True
            elif c == '}':
                depth -= 1
                if started and depth == 0: return i, j
            j += 1
        i += 1
    return n-1, -1

spin_re = re.compile(r'\bspin_lock(_irqsave|_irq|_bh|_irqrestore|_nested)?\s*\(\s*([^;]*?)\s*\)')
results = []
plain_handlers = []
for (dfile, dline, hname), regs in by_def.items():
    lines = get_lines(dfile)
    if not lines:
        continue
    i0 = dline - 1; brace_line = None; k = i0; n = len(lines)
    while k < n and k - i0 < 20:
        if '{' in lines[k]:
            # make sure this '{' follows the signature close paren, take first
            brace_line = k; break
        if ';' in lines[k]: break
        k += 1
    if brace_line is None:
        continue
    end_line, _ = brace_forward(lines, brace_line)
    body = lines[brace_line:end_line+1]
    locksites = []
    for off, ln in enumerate(body):
        for m in spin_re.finditer(ln):
            suffix = m.group(1) or ''
            arg = m.group(2)
            locksites.append((brace_line + off + 1, suffix or 'plain', arg))
    if locksites:
        plain = [ls for ls in locksites if ls[1] in ('plain', '_bh')]
        results.append({'handler': hname, 'file': dfile, 'def_line': dline, 'end_line': end_line+1,
                        'regs': regs, 'locks': locksites, 'n_plain': len(plain), 'n_bh': len([l for l in locksites if l[1]=='_bh'])})
        if plain:
            plain_handlers.append((dfile, dline, hname, plain))

print('handlers with lock sites:', len(results))
print('handlers with plain/bh spin_lock:', len(plain_handlers))
json.dump(results, open(os.path.join(TMP, 'handlers.json'), 'w'))
json.dump(unresolved, open(os.path.join(TMP, 'unresolved.json'), 'w'))
for p in plain_handlers:
    print(p[0], p[1], p[2], [(x[0], x[2]) for x in p[3]][:6])
