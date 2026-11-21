import os, re, json, sys
from collections import defaultdict

TMP = os.environ['TMPDIR']
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"
d = json.load(open(os.path.join(TMP, 'step1.json')))
reg_sites = d['reg_sites']
handler_defs = d['handler_defs']

# Resolve handler name -> def file/line
resolved, unresolved = [], []
for rel, ln, h in reg_sites:
    if h and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', h):
        if h in handler_defs:
            resolved.append((rel, ln, h, handler_defs[h][0], handler_defs[h][1]))
        else:
            unresolved.append((rel, ln, h))
    else:
        unresolved.append((rel, ln, h))
print('resolved:', len(resolved), 'unresolved:', len(unresolved))

# Group registrations by handler definition
by_def = defaultdict(list)
for rel, ln, h, dfile, dline in resolved:
    by_def[(dfile, dline, h)].append((rel, ln))

# Load per-file source caches
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
    """Return index after matching '}' for function body starting at line `start` (index where '{' found).
    Handles braces, strings and comments crudely."""
    i = start
    depth = 0
    started = False
    n = len(lines)
    while i < n:
        ln = lines[i]
        j = 0
        L = len(ln)
        in_s = in_c = False
        # persist string/comment state across lines crudely (block comments)
        while j < L:
            c = ln[j]
            if in_c:
                if c == '*' and j+1 < L and ln[j+1] == '/':
                    in_c = False; j += 2; continue
                j += 1; continue
            if in_s:
                if c == '\\':
                    j += 2; continue
                if c == '"':
                    in_s = False
                j += 1; continue
            if c == '/' and j+1 < L and ln[j+1] == '/':
                break
            if c == '/' and j+1 < L and ln[j+1] == '*':
                in_c = True; j += 2; continue
            if c == '"':
                in_s = True; j += 1; continue
            if c == "'":
                # char literal; skip till closing quote on this line
                j += 1
                while j < L:
                    if ln[j] == '\\': j += 2; continue
                    if ln[j] == "'": break
                    j += 1
                j += 1; continue
            if c == '{':
                depth += 1; started = True
            elif c == '}':
                depth -= 1
                if started and depth == 0:
                    return i, j
            j += 1
        i += 1
    return n-1, -1

spin_re = re.compile(r'\bspin_lock(?:_irqsave|_irq|_bh|_irqrestore|_nested)?\s*\(\s*([^)]*?)\s*\)')
write_re = re.compile(r'\bwrite_lock(?:_irqsave|_irq|_bh|_irqrestore)?\s*\(\s*([^)]*?)\s*\)')

results = []  # per handler: list of lock acquisition sites
plain_handlers = []

for (dfile, dline, hname), regs in by_def.items():
    lines = get_lines(dfile)
    if not lines:
        continue
    # find body start: from dline-1 index forward, find first '{' within 12 lines
    i0 = dline - 1
    brace_line = None
    k = i0
    n = len(lines)
    while k < n and k - i0 < 12:
        if '{' in lines[k]:
            brace_line = k; break
        if ';' in lines[k]:
            break
        k += 1
    if brace_line is None:
        continue
    end_line, _ = brace_forward(lines, brace_line)
    body = lines[brace_line:end_line+1]
    # collect lock sites
    locksites = []
    for off, ln in enumerate(body):
        for m in spin_re.finditer(ln):
            arg = m.group(1)
            flags = m.group(0)
            locksites.append((brace_line + off + 1, 'plain' if flags.startswith('spin_lock(') else flags[flags.index('(')-len('spin_lock'):flags.index('(')] or 'plain', arg))
    if locksites:
        plain = [ls for ls in locksites if ls[1] == 'plain']
        results.append({'handler': hname, 'file': dfile, 'def_line': dline, 'end_line': end_line+1,
                        'regs': regs, 'locks': locksites, 'n_plain': len(plain)})
        if plain:
            plain_handlers.append((dfile, dline, hname, plain))

print('handlers with lock sites:', len(results))
print('handlers with plain spin_lock:', len(plain_handlers))
json.dump(results, open(os.path.join(TMP, 'handlers.json'), 'w'))
json.dump(unresolved, open(os.path.join(TMP, 'unresolved.json'), 'w'))
for p in plain_handlers[:80]:
    print(p)
