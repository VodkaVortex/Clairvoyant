import os, re
Tree = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
T = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore/i046'
call = re.compile(r'\b(?:devm_)?request(?:_threaded|_any|_percpu|_noprobe|_pirq)?_irq(?:_exclusive|_arrays|_resources|_free)?\s*\(')
plain = re.compile(r'\bspin_lock\s*\(')

def read(fp): return open(fp, encoding='utf-8', errors='replace').read()

def arg2(text, i):
    depth = 0; j = i
    while j < len(text):
        c = text[j]
        if c == '(': depth += 1
        elif c == ')':
            if depth == 0: break
            depth -= 1
        elif c == ';' and depth == 0: break
        j += 1
    args = text[i:j]
    parts, buf, d = [], [], 0
    for ch in args:
        if ch in '([': d += 1
        elif ch in ')]': d -= 1
        if ch == ',' and d == 0: parts.append(''.join(buf)); buf = []
        else: buf.append(ch)
    parts.append(''.join(buf))
    return parts

files = []
for dp, _, fs in os.walk(Tree):
    for f in fs:
        if f.endswith(('.c', '.h')): files.append(os.path.join(dp, f))
pref = ('drivers/', 'sound/', 'net/', 'fs/', 'kernel/', 'block/', 'crypto/', 'arch/', 'lib/')

global_handlers = {}
for fp in files:
    rel = os.path.relpath(fp, Tree)
    if not rel.startswith(pref): continue
    src = read(fp)
    for m in call.finditer(src):
        parts = arg2(src, m.end())
        if len(parts) >= 2:
            h = parts[1].strip()
            h = re.sub(r'^\([^\)]*\)\s*', '', h)
            h = h.split('=')[0].strip()
            nm = re.match(r'^[A-Za-z_]\w*', h)
            if nm:
                global_handlers.setdefault(nm.group(0), rel)
print('handlers:', len(global_handlers), flush=True)

# definitions: match 'name(' preceded by non-ident char, line contains ) { or )\n{
handler_def = {}
for fp in files:
    rel = os.path.relpath(fp, Tree)
    src = read(fp)
    for h in global_handlers:
        if h in handler_def: continue
        for m in re.finditer(r'(?<![\w.>])' + re.escape(h) + r'\s*\(', src):
            # look backwards: must be definition start (newline, ';', '}', or file start) within ~120 chars
            s = max(0, m.start()-120)
            pre = src[s:m.start()]
            lastnl = pre.rfind('\n')
            first = pre[lastnl+1:] if lastnl >= 0 else pre
            if first.strip() == '' or first.strip().endswith(('(', ';', '{', '}', ',')):
                continue  # call site or indented continuation
            # must not be preceded by '&' or '->' or '.'
            if first.rstrip().endswith(('&', '>', '.')): continue
            handler_def[h] = (rel, src[:m.start()].count('\n')+1)
            break
print('resolved defs:', len(handler_def), flush=True)

results = []
for h, (rel, ln) in handler_def.items():
    src = read(os.path.join(Tree, rel))
    lines = src.split('\n')
    depth = 0; started = False; body = []
    k = ln - 1
    while k < len(lines) and k - ln < 400:
        body.append(lines[k])
        depth += lines[k].count('{') - lines[k].count('}')
        if '{' in lines[k]: started = True
        if started and depth <= 0: break
        k += 1
    btext = '\n'.join(body)
    if plain.search(btext):
        results.append((rel, ln, h))
with open(os.path.join(T, 'handlers_plain.txt'), 'w') as f:
    for rel, ln, h in sorted(results): f.write(f'{rel}:{ln}\t{h}\n')
print('handlers with plain spin_lock:', len(results), flush=True)
