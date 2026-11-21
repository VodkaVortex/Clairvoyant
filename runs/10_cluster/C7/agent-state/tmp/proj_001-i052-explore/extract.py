#!/usr/bin/env python3
"""Extract hardirq handler -> plain-lock pairs and cross-index with non-handler plain lock sites."""
import re, os, json

W = os.path.dirname(os.path.abspath(__file__))
S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s08"
regs = []
with open(os.path.join(W, "irq_regs.txt")) as f:
    for line in f:
        line = line.rstrip("\n")
        m = re.match(r'^(.*?):(\d+):(.*)$', line)
        if not m: continue
        regs.append((m.group(1), int(m.group(2)), m.group(3)))

handler_re = re.compile(r'(?:devm_)?request(?:_threaded)?_irq\s*\(')

def split_args(out):
    args = []
    cur = ''
    d2 = 0
    instr2 = False
    esc2 = False
    for c in out:
        if instr2:
            cur += c
            if esc2:
                esc2 = False
            elif c == '\\':
                esc2 = True
            elif c == '"':
                instr2 = False
            continue
        if c == '"':
            instr2 = True
            cur += c
            continue
        if c in '([':
            d2 += 1
        if c in ')]':
            d2 -= 1
        if c == ',' and d2 == 0:
            args.append(cur.strip())
            cur = ''
        else:
            cur += c
    if cur.strip():
        args.append(cur.strip())
    return args

def parse_handler(text, kind):
    m = handler_re.search(text)
    if not m:
        return []
    inner = text[m.end():]
    depth = 1
    i = 0
    out = ''
    while i < len(inner) and depth > 0:
        c = inner[i]
        if c == '"':
            j = i + 1
            while j < len(inner) and inner[j] != '"':
                if inner[j] == '\\':
                    j += 1
                j += 1
            out += inner[i:j+1]
            i = j + 1
            continue
        if c == '(':
            depth += 1
            out += c
        elif c == ')':
            depth -= 1
            if depth == 0:
                break
            out += c
        else:
            out += c
        i += 1
    args = split_args(out)
    if not args:
        return []
    def is_fn(a):
        a = a.strip()
        if a == 'NULL':
            return None
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', a):
            return a
        return None
    ids = []
    if kind in ('request_irq', 'devm_request_irq'):
        if len(args) > 1:
            h = is_fn(args[1])
            if h:
                ids.append(h)
    else:
        if len(args) > 1:
            h = is_fn(args[1])
            if h:
                ids.append(h)
    return ids

results = []
for path, lineno, text in regs:
    if 'request_threaded_irq' in text:
        kind = 'threaded'
    elif 'devm_request_irq' in text:
        kind = 'devm_request_irq'
    elif 'request_irq' in text:
        kind = 'request_irq'
    else:
        continue
    hs = parse_handler(text, kind)
    results.append({'path': path, 'line': lineno, 'kind': kind, 'handlers': hs, 'text': text.strip()})

filecache = {}
def get_file(path):
    if path not in filecache:
        try:
            with open(os.path.join(S, path), errors='replace') as f:
                filecache[path] = f.read().splitlines()
        except OSError:
            filecache[path] = None
    return filecache[path]

def find_funcs(lines, name):
    ranges = []
    pat = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\b' + re.escape(name) + r'\s*\(')
    n = len(lines)
    for i, l in enumerate(lines):
        if pat.match(l):
            k = i
            while k < n and k < i + 15:
                if '{' in lines[k]:
                    break
                k += 1
            if k >= n or k >= i + 15 or '{' not in lines[k]:
                continue
            depth = 0
            started = False
            m2 = k
            while m2 < n:
                depth += lines[m2].count('{') - lines[m2].count('}')
                if depth > 0:
                    started = True
                if started and depth <= 0:
                    ranges.append((i + 1, m2 + 1))
                    break
                m2 += 1
    return ranges

lock_acq = re.compile(r'\bspin_lock\s*\(\s*([^);]+?)\s*\)')
lock_irq = re.compile(r'\bspin_lock_irq(?:save)?\s*\(')

pairs = []
unresolved = []
for r in results:
    for h in r['handlers']:
        lines = get_file(r['path'])
        if lines is None:
            continue
        rngs = find_funcs(lines, h)
        if not rngs:
            unresolved.append((r['path'], r['line'], h, r['kind']))
            continue
        for (a, b) in rngs:
            for ln in range(a, b + 1):
                if ln - 1 >= len(lines):
                    break
                l = lines[ln - 1]
                if lock_irq.search(l):
                    continue
                for m in lock_acq.finditer(l):
                    pairs.append({'path': r['path'], 'regline': r['line'], 'handler': h,
                                  'kind': r['kind'], 'func_start': a, 'func_end': b,
                                  'acq_line': ln, 'lock': m.group(1)})

with open(os.path.join(W, "handler_plain_locks.json"), "w") as f:
    json.dump(pairs, f, indent=1)
with open(os.path.join(W, "unresolved_handlers.txt"), "w") as f:
    for u in unresolved:
        f.write("%s\n" % (u,))
print("registrations:", len(results))
print("handler-plain-lock acquisitions:", len(pairs))
print("distinct handler lock exprs:", len(set(p['lock'] for p in pairs)))
print("unresolved handlers:", len(set(u[2] for u in unresolved)))
