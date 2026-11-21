import re, os, json

files = [l.strip() for l in open(os.environ['W']+'/napi_files.txt')]

def func_body_span(src, fname):
    for m in re.finditer(r'\b'+re.escape(fname)+r'\b\s*\(', src):
        i = m.end(); depth=1
        while i < len(src) and depth:
            if src[i]=='(': depth+=1
            elif src[i]==')': depth-=1
            i+=1
        j = i
        while j < len(src) and src[j] in ' \t\r\n': j+=1
        if j < len(src) and src[j]=='{':
            depth=0; k=j
            while k < len(src):
                if src[k]=='{': depth+=1
                elif src[k]=='}':
                    depth-=1
                    if depth==0:
                        return j, k+1
                k+=1
    return None

def line_of(src, pos):
    return src.count('\n', 0, pos)+1

LOCKRE = re.compile(r'spin_lock\s*\(\s*&?([^);]+?)\s*\)')
CALLRE = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')

def callee_names(body, defined):
    names = set()
    for m in CALLRE.finditer(body):
        n = m.group(1)
        if n in defined and n not in ('if','for','while','switch','sizeof','return','spin_lock','spin_unlock'):
            names.add(n)
    return names

results = []
for f in files:
    try:
        src = open(f, errors='replace').read()
    except Exception:
        continue
    # poll function names from netif_napi_add(dev, &x, name, ...) or netif_napi_add_weight / netif_napi_add_tx
    polls = []
    for m in re.finditer(r'netif_napi_add(?:_weight|_tx)?\s*\([^;]*?\)', src, re.S):
        args = m.group(0)
        parts = args.split(',')
        # find first arg that looks like an identifier not starting with & and not 'NAPI_POLL_WEIGHT'
        for p in parts[2:]:
            p = p.strip()
            if re.fullmatch(r'[a-zA-Z_]\w*', p):
                polls.append(p); break
    polls = [p for p in dict.fromkeys(polls) if func_body_span(src, p)]
    if not polls: continue
    # defined function names in file (static defs)
    defined = set(re.findall(r'(?:static\s+)?(?:inline\s+)?[\w\s\*]+?\b([a-zA-Z_]\w*)\s*\([^;{]*\)\s*\{', src))
    softfuncs = set(polls)
    for p in polls:
        span = func_body_span(src, p)
        body = src[span[0]:span[1]]
        softfuncs |= callee_names(body, defined)
    # locks inside softirq-side functions (poll + direct callees)
    soft_locks = {}
    for fn in softfuncs:
        span = func_body_span(src, fn)
        if not span: continue
        body = src[span[0]:span[1]]
        for lm in LOCKRE.finditer(body):
            lock = lm.group(1).strip()
            soft_locks.setdefault(lock, []).append((fn, line_of(src, span[0]+lm.start())))
    if not soft_locks: continue
    lockbases = {lk.split('.')[-1].split('->')[-1]: lk for lk in soft_locks}
    for m in LOCKRE.finditer(src):
        lock = m.group(1).strip()
        base = lock.split('.')[-1].split('->')[-1]
        if base in lockbases:
            ln = line_of(src, m.start())
            inside = False
            for fn in softfuncs:
                span = func_body_span(src, fn)
                if span and span[0] <= m.start() < span[1]:
                    inside = True; break
            if not inside:
                results.append((f, ln, lock, ";".join(f"{fn2}:{ln2}" for lk in soft_locks.values() for fn2,ln2 in lk)))

for r in sorted(set(results)):
    print(json.dumps(list(r)))
