import re, os, sys, json, collections

ROOT = os.getcwd()
tasklet_regs = open(os.environ['T'] + '/tasklet_regs.txt').read().splitlines()
napi_regs = open(os.environ['T'] + '/napi_regs.txt').read().splitlines()

def extract_cb(code):
    # tasklet_init(&x, name, ...) / tasklet_setup(&x, name) / DECLARE_TASKLET(name, func, ...)
    code = code.strip()
    m = re.match(r'.*tasklet_init\s*\(', code)
    if m:
        inner = code[code.index('(')+1:]
        # strip trailing ); etc
        parts = [p.strip() for p in inner.rsplit(';',1)[0].rstrip(')').split(',')]
        if len(parts) >= 2:
            return parts[1].lstrip('(').strip()
    m = re.match(r'.*tasklet_setup\s*\(', code)
    if m:
        inner = code[code.index('(')+1:]
        parts = [p.strip() for p in inner.rsplit(';',1)[0].rstrip(')').split(',')]
        if len(parts) >= 2:
            return parts[1].strip()
    return None

def extract_napi(code):
    # netif_napi_add(dev, &n, poll, weight) or (dev, poll, weight) old style
    code = code.strip()
    inner = code[code.index('(')+1:]
    parts = [p.strip() for p in inner.rsplit(';',1)[0].rstrip(')').split(',')]
    # last-but-one or second arg is the poll fn; find identifier that looks like a function name
    for p in parts:
        p = p.lstrip('&').strip()
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', p) and p not in ('NAPI_POLL_WEIGHT',):
            # heuristics: the poll fn is typically 2nd arg or 3rd; dev name may also be identifier
            pass
    # positional: pick the identifier that is not 'dev'-like: just return all identifiers
    return [p.lstrip('&').strip() for p in parts if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', p.lstrip('&').strip())]

cb_map = collections.defaultdict(set)   # file -> set of softirq callback names
for line in tasklet_regs:
    f, ln, code = line.split(':', 2)
    n = extract_cb(code)
    if n and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', n.lstrip('(')):
        cb_map[f].add(n.lstrip('(').strip())

for line in napi_regs:
    f, ln, code = line.split(':', 2)
    if 'netif_napi_add' in code:
        for n in extract_napi(code):
            cb_map[f].add(n)

def get_func_body(src, fname):
    # find definition: name( ... ) { ... }
    pat = re.compile(r'\b' + re.escape(fname) + r'\s*\(')
    out = []
    idx = 0
    while True:
        m = pat.search(src, idx)
        if not m: break
        # find the opening brace of the body
        i = m.end()
        depth_p = 1
        # skip to matching close paren of param list
        while i < len(src) and depth_p > 0:
            if src[i] == '(': depth_p += 1
            elif src[i] == ')': depth_p -= 1
            i += 1
        # skip whitespace/newlines to '{'
        j = i
        while j < len(src) and src[j] in ' \t\n\r': j += 1
        if j >= len(src) or src[j] != '{':
            idx = m.end()
            continue
        # brace match
        k = j; depth = 0
        while k < len(src):
            if src[k] == '{': depth += 1
            elif src[k] == '}':
                depth -= 1
                if depth == 0: break
            k += 1
        body = src[j:k+1]
        # record line number of start
        line_no = src[:j].count('\n') + 1
        out.append((line_no, body))
        idx = k
    return out

LOCK_RE = re.compile(r'\b(spin_lock|spin_trylock|spin_lock_nested|spin_lock_bh|spin_lock_irq|spin_lock_irqsave|spin_unlock|spin_unlock_bh|spin_unlock_irq|spin_unlock_irqrestore)\s*\(')

def lock_calls(body):
    res = []
    for m in LOCK_RE.finditer(body):
        # extract arg
        i = m.end(); depth = 1; start = i
        while i < len(body) and depth > 0:
            if body[i] == '(': depth += 1
            elif body[i] == ')': depth -= 1
            i += 1
        arg = body[start:i-1].strip()
        res.append((m.group(1), arg))
    return res

def base_of(arg):
    # last identifier component of &priv->foo or q->lock or lock
    arg = arg.strip().lstrip('&').strip()
    ids = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', arg)
    return ids[-1] if ids else None

CALL_RE = re.compile(r'\b([a-z_][a-z0-9_]*)\s*\(')

softirq_locks = []  # entries: dict(file, cb, line, kind=napi/tasklet, lockarg, base)
all_funcs_bodies = {}

results = []
for f, cbs in cb_map.items():
    path = os.path.join(ROOT, f)
    if not os.path.exists(path): continue
    src = open(path, errors='replace').read()
    lines = src.split('\n')
    for cb in cbs:
        bodies = get_func_body(src, cb)
        for (ln, body) in bodies:
            locks = lock_calls(body)
            # one-level same-file callees
            callees = set()
            for cm in CALL_RE.finditer(body):
                nm = cm.group(1)
                if nm in ('spin_lock','spin_unlock','spin_lock_bh','spin_unlock_bh','spin_lock_irqsave','spin_unlock_irqrestore','spin_lock_irq','spin_unlock_irq','spin_trylock','spin_lock_nested','if','while','for','switch','sizeof','return','min','max','cpu_to_le32','le32_to_cpu','dev_kfree_skb','kfree','kmalloc','memcpy','memset','WARN_ON','BUG_ON','readl','writel','ioread32','iowrite32'): continue
                callees.add(nm)
            callee_locks = []
            for c in callees:
                for (cln, cbody) in get_func_body(src, c):
                    callee_locks.extend(lock_calls(cbody))
            all_locks = locks + callee_locks
            if not all_locks: continue
            for (kind, arg) in all_locks:
                b = base_of(arg)
                if not b: continue
                results.append(dict(file=f, cb=cb, line=ln, base=b, arg=arg, kind=kind, napi=(f in [x.split(':')[0] for x in napi_regs if True])))

# dedupe
seen = set()
uniq = []
for r in results:
    key = (r['file'], r['cb'], r['base'], r['kind'])
    if key in seen: continue
    seen.add(key)
    uniq.append(r)

json.dump(uniq, open(os.environ['T']+'/softirq_locks.json','w'), indent=0)
print(len(uniq), "softirq-side lock sites")
