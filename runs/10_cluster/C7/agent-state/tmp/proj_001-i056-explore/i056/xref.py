import os, re
from collections import defaultdict

out = os.path.join(os.environ['TMPDIR'], 'i056')
ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12'

handlers = []
with open(os.path.join(out, 'handlers.txt')) as fh:
    for ln in fh:
        rel, line, api = ln.strip().rsplit(':', 2)
        handlers.append((rel, int(line), api))

locks = []
with open(os.path.join(out, 'locks.txt')) as fh:
    for ln in fh:
        rel, line, fn, kind, expr = ln.strip().split(':', 4)
        locks.append((rel, int(line), fn, kind, expr))

# group handlers by file
hby = defaultdict(list)
for rel, line, api in handlers:
    hby[rel].append((line, api))

lby = defaultdict(list)
for rel, line, fn, kind, expr in locks:
    lby[rel].append((line, fn, kind, expr))

# parse handler names: from the registration text (first argument that looks like identifier, or second for devm)
# We captured text in scan but not stored; re-derive by reading files.
handler_names = {}  # (rel,line) -> name
irq_call = re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq)\s*\(')
for rel, hlist in hby.items():
    path = os.path.join(ROOT, rel)
    try:
        lines = open(path, errors='replace').readlines()
    except Exception:
        continue
    for line, api in hlist:
        text = ''.join(lines[line-1:line+6])
        # candidate identifiers before ',' — take first identifier that is not dev/irq/flags
        ids = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', text)
        # skip leading: devm_ -> skip 'dev'; request_irq -> first arg is handler (unsigned int irq may be expr)
        name = None
        skipwords = {'request_irq','devm_request_irq','request_threaded_irq','devm','request','irq','dev','void','static','int','unsigned','return','NULL','IRQF','if','ret'}
        for x in ids:
            if x in skipwords: continue
            if re.match(r'^IRQF_', x) or re.match(r'^[A-Z0-9_]+$', x): continue
            name = x; break
        handler_names[(rel, line)] = (api, name)

# cross-index: for each file, for each handler name, find lock sites inside handler body
# function bodies: find definition line of handler in same file
results = []
for rel in sorted(hby):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path): continue
    try:
        lines = open(path, errors='replace').readlines()
    except Exception:
        continue
    fl = lby.get(rel, [])
    for (line, api) in hby[rel]:
        api2, hname = handler_names.get((rel, line), (api, None))
        if not hname: continue
        # find def: line where func starts
        defline = None
        pat = re.compile(r'^[A-Za-z_].*\b' + re.escape(hname) + r'\s*\(')
        for i, l in enumerate(lines, 1):
            if pat.match(l) and i != line:
                defline = i; break
        if defline is None: continue
        # body end: next line starting with '}' at col 0 after defline
        end = None
        for j in range(defline, min(len(lines), defline+900)):
            if lines[j].rstrip() == '}':
                end = j+1; break
        if end is None: continue
        body = lines[defline-1:end]
        # locks inside body
        lock_re = re.compile(r'\b(spin_lock|spin_lock_irq|spin_lock_irqsave|spin_lock_bh|spin_trylock|spin_trylock_irq|spin_trylock_bh|spin_lock_irqsave_nested|spin_lock_nested)\s*\(\s*(?:&\s*)?([^,\s\)]+)')
        hlocks = []
        for off, l in enumerate(body):
            for m in lock_re.finditer(l):
                hlocks.append((defline+off, m.group(1), m.group(2)))
        if not hlocks: continue
        for (hl, kind, expr) in hlocks:
            base = expr
            # find all other sites in same file with same expr, outside handler body
            for (ll, fn, k2, e2) in fl:
                if e2 == expr and not (defline <= ll <= end):
                    if k2 in ('spin_lock', 'spin_trylock', 'spin_lock_nested'):
                        results.append((rel, line, api2, hname, defline, expr, hl, kind, ll, fn, k2))

with open(os.path.join(out, 'cross.tsv'), 'w') as fh:
    fh.write("file\tregline\tapi\thandler\tdefline\tlockexpr\thandlerlockline\thandlerkind\totherline\totherfunc\totherkind\n")
    for r in results:
        fh.write('\t'.join(str(x) for x in r) + '\n')
print("cross pairs:", len(results))
