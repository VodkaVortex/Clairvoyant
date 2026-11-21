import re, os, sys, json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import read_fns, base_name

def lock_info(body):
    out = []
    for m in re.finditer(r'(spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested|_bh_nested)?)\s*\(\s*(?:&?\s*)?([^),;]+?)\s*[,)]', body):
        out.append((m.group(1), m.group(2).strip()))
    return out

BASE = sys.argv[1]
# union corpus: tasklet files + napi files + all .c under drivers/net
corpus = set()
for lf in sys.argv[2:]:
    for l in open(lf):
        l = l.strip()
        p = os.path.join(BASE, l) if not l.startswith('/') else l
        if os.path.exists(p): corpus.add(p)
# add all drivers/net .c files (cheap enough)
for root, dirs, files in os.walk(os.path.join(BASE, 'drivers/net')):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for fn in files:
        if fn.endswith('.c'): corpus.add(os.path.join(root, fn))
print("corpus files:", len(corpus), file=sys.stderr)

# parse
filefns = {}
for f in corpus:
    filefns[f] = read_fns(f)

# fn name -> [(file, start, end, body)]
fnidx = defaultdict(list)
for f, fns in filefns.items():
    for name,(s,e,b) in fns.items():
        fnidx[name].append((f,s,e,b))

# softirq callbacks: tasklet callbacks (from tasklet_init/DECLARE/TASKLET_SETUP) and NAPI poll fns
soft_cbs = defaultdict(list)  # fn -> [(file, kind, line)]
TASKLET_INIT = re.compile(r'tasklet_init\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,')
TASKLET_SETUP = re.compile(r'tasklet_setup\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,')
DECLARE_TASKLET = re.compile(r'DECLARE_TASKLET(?:_OLD)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*[,)]')
NAPI_ADD = re.compile(r'netif_napi_add(?:_weight|_dev)?\s*\(([^;]{0,300}?)\)')
for f, fns in filefns.items():
    txt = open(f, encoding='utf-8', errors='replace').read()
    for m in TASKLET_INIT.finditer(txt): soft_cbs[m.group(2)].append((f,'tasklet', txt[:m.start()].count('\n')+1))
    for m in TASKLET_SETUP.finditer(txt): soft_cbs[m.group(2)].append((f,'tasklet', txt[:m.start()].count('\n')+1))
    for m in DECLARE_TASKLET.finditer(txt): soft_cbs[m.group(2)].append((f,'tasklet_decl', txt[:m.start()].count('\n')+1))
    for m in NAPI_ADD.finditer(txt):
        args=[a.strip() for a in m.group(1).split(',')]
        if len(args)>=3 and re.match(r'^[A-Za-z0-9_]+$', args[2]):
            soft_cbs[args[2]].append((f,'napi', txt[:m.start()].count('\n')+1))

# transitive callers of softirq callbacks within same file (depth <= 3) — helpers called FROM the cb
def callees(body):
    return set(re.findall(r'\b([a-z][A-Za-z0-9_]*)\s*\(', body))

soft_fn_names = set(soft_cbs.keys())
# expand: for each cb, walk calls within same file
soft_expanded = defaultdict(set)  # fname -> set of files where it is softirq-reachable
for cb, sites in soft_cbs.items():
    for (f, kind, line) in sites:
        soft_expanded[cb].add(f)
        seen = set()
        frontier = [cb]
        depth = 0
        while frontier and depth < 3:
            nxt = []
            for name in frontier:
                if name in seen: continue
                seen.add(name)
                for (ff,s,e,b) in fnidx.get(name, []):
                    if ff != f: continue
                    for c in callees(b):
                        if c in fnidx and c not in seen:
                            soft_expanded[c].add(f)
                            nxt.append(c)
            frontier = nxt
            depth += 1

# lock -> set of (fn, file) softirq-side (incl. helpers, depth<=3)
soft_locks = defaultdict(list)
for fn, files in soft_expanded.items():
    for (f,s,e,b) in fnidx.get(fn, []):
        if f not in files: continue
        for variant, expr in lock_info(b):
            soft_locks[base_name(expr)].append({'fn': fn, 'file': f, 'variant': variant, 'expr': expr, 'line': s})

# process-side: any fn in corpus (not softirq-reachable) taking same lock with plain spin_lock, and fn NOT bh-disabled
hits = []
soft_fn_file = {}
for fn, files in soft_expanded.items():
    for f in files: soft_fn_file[(fn,f)] = True
for lockname, softsites in soft_locks.items():
    if not lockname or lockname in ('lock',):  # generic names need same-file constraint
        pass
    for f, fns in filefns.items():
        for name,(s,e,b) in fns.items():
            if (name,f) in soft_fn_file: continue
            for variant, expr in lock_info(b):
                if base_name(expr) != lockname: continue
                if variant != 'spin_lock': continue
                bh = bool(re.search(r'spin_lock_bh\s*\(|local_bh_disable\s*\(', b))
                # require same driver directory for generic lock names, or lock defined in same file as one soft site
                same_dir = any(os.path.dirname(x['file'])==os.path.dirname(f) for x in softsites)
                same_file = any(x['file']==f for x in softsites)
                if lockname in ('lock','locks','lck') and not (same_dir or same_file): continue
                if not (same_dir or same_file): continue
                hits.append({'lock': lockname, 'file': f, 'fn': name, 'line': s, 'expr': expr, 'bh_in_fn': bh,
                             'same_file': same_file, 'soft': [{'fn':x['fn'],'file':os.path.relpath(x['file'],BASE),'variant':x['variant'],'line':x['line'],'expr':x['expr']} for x in softsites]})
import io
out = os.environ.get('OUT')
json.dump(hits, open(out,'w'), indent=1)
print(len(hits), "hits", file=sys.stderr)
