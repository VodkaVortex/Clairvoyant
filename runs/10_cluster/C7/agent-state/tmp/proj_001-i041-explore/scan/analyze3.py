import re, os, sys, json
from collections import defaultdict

sys.path.insert(0, os.path.join(os.environ['TMPDIR'], 'scan'))
from parse import read_fns, base_name

BASE = sys.argv[1]
corpus = set()
for root, dirs, files in os.walk(BASE):
    dirs[:] = [d for d in dirs if d not in ('.git','tools','Documentation','scripts','samples','usr')]
    for fn in files:
        if fn.endswith(('.c','.h')):
            corpus.add(os.path.join(root, fn))
print("corpus files:", len(corpus), file=sys.stderr)

filefns = {}
fnidx = defaultdict(list)
for f in corpus:
    fns = read_fns(f)
    filefns[f] = fns
    for name,(s,e,b) in fns.items():
        fnidx[name].append((f,s,e,b))

TASKLET_INIT = re.compile(r'tasklet_init\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,')
TASKLET_SETUP = re.compile(r'tasklet_setup\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,')
DECLARE_TASKLET = re.compile(r'DECLARE_TASKLET(?:_OLD)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*[,)]')
NAPI_ADD = re.compile(r'netif_napi_add(?:_weight|_dev)?\s*\(([^;]{0,400}?)\)\s*;')

soft_cbs = defaultdict(list)
for f in filefns:
    txt = open(f, encoding='utf-8', errors='replace').read()
    for m in TASKLET_INIT.finditer(txt): soft_cbs[m.group(2)].append((f,'tasklet_init', txt[:m.start()].count('\n')+1))
    for m in TASKLET_SETUP.finditer(txt): soft_cbs[m.group(2)].append((f,'tasklet_setup', txt[:m.start()].count('\n')+1))
    for m in DECLARE_TASKLET.finditer(txt): soft_cbs[m.group(2)].append((f,'declare_tasklet', txt[:m.start()].count('\n')+1))
    for m in NAPI_ADD.finditer(txt):
        args=[a.strip() for a in m.group(1).split(',')]
        if len(args)>=3 and re.match(r'^[A-Za-z0-9_]+$', args[2]):
            soft_cbs[args[2]].append((f,'napi_add', txt[:m.start()].count('\n')+1))
print("soft cbs:", len(soft_cbs), file=sys.stderr)

def callees(body):
    return set(re.findall(r'\b([a-z][A-Za-z0-9_]*)\s*\(', body))

soft_expanded = defaultdict(set)
for cb, sites in soft_cbs.items():
    for (f, kind, line) in sites:
        soft_expanded[cb].add(f)
        seen=set(); frontier=[cb]; depth=0
        while frontier and depth<4:
            nxt=[]
            for name in frontier:
                if name in seen: continue
                seen.add(name)
                for (ff,s,e,b) in fnidx.get(name,[]):
                    if ff!=f: continue
                    for c in callees(b):
                        if c in fnidx and c not in seen:
                            soft_expanded[c].add(f); nxt.append(c)
            frontier=nxt; depth+=1

soft_locks = defaultdict(list)
for fn, files in soft_expanded.items():
    for (f,s,e,b) in fnidx.get(fn,[]):
        if f not in files: continue
        for m in re.finditer(r'(spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested|_bh_nested)?)\s*\(\s*(?:&?\s*)?([^),;]+?)\s*[,)]', b):
            soft_locks[base_name(m.group(2))].append({'fn': fn, 'file': f, 'variant': m.group(1), 'expr': m.group(2), 'line': s})

soft_fn_file = set()
for fn, files in soft_expanded.items():
    for f in files: soft_fn_file.add((fn,f))

hits=[]
for lockname, softsites in soft_locks.items():
    if not lockname: continue
    softdirs = set(os.path.dirname(x['file']) for x in softsites)
    softfiles = set(x['file'] for x in softsites)
    for f, fns in filefns.items():
        d = os.path.dirname(f)
        # candidate must share directory with a soft site, or be in a subdir of same driver
        if f not in softfiles and d not in softdirs: continue
        for name,(s,e,b) in fns.items():
            if (name,f) in soft_fn_file: continue
            for m in re.finditer(r'(spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested|_bh_nested)?)\s*\(\s*(?:&?\s*)?([^),;]+?)\s*[,)]', b):
                if base_name(m.group(2)) != lockname: continue
                if m.group(1) != 'spin_lock': continue
                bh = bool(re.search(r'spin_lock_bh\s*\(|local_bh_disable\s*\(', b))
                hits.append({'lock': lockname, 'file': os.path.relpath(f,BASE), 'fn': name, 'line': s, 'expr': m.group(2), 'bh_in_fn': bh,
                             'soft': [{'fn':x['fn'],'file':os.path.relpath(x['file'],BASE),'variant':x['variant'],'line':x['line'],'expr':x['expr']} for x in softsites]})
out=os.environ.get('OUT')
json.dump(hits, open(out,'w'), indent=1)
print(len(hits), "hits", file=sys.stderr)
