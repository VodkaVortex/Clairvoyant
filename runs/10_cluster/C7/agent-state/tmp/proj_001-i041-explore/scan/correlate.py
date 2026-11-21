import re, os, sys, json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import read_fns, lock_uses, base_name, has_bh_disable

# softirq-side: tasklet callback bodies + NAPI poll bodies (first-level lock usage)
# process-side: any other function in the same driver directory tree that takes the same lock with plain spin_lock (no bh)

def lock_info(body):
    out = []
    for m in re.finditer(r'(spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested|_bh_nested)?)\s*\(\s*(?:&?\s*)?([^),;]+?)\s*[,)]', body):
        out.append((m.group(1), m.group(2).strip()))
    return out

def analyze(base, cbs_json):
    d = json.load(open(cbs_json))
    task_cbs = d['tasklet_callbacks']   # fn -> [{file, tasklet, how, line}]
    napi_polls = d['napi_polls']
    results = []
    # softirq lock map: lock base name -> (fn, file, variant, expr)
    soft_locks = defaultdict(list)
    soft_fn_files = {}
    for fn, sites in task_cbs.items():
        for site in sites:
            p = os.path.join(base, site['file'])
            if not os.path.exists(p): continue
            fns = read_fns(p)
            if fn not in fns: continue
            s,e,body = fns[fn]
            soft_fn_files[fn] = p
            for variant, expr in lock_info(body):
                soft_locks[base_name(expr)].append({'fn': fn, 'file': site['file'], 'variant': variant, 'expr': expr, 'ctx': 'tasklet', 'line': s})
    for fn, sites in napi_polls.items():
        for site in sites:
            p = os.path.join(base, site['file'])
            if not os.path.exists(p): continue
            fns = read_fns(p)
            if fn not in fns: continue
            s,e,body = fns[fn]
            soft_fn_files[fn] = p
            for variant, expr in lock_info(body):
                soft_locks[base_name(expr)].append({'fn': fn, 'file': site['file'], 'variant': variant, 'expr': expr, 'ctx': 'napi', 'line': s})
    return soft_locks, soft_fn_files

def find_process_sides(base, soft_locks, soft_fn_files, tasklet_files):
    """For each softirq-used lock base name, scan all tasklet/napi corpus files for OTHER functions
    (not the softirq callback itself) that take the same lock with plain spin_lock (no bh disable in fn)."""
    hits = []
    # map file -> fns
    cache = {}
    files = [os.path.join(base, l.strip()) for l in open(tasklet_files) if l.strip()]
    files = [f for f in files if os.path.exists(f)]
    lock_to_files = defaultdict(set)
    for f in files:
        if f not in cache:
            cache[f] = read_fns(f)
        for name, (s,e,body) in cache[f].items():
            for variant, expr in lock_info(body):
                lock_to_files[base_name(expr)].add(f)
    for lockname, softsites in soft_locks.items():
        soft_fns = set(x['fn'] for x in softsites)
        for f in sorted(lock_to_files.get(lockname, ())):
            fns = cache[f]
            rel = os.path.relpath(f, base)
            for name, (s,e,body) in fns.items():
                if name in soft_fns and f == soft_fn_files.get(name):
                    continue
                for variant, expr in lock_info(body):
                    if base_name(expr) != lockname: continue
                    if variant == 'spin_lock':
                        # plain lock in this function; is there any bh disable in the fn?
                        bh = bool(re.search(r'spin_lock_bh\s*\(|local_bh_disable\s*\(', body))
                        hits.append({'lock': lockname, 'file': rel, 'fn': name, 'line': s, 'expr': expr,
                                     'bh_in_fn': bh,
                                     'soft_sites': softsites})
    return hits

if __name__ == '__main__':
    base = sys.argv[1]
    cbs = sys.argv[2]
    tfiles = sys.argv[3]
    soft_locks, soft_fn_files = analyze(base, cbs)
    hits = find_process_sides(base, soft_locks, soft_fn_files, tfiles)
    # dedupe
    json.dump(hits, open(os.path.join(os.path.dirname(cbs), 'correlate_hits.json'), 'w'), indent=1)
    print(len(hits), "raw hits")
