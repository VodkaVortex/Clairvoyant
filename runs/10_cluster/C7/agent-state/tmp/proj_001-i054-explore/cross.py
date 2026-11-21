import re, os, sys, collections, json
ROOT = os.getcwd()
data = json.load(open(os.environ['TMPDIR'] + '/handler_locks.json'))
# normalize lock expr -> base (last member or identifier)
def base(e):
    e = e.strip().lstrip('&').strip()
    # strip casts and flags like true/false
    e = re.sub(r',.*$', '', e)
    parts = re.split(r'->|\.', e)
    return parts[-1].strip()
cross = []
for rel, handlers in data.items():
    p = os.path.join(ROOT, rel)
    src = open(p, encoding='utf-8', errors='replace').read()
    lines = src.split('\n')
    for (hname, s, e, locks) in handlers:
        plain_h = []
        for L in locks:
            m = re.match(r'spin_lock\s*\(\s*(?:&)?([^,)]+)', L)
            if m: plain_h.append(base(m.group(1)))
        if not plain_h: continue
        # gather all plain spin_lock sites in file (excluding handler ranges)
        plain_sites = collections.defaultdict(list)
        for i, ln in enumerate(lines):
            if s-1 <= i <= e-1: continue
            for m in re.finditer(r'\bspin_lock\s*\(\s*(?:&)?([^,)]+)', ln):
                b = base(m.group(1))
                plain_sites[b].append(i+1)
            # also count irqsave sites for discipline info
        for b in set(plain_h):
            if b in plain_sites:
                cross.append(dict(file=rel, handler=hname, hstart=s, hend=e, lock=b,
                                  plain_outside=sorted(set(plain_sites[b]))[:12]))
print(json.dumps(cross, indent=1))
