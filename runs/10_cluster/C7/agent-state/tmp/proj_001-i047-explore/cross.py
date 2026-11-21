import re, os, json, collections
tdir = os.environ["TMPDIR"]
hl = json.load(open(os.path.join(tdir, "handler_locks.json")))
regs = [l.rstrip('\n').split('\t') for l in open(os.path.join(tdir, "registrations.tsv"))]

# register_kind: which handlers are real hardirq (exclude threaded primary = separate)
# map handler -> registration kind(s)
kinds = collections.defaultdict(set)
for path, line, h, kind in regs:
    kinds[h].add(kind)

# For each (file, plain lock expr) from handler bodies, count same-file plain acquisitions
# in NON-handler functions and their locations.
lockpat_cache = {}

def file_plain_sites(path, lockexpr):
    # find all spin_lock(lockexpr) sites in file, return list of (line, funcname)
    if path not in lockpat_cache:
        try:
            lockpat_cache[path] = open(path, errors='replace').readlines()
        except Exception:
            lockpat_cache[path] = None
    lines = lockpat_cache[path]
    if lines is None:
        return []
    sites = []
    curfunc = None
    funcdef = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    for i, ln in enumerate(lines, 1):
        m = funcdef.match(ln)
        if m and not ln.lstrip().startswith(('if','for','while','switch','return','}','else')) and '=' not in ln.split('(')[0]:
            curfunc = m.group(1)
        if re.search(r'\bspin_lock\s*\(\s*' + re.escape(lockexpr) + r'\s*\)\s*;', ln):
            sites.append((i, curfunc))
    return sites

rows = []
for h, files in hl.items():
    for p, lst in files.items():
        for e in lst:
            for le in e['plain']:
                sites = file_plain_sites(p, le)
                # handler line itself
                hsites = [s for s in sites if e['line'] <= s[0] < (e['end'] or 10**9)]
                others = [s for s in sites if not (e['line'] <= s[0] < (e['end'] or 10**9))]
                if others:
                    rows.append({
                        'handler': h, 'kind': sorted(kinds.get(h, ['?'])),
                        'file': p, 'hline': e['line'], 'hend': e['end'],
                        'lock': le, 'hlocksites': hsites,
                        'other_sites': others,
                        'bh': e['bh'], 'irq': e['irq'], 'irqsave': e['irqsave']})

rows.sort(key=lambda r: -len(r['other_sites']))
with open(os.path.join(tdir, "cross.tsv.json"), "w") as out:
    json.dump(rows, out, indent=0)
for r in rows[:60]:
    print(f"{r['file']}:{r['hline']} handler={r['handler']} lock={r['lock']} kind={r['kind']} others={len(r['other_sites'])} firstothers={r['other_sites'][:4]} irqsave={r['irqsave'][:2]}")
print("TOTAL", len(rows))
