import os, re, json, collections
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
SCAN_DIRS = ["drivers/net/wireless", "drivers/staging", "net", "drivers/net", "net/wireless"]
data = json.load(open(os.path.join(os.environ['TMPDIR'],'i016','timer_callbacks.json')))
timer_callbacks = data["timer_callbacks"]
hrtimer_handlers = set(h[0] for h in data["hrtimer_handlers"])

lockcall_re = re.compile(r'\b(spin_(?:un)?lock(?:_bh|_irqsave|_irqrestore|_irq|_nested)?|spin_trylock(?:_bh)?)\s*\(\s*([^;]+?)\s*\)\s*;')
call_re = re.compile(r'\b([a-z][a-z0-9_]{5,})\s*\(')

def mode(fn):
    if 'irqsave' in fn or 'irqrestore' in fn: return 'irqsave'
    if '_bh' in fn: return 'bh'
    if 'irq' in fn: return 'irq'
    return 'plain'

# index all files
files = []
for d in SCAN_DIRS:
    p = os.path.join(ROOT, d)
    if not os.path.isdir(p): continue
    for dirpath, _, fnames in os.walk(p):
        for f in fnames:
            if f.endswith('.c'): files.append(os.path.join(dirpath, f))

def find_defs(lines):
    defs = {}
    for i, l in enumerate(lines):
        m = re.match(r'^(?:static\s+|inline\s+)*(?:const\s+)?[A-Za-z_][A-Za-z0-9_ \t\*&]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
        if m and not l.lstrip().startswith(('if','for','while','switch','return')) and '=' not in l.split('(')[0]:
            name = m.group(1)
            # walk to closing brace
            depth = 0; started = False
            for k in range(i, min(i+400, len(lines))):
                depth += lines[k].count('{') - lines[k].count('}')
                if '{' in lines[k]: started = True
                if started and depth <= 0:
                    if k > i:
                        defs.setdefault(name, []).append((i, k))
                    break
    return defs

file_defs = {}
file_lines = {}
for fp in files:
    try:
        lines = open(fp, errors='ignore').read().split('\n')
    except: continue
    file_lines[fp] = lines
    file_defs[fp] = find_defs(lines)

def lockfield(arg):
    names = re.findall(r'->\s*([A-Za-z_][A-Za-z0-9_]*)|\.([A-Za-z_][A-Za-z0-9_]*)', arg)
    names = [a or b for a,b in names]
    return names[-1] if names else None

def collect_locks(fp, fname, depth, seen):
    """return list of (file, line, mode, func, lockexpr, rawline) for locks taken in body, expanding one level of same-file helper calls"""
    out = []
    if depth > 2 or fname in seen: return out
    seen = seen | {fname}
    for dfp, defs in file_defs.items():
        if os.path.basename(dfp) != os.path.basename(fp): continue
        if fname not in defs: continue
        lines = file_lines[dfp]
        for (s,e) in defs[fname]:
            for idx in range(s, e+1):
                l = lines[idx]
                for m in lockcall_re.finditer(l):
                    out.append((os.path.relpath(dfp, ROOT), idx+1, mode(m.group(1)), m.group(1), m.group(2), l.strip()[:150]))
            if depth < 2:
                for m in call_re.finditer('\n'.join(lines[s:e+1])):
                    h = m.group(1)
                    if h not in seen:
                        out.extend(collect_locks(dfp, h, depth+1, seen))
    return out

# timer callback lock inventory
timer_lock_inv = {}
for fname in list(timer_callbacks.keys()) + sorted(hrtimer_handlers):
    if fname in ('NULL','function'): continue
    sinfo = timer_callbacks.get(fname, ['?','?','hrtimer'])
    fp0 = os.path.join(ROOT, sinfo[0]) if sinfo[0] != '?' else None
    locks = []
    for fp in files:
        # only search files in same directory as setup (or any for hrtimer)
        if fp0 and os.path.dirname(fp) != os.path.dirname(fp0) and len(files) > 2000:
            pass
        locks.extend(collect_locks(fp, fname, 0, set()))
    if locks:
        timer_lock_inv.setdefault(fname, []).extend(locks)

# for each timer callback that takes at least one lock of ANY mode, find plain-mode same-field locks elsewhere in same driver dir
report = []
for fname, locks in timer_lock_inv.items():
    sinfo = timer_callbacks.get(fname, ['?','?','hrtimer'])
    base = os.path.dirname(sinfo[0]) if sinfo[0] != '?' else ''
    fields = {}
    for (rf, ln, md, fn, expr, raw) in locks:
        f = lockfield(expr)
        if f: fields.setdefault(f, []).append((rf, ln, md, fn, expr, raw))
    for f, sites in fields.items():
        # search entire tree for same field acquired PLAIN in other functions
        others = []
        for fp, lines in file_lines.items():
            d = os.path.relpath(os.path.dirname(fp), ROOT)
            if not (d == base or base in d or d in base): continue
            for idx, l in enumerate(lines):
                for m in lockcall_re.finditer(l):
                    if mode(m.group(1)) != 'plain': continue
                    if lockfield(m.group(2)) != f: continue
                    others.append((os.path.relpath(fp, ROOT), idx+1, m.group(2), l.strip()[:150]))
        if others:
            report.append({"timer_cb": fname, "setup": sinfo, "field": f,
                           "timer_side": [(s[0], s[1], s[2], s[4], s[5]) for s in sites],
                           "plain_sites": others[:40]})

json.dump(report, open(os.path.join(os.environ['TMPDIR'],'i016','pairs.json'),'w'), indent=1)
print("timer callbacks sharing a lock field with plain-mode sites elsewhere:", len(report))
for r in report:
    print("="*100)
    print("TIMER_CB:", r["timer_cb"], "field:", r["field"], "setup:", r["setup"][0], r["setup"][1])
    for s in r["timer_side"]:
        print("   TIMER-SIDE:", s[0]+":"+str(s[1]), s[2], s[3], "|", s[4][:110])
    for o in r["plain_sites"]:
        print("   PLAIN:", o[0]+":"+str(o[1]), o[2], "|", o[3][:110])
