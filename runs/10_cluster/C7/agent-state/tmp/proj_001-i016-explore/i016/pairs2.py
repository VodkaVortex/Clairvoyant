import os, re, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
SCAN_DIRS = ["drivers/net/wireless", "drivers/staging", "drivers/net", "net"]
data = json.load(open(os.path.join(os.environ['TMPDIR'],'i016','timer_callbacks.json')))
timer_callbacks = data["timer_callbacks"]
hrtimer_handlers = set(h[0] for h in data["hrtimer_handlers"])

lockcall_re = re.compile(r'\b(spin_(?:un)?lock(?:_bh|_irqsave|_irqrestore|_irq|_nested)?|spin_trylock(?:_bh)?)\s*\(\s*([^;]+?)\s*\)\s*;')
def mode(fn):
    if 'irqsave' in fn or 'irqrestore' in fn: return 'irqsave'
    if '_bh' in fn: return 'bh'
    if 'irq' in fn: return 'irq'
    return 'plain'
def lockfield(arg):
    names = re.findall(r'->\s*([A-Za-z_][A-Za-z0-9_]*)|\.([A-Za-z_][A-Za-z0-9_]*)', arg)
    names = [a or b for a,b in names]
    return names[-1] if names else None

def find_defs(lines):
    defs = {}
    for i, l in enumerate(lines):
        m = re.match(r'^(?:static\s+|inline\s+)*(?:const\s+)?[A-Za-z_][A-Za-z0-9_ \t\*&]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
        if m and not l.lstrip().startswith(('if','for','while','switch','return')) and '=' not in l.split('(')[0]:
            name = m.group(1); depth = 0; started = False
            for k in range(i, min(i+300, len(lines))):
                depth += lines[k].count('{') - lines[k].count('}')
                if '{' in lines[k]: started = True
                if started and depth <= 0:
                    if k > i: defs.setdefault(name, []).append((i, k))
                    break
    return defs

# one pass: parse every file, record defs and all plain/bh/irq lock sites per file
files = {}
for d in SCAN_DIRS:
    p = os.path.join(ROOT, d)
    for dirpath, _, fnames in os.walk(p):
        for f in fnames:
            if f.endswith('.c'):
                fp = os.path.join(dirpath, f)
                try: lines = open(fp, errors='ignore').read().split('\n')
                except: continue
                files[fp] = (lines, find_defs(lines))

# build function-name -> (file, span) map for timer callbacks
timer_defs = {}   # fname -> list of (fp, s, e)
for fp,(lines,defs) in files.items():
    for name, spans in defs.items():
        if name in timer_callbacks or name in hrtimer_handlers:
            for (s,e) in spans:
                timer_defs.setdefault(name, []).append((fp,s,e))

# build global plain-lock index: field -> list of (relfile, line, expr, raw)
plain_idx = {}
all_locks = []
for fp,(lines,defs) in files.items():
    rel = os.path.relpath(fp, ROOT)
    for idx,l in enumerate(lines):
        for m in lockcall_re.finditer(l):
            md = mode(m.group(1)); expr = m.group(2)
            f = lockfield(expr)
            if not f: continue
            all_locks.append((f, rel, idx+1, md, m.group(1), expr, l.strip()[:150]))
            if md == 'plain':
                plain_idx.setdefault(f, []).append((rel, idx+1, expr, l.strip()[:150]))

# timer-side lock sites
report = []
for fname, spans in timer_defs.items():
    for (fp,s,e) in spans:
        lines = files[fp][0]
        rel = os.path.relpath(fp, ROOT)
        for idx in range(s, e+1):
            for m in lockcall_re.finditer(lines[idx]):
                f = lockfield(m.group(2))
                if not f: continue
                report.append({"cb": fname, "cbfile": rel, "cbline": idx+1,
                               "mode": mode(m.group(1)), "lock": m.group(2),
                               "field": f, "raw": lines[idx].strip()[:150]})

json.dump(report, open(os.path.join(os.environ['TMPDIR'],'i016','timer_side_locks.json'),'w'), indent=1)
print("direct lock sites inside timer/hrtimer callback bodies:", len(report))
# candidates: timer-side takes lock (any mode) AND plain sites exist for same field in same driver dir
cands = []
for r in report:
    f = r["field"]
    if f not in plain_idx: continue
    drv = '/'.join(r["cbfile"].split('/')[:-1])
    same = [p for p in plain_idx[f] if '/'.join(p[0].split('/')[:-1]).startswith(drv.split('/')[0]) ]
    same_dir = [p for p in plain_idx[f] if p[0].startswith(drv)]
    if same_dir and (r["mode"] in ('plain','bh')) :
        cands.append((r, same_dir[:10]))
print("fields shared (plain sites in same dir):", len(cands))
for r, same in cands:
    print("="*90)
    print("CB:", r["cb"], r["cbfile"]+":"+str(r["cbline"]), "mode:", r["mode"], "lock:", r["lock"][:60])
    for p in same:
        print("   PLAIN:", p[0]+":"+str(p[1]), p[2][:60], "|", p[3][:100])
