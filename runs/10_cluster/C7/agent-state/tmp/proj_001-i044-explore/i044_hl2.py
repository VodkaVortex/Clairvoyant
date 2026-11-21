import re, os, sys
from collections import defaultdict

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)

handler_regs = defaultdict(list)   # handler name -> [(file,line)]
nreg = 0
for line in open(os.path.join(os.environ['TMPDIR'],'i044_irq_handlers.tsv')):
    parts = line.rstrip('\n').split('\t')
    if len(parts)!=4: continue
    f,l,k,h = parts
    f = f.lstrip('./')
    nreg += 1
    if re.match(r'^[A-Za-z_][A-Za-z_0-9]*$', h):
        handler_regs[h].append((f,int(l),k))

# Build file map once
fileset = set()
for h, sites in handler_regs.items():
    for f,_,_ in sites: fileset.add(f)

# Resolve handler definitions by scanning each file for the name preceded by irqreturn on the def line or the previous line
defs = {}   # handler -> (file, defline)
defline_pat = re.compile(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\(')
for f in fileset:
    try: src = open(f, errors='replace').read()
    except: continue
    lines = src.split('\n')
    for i, l in enumerate(lines):
        # quick filter: function name at start of a line followed by (
        m = re.match(r'^([A-Za-z_][A-Za-z_0-9]*)\s*\(', l)
        if not m: continue
        h = m.group(1)
        if h not in handler_regs: continue
        # check previous line or same line prefix contains irqreturn
        prev = lines[i-1] if i>0 else ''
        if 'irqreturn' in l.split(h)[0] or 'irqreturn' in prev:
            if h not in defs:
                defs[h] = (f, i+1)

print("registrations:", nreg, "unique handlers:", len(handler_regs), "resolved defs:", len(defs), file=sys.stderr)

# extract lock usage in handler bodies
lockpat = re.compile(r'\b(spin_lock_irqsave_nested|spin_lock_irqsave|spin_lock_irq|spin_lock_bh|spin_lock_nosync|spin_lock|read_lock_irqsave|read_lock_irq|read_lock_bh|read_lock|write_lock_irqsave|write_lock_irq|write_lock_bh|write_lock|raw_spin_lock_irqsave|raw_spin_lock_irq|raw_spin_lock)\s*\(\s*&?\s*([^);]+?)\s*[\),]')
results = []
bodies = {}
for h,(f,dl) in defs.items():
    try: src = open(f, errors='replace').read()
    except: continue
    lines = src.split('\n')
    body_start = None
    for i in range(dl-1, min(dl+25, len(lines))):
        if lines[i].count('{')>0:
            body_start = i; break
    if body_start is None: continue
    depth = 0; end = None
    for i in range(body_start, min(body_start+800, len(lines))):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth<=0 and i>body_start:
            end = i; break
    if end is None: continue
    for i in range(body_start, end+1):
        m = lockpat.search(lines[i])
        if m:
            results.append((f, i+1, h, m.group(1), m.group(2).strip()))
            bodies.setdefault(h, (f, body_start+1, end+1))

with open(os.path.join(os.environ['TMPDIR'],'handlers_locks.tsv'),'w') as out:
    for f,l,h,kind,lock in results:
        out.write(f"{f}\t{l}\t{h}\t{kind}\t{lock}\n")
print("handler lock sites:", len(results), file=sys.stderr)
