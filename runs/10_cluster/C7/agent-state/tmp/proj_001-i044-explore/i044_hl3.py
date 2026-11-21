import re, os, sys, subprocess
from collections import defaultdict

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)

# registration index
regs_by_handler = defaultdict(list)
for line in open(os.path.join(os.environ['TMPDIR'],'i044_irq_handlers.tsv')):
    parts = line.rstrip('\n').split('\t')
    if len(parts)!=4: continue
    f,l,k,h = parts
    f = f.lstrip('./')
    if re.match(r'^[A-Za-z_][A-Za-z_0-9]*$', h):
        regs_by_handler[h].append((f,int(l),k))

# Build candidate file list: files that register a handler + files in same dir (defs often nearby)
cand_files = set()
for h, sites in regs_by_handler.items():
    for f,_,_ in sites:
        cand_files.add(f)

# Get all .c/.h files
allfiles = subprocess.run(['find','.','-name','*.c','-o','-name','*.h'],capture_output=True,text=True).stdout.split()
allfiles = [a.lstrip('./') for a in allfiles]

defline = re.compile(r'^([A-Za-z_][A-Za-z_0-9]*)\s*\($')
defline2 = re.compile(r'^(?:static\s+|inline\s+|__always_inline\s+)*irqreturn_t\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(')

defs = {}
for f in cand_files:
    try: src = open(f, errors='replace').read()
    except: continue
    lines = src.split('\n')
    for i, l in enumerate(lines):
        m = defline2.match(l.strip())
        if m:
            h = m.group(1)
            if h in regs_by_handler and h not in defs:
                defs[h] = (f, i+1)
            continue
        m2 = defline.match(l.strip())
        if m2:
            h = m2.group(1)
            if h in regs_by_handler and h not in defs:
                prev = lines[i-1].strip() if i>0 else ''
                if 'irqreturn' in prev:
                    defs[h] = (f, i+1)

print("resolved defs:", len(defs), "of", len(regs_by_handler), file=sys.stderr)

lockpat = re.compile(r'\b(spin_lock_irqsave_nested|spin_lock_irqsave|spin_lock_irq|spin_lock_bh|spin_lock_nosync|spin_lock|read_lock_irqsave|read_lock_irq|read_lock_bh|read_lock|write_lock_irqsave|write_lock_irq|write_lock_bh|write_lock|raw_spin_lock_irqsave|raw_spin_lock_irq|raw_spin_lock)\s*\(\s*&?\s*([^);]+?)\s*[\),]')
results = []
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

with open(os.path.join(os.environ['TMPDIR'],'handlers_locks.tsv'),'w') as out:
    for f,l,h,kind,lock in results:
        out.write(f"{f}\t{l}\t{h}\t{kind}\t{lock}\n")
print("handler lock sites:", len(results), file=sys.stderr)
# also dump unresolved count
