import re, os, subprocess, sys
from collections import defaultdict

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)

handler_file = defaultdict(list)   # handler name -> [(file,line)]
regs = []
for line in open(os.path.join(os.environ['TMPDIR'],'i044_irq_handlers.tsv')):
    parts = line.rstrip('\n').split('\t')
    if len(parts)!=4: continue
    f,l,k,h = parts
    f = f.lstrip('./')
    regs.append((f,int(l),k,h))
    if re.match(r'^[A-Za-z_][A-Za-z_0-9]*$', h):
        handler_file[h].append((f,int(l)))

# locate handler definitions: for each unique handler, find its file & def line
defs = {}  # handler -> (file, defline)
defpat = re.compile(r'^(?:static\s+)?(?:[A-Za-z_0-9]+\s+)+([A-Za-z_][A-Za-z_0-9]*)\s*\(')
for h, sites in handler_file.items():
    cand_files = set(f for f,_ in sites)
    for cf in cand_files:
        try: src = open(cf, errors='replace').read()
        except: continue
        for m in re.finditer(r'\b(?:irq_handler_t\s+|)\b'+re.escape(h)+r'\s*=', src):
            pass
        # find definition "h(" preceded by "static ... irqreturn"
        for m in re.finditer(r'(?:^|\n)((?:[A-Za-z_][A-Za-z_0-9]*\s+)*'+re.escape(h)+r'\s*\()', src):
            start = src.rfind('\n', 0, m.start(1))+1
            defline = src.count('\n',0,m.start(1))+1
            prefix = src[start:m.start(1)]
            if 'irqreturn' in prefix or 'irqreturn_t' in prefix:
                defs[h] = (cf, defline)
                break
        if h in defs: break

print("total registrations:", len(regs), "unique handlers:", len(handler_file), "resolved defs:", len(defs))

# For each handler def, extract its function body and find spin_lock acquisitions
lockpat = re.compile(r'(spin_lock(?:_irqsave|_irq|_bh|_nosync)?|read_lock|write_lock|raw_spin_lock\w*)\s*\(\s*&?([^);]+?)\s*\)')
results = []
for h,(f,dl) in defs.items():
    try: src = open(f, errors='replace').read()
    except: continue
    lines = src.split('\n')
    # naive body extraction: from defline to matching close brace
    body_start = None
    for i in range(dl-1, min(dl+20, len(lines))):
        if lines[i].count('{')>0:
            body_start = i; break
    if body_start is None: continue
    depth = 0; end = None
    for i in range(body_start, min(body_start+600, len(lines))):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth==0 and i>body_start:
            end = i; break
    if end is None: continue
    body_lines = lines[body_start:end+1]
    for j,bl in enumerate(body_lines):
        m = lockpat.search(bl)
        if m:
            results.append((f, body_start+j+1, h, m.group(1), m.group(2).strip()))

for f,l,h,kind,lock in results:
    print(f"{f}\t{l}\t{h}\t{kind}\t{lock}")
