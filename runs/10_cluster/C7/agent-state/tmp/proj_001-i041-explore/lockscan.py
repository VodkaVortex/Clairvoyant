import re, subprocess, os
root="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
def read(p):
    with open(os.path.join(root,p),errors='replace') as f: return f.readlines()
def findfn(lines, fn):
    # find definition start: 'fn(' at position with { ... }
    starts=[]
    for i,l in enumerate(lines):
        if re.search(r'\b'+re.escape(fn)+r'\s*\(', l):
            # crude: must have return-type-ish before, and find closing brace
            starts.append(i)
    return starts
def body(lines, fn):
    # take the last-looking definition: line where fn( starts and previous line looks like type
    for i,l in enumerate(lines):
        if re.search(r'(?:^|\W)'+re.escape(fn)+r'\s*\(', l) and '{' in ''.join(lines[i:i+3]):
            # scan forward to matching brace
            depth=0; started=False; j=i
            while j < len(lines):
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]: started=True
                if started and depth<=0:
                    return i+1, j+1, lines[i:j+1]
                j+=1
    return None
def callees(bodylines, fn):
    c=set()
    for l in bodylines:
        for mm in re.finditer(r'\b([a-z_][a-z_0-9]*)\s*\(', l):
            c.add(mm.group(1))
    c.discard(fn)
    return c
def locks(bodylines):
    lk=[]
    for idx,l in enumerate(bodylines):
        for mm in re.finditer(r'spin_lock(?:_irqsave|_irq|_bh|_irqsave_nest_lock)?\s*\(\s*&?([^),]+?)\s*(?:,\s*[^),]+)?\)', l):
            lk.append((mm.group(1).strip(), mm.group(0)))
    return lk
cbs=[]
for f in ['tasklet_cbs.txt','napi_cbs.txt']:
    for line in open(f):
        p,l,fn=line.strip().rsplit(':',2)
        cbs.append((p,int(l),fn,f))
byfile={}
for p,l,fn,kind in cbs:
    byfile.setdefault(p,[]).append((l,fn,kind))
results=[]
for p,items in byfile.items():
    try: lines=read(p)
    except: continue
    for l,fn,kind in items:
        b=body(lines,fn)
        if not b: continue
        s,e,bl=b
        lk=locks(bl)
        if not lk: continue
        # find plain spin_lock (not _bh/_irq/_irqsave)
        plain=[x for x in lk if x[1].startswith('spin_lock(') or x[1].startswith('spin_lock(&')]
        if not plain: continue
        ce=callees(bl,fn)
        results.append((p,fn,kind,l,s,e,plain,sorted(ce)))
results.sort()
with open('cb_locks.txt','w') as f:
    for p,fn,kind,reg,s,e,plain,ce in results:
        f.write(f"{p} fn={fn} kind={kind} reg@{reg} def@{s}-{e} plain_locks={[x[0] for x in plain]} callees={ce}\n")
print(len(results))
