import os,re,collections
TMP=os.path.join(os.environ["TMPDIR"],"i048")
# handler-side plain locks
handler_plain=collections.defaultdict(set)  # (file,lockname) -> handler lines
for line in open(os.path.join(TMP,"handler_locks.tsv")):
    f,h,ln,kind,lnm=line.rstrip("\n").split("\t")
    if kind in ("plain","irq"):
        handler_plain[(f,lnm)].add((h,ln,kind))
# index all spin_lock sites per file
all_locks=collections.defaultdict(list)
files=set(f for f,_ in handler_plain)
lockline_re=re.compile(r'\bspin_lock\s*\(\s*(\&?[A-Za-z_][\w\.\->]*(?:\(\))?[\w\.\->]*)')
for f in files:
    try: lines=open(f,errors="ignore").read().split("\n")
    except: continue
    for i,l in enumerate(lines):
        m=lockline_re.search(l)
        if m:
            arg=re.sub(r'\s+','',m.group(1))
            all_locks[f].append((i+1,arg,l.strip()[:120]))
rows=[]
for (f,lnm),hsites in handler_plain.items():
    target=lnm
    matches=[(ln,arg,txt) for ln,arg,txt in all_locks[f] if arg==target]
    # plain non-handler sites: those not within handler body lines; approximate by excluding exact handler lines
    handler_lines={ln for h,ln,kind in hsites}
    plain_other=[(ln,txt) for ln,arg,txt in matches if ln not in handler_lines]
    if plain_other:
        rows.append((f,lnm,sorted(hsites),plain_other))
rows.sort(key=lambda r:-len(r[3]))
with open(os.path.join(TMP,"cross.tsv"),"w") as out:
    for f,lnm,hs,po in rows:
        out.write(f"{f}\t{lnm}\thandler:{';'.join(f'{h}@{ln}({k})' for h,ln,k in hs)}\tplain_sites:{';'.join(str(l) for l,_ in po)}\n")
        for l,t in po:
            out.write(f"    {l}: {t}\n")
print("cross-index rows:",len(rows))
