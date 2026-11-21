import re, os, sys, subprocess, json

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"

def read(f):
    try:
        return open(os.path.join(root,f),errors="ignore").read().split("\n")
    except: return []

def find_func_body(lines, funcname):
    """Return (start_idx,end_idx) of function definition body (brace matching), 0-based line idx."""
    pat = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:[A-Za-z_][A-Za-z0-9_]*[\s\*]+)+(' + re.escape(funcname) + r')\s*\(')
    for i,l in enumerate(lines):
        if re.search(r'\b' + re.escape(funcname) + r'\s*\(', l):
            # candidate def line: funcname( ... ) and eventually {
            if l.strip().startswith("//") or l.strip().startswith("*"): continue
            # find the opening brace within a few lines
            j=i; depth=0; started=False; buf=""
            while j < len(lines) and j < i+12:
                buf += lines[j] + "\n"
                if ";" in lines[j] and not started:
                    # could be prototype/declaration end
                    if depth==0 and "{" not in lines[j]:
                        break
                depth += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started=True
                if started and depth==0:
                    return (i, j)
                j+=1
    return None

lockre = re.compile(r'spin_lock(?:_bh|_irq|_irqsave|_irqrestore|_nested|_bh_nested)?\s*\(\s*&?\s*([A-Za-z0-9_\>\.\-\[\]\(\)]+?)\s*\)')
readre  = re.compile(r'spin_(?:try|un)lock(?:_bh|_irqsave|_irqrestore)?\s*\(\s*&?\s*([A-Za-z0-9_\>\.\-\[\]\(\)]+?)\s*\)')

def locks_in_range(lines, a, b):
    res=[]
    for i in range(a,b+1):
        for m in lockre.finditer(lines[i]):
            res.append((i+1, m.group(0).split("(")[0], m.group(1)))
    return res

def base(expr):
    # strip pointer arithmetic / array indexing
    e = expr.strip()
    e = re.sub(r'\[[^\]]*\]','',e)
    return e

tasklets=[]
for line in open(sys.argv[1]):
    f,ln,tasklet,cb = line.rstrip("\n").split("\t")
    tasklets.append((f,int(ln),tasklet,cb))

out=[]
for f,ln,tasklet,cb in tasklets:
    lines=read(f)
    if not lines: continue
    r=find_func_body(lines,cb)
    if r is None:
        out.append((f,ln,tasklet,cb,"NOTFOUND",[]))
        continue
    a,b=r
    lk=locks_in_range(lines,a,b)
    # direct callees: names of functions called within the body that are defined in same file
    calls=set(re.findall(r'\b([a-z_][a-z0-9_]+)\s*\(', "\n".join(lines[a:b+1])))
    callees=[]
    for c in calls:
        if c in (cb,): continue
        rr=find_func_body(lines,c)
        if rr and rr[0] > 0:
            # exclude common keywords
            if c in ("if","for","while","switch","return","sizeof"): continue
            callees.append((c, rr[0]+1, rr[1]+1))
    lk2=[]
    for (c,ca,cbn) in callees[:20]:
        lk2 += locks_in_range(lines, ca-1, cbn-1)
    out.append((f,ln,tasklet,cb,f"{a+1}-{b+1}",lk+lk2))

for f,ln,tasklet,cb,span,lk in out:
    if lk:
        print(f"{f}\t{ln}\t{cb}\t{span}\t" + ";".join(f"{l}:{fn}:{n}" for l,fn,n in lk))
