import re, os, sys, subprocess, json, glob

ROOT="/mnt/radium"  # placeholder
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
DIRS=["drivers/net","drivers/staging","net","drivers/atm","drivers/isdn","drivers/usb/gadget","drivers/tty","drivers/char","drivers/scsi","drivers/mmc","drivers/iio"]
files=[]
for d in DIRS:
    out=subprocess.run(["find",os.path.join(ROOT,d),"-name","*.c"],capture_output=True,text=True)
    files+= [f for f in out.stdout.split() ]
files=sorted(set(files))
print("files:",len(files),file=sys.stderr)

def read(p):
    try:
        return open(p,encoding="utf-8",errors="replace").read()
    except: return ""

# regex for function definitions at col 0: type name(args)\n{
FUNC_RE=re.compile(r'^[A-Za-z_][\w\s\*,\(\)\[\]\.]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{', re.M)

def extract_funcs(src):
    funcs={}  # name -> (startline, body)
    for m in FUNC_RE.finditer(src):
        name=m.group(1)
        bstart=m.end()-1  # position of '{'
        depth=0; i=bstart
        while i < len(src):
            c=src[i]
            if c=='{': depth+=1
            elif c=='}':
                depth-=1
                if depth==0: break
            i+=1
        body=src[bstart:i+1]
        line=src[:m.start()].count('\n')+1
        # avoid redef better: keep first or longest
        if name not in funcs or len(body)>len(funcs[name][1]):
            funcs[name]=(line,body)
    return funcs

CALL_RE=re.compile(r'\b([A-Za-z_]\w*)\s*\(')

results=[]
for f in files:
    src=read(f)
    if not src: continue
    if 'tasklet' not in src and 'napi' not in src: continue
    # softirq entries
    soft=set()
    for m in re.finditer(r'tasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,',src):
        soft.add(m.group(1))
    for m in re.finditer(r'DECLARE_TASKLET(?:_OLD)?\s*\(\s*\w+\s*,\s*([A-Za-z_]\w*)',src):
        soft.add(m.group(1))
    for m in re.finditer(r'tasklet_(?:hi_)?schedule\s*\(',src):
        pass
    for m in re.finditer(r'netif_napi_add\s*\([^;]*?,\s*([A-Za-z_]\w*)\s*,',src):
        soft.add(m.group(1))
    # napi poll assigned via struct? also &dev->napi etc handled by name
    if not soft: continue
    funcs=extract_funcs(src)
    # build intra-file call graph
    def calls(body):
        return set(CALL_RE.findall(body))
    graph={n:calls(b) & set(funcs) for n,(l,b) in funcs.items()}
    # reachability from soft entries
    reach=set()
    stack=[s for s in soft if s in funcs]
    while stack:
        n=stack.pop()
        if n in reach: continue
        reach.add(n)
        stack.extend(graph.get(n,()))
    # find plain spin_lock sites in reachable funcs
    for n in reach:
        line0,body=funcs[n]
        for m in re.finditer(r'spin_lock(?:_nested)?\(\s*([^)]+)\)',body):
            lock=m.group(1).strip()
            bl=line0+body[:m.start()].count('\n')
            results.append((f.replace(ROOT+"/",""),n,bl,lock))
print(json.dumps(results,indent=0))
