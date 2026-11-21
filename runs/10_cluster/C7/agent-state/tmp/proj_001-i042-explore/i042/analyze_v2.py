import re, os, sys, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath("$TMPDIR/i042/analyze_v2.py")))
sys.path.insert(0, "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i042-explore/i042")
from find_func_v2 import read, strip_comments_strings, find_all_funcs

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"

lockre = re.compile(r'\bspin_(?:try)?lock(?:_bh|_irq|_irqsave|_irqrestore|_nested|_bh_nested|_irqsave_nested)?\s*\(\s*&?\s*([A-Za-z0-9_\>\.\-\[\]\(\)-> ]+?)\s*[,)]')
unlockre = re.compile(r'\bspin_unlock(?:_bh|_irq|_irqrestore)?\s*\(\s*&?\s*([A-Za-z0-9_\>\.\-\[\]\(\)-> ]+?)\s*[,)]')

filecache={}
def get(f):
    if f not in filecache:
        raw=open(os.path.join(root,f),errors="ignore").read()
        stripped=strip_comments_strings(raw)
        lines=stripped.split("\n")
        funcs=find_all_funcs(lines)
        filecache[f]=(lines,funcs,raw.split("\n"))
    return filecache[f]

tasklets=[]
for line in open(sys.argv[1]):
    parts=line.rstrip("\n").split("\t")
    if len(parts)<4: continue
    f,ln,tasklet,cb = parts[0],int(parts[1]),parts[2],parts[3]
    tasklets.append((f,ln,tasklet,cb))

for f,ln,tasklet,cb in tasklets:
    try:
        lines,funcs,rawlines = get(f)
    except Exception as e:
        print(f"{f}\t{ln}\t{cb}\tERR {e}")
        continue
    if cb not in funcs:
        print(f"{f}\t{ln}\t{cb}\tNOFUNCDEF")
        continue
    a,b = funcs[cb]
    # locks in body plus same-file direct callees (1 level)
    callees=set(re.findall(r'\b([a-z_][a-z0-9_]{2,})\s*\(', "\n".join(lines[a:b+1])))
    skip=set("if for while switch return sizeof else do spin_lock spin_unlock spin_lock_irqsave spin_unlock_irqrestore spin_lock_bh spin_unlock_bh kmalloc kzalloc dev_warn dev_err dev_info netdev_warn cpu_relax udelay mdelay printk pr_info pr_err pr_warn memcpy memset".split())
    locks=[]
    def scan(a,b,depth_name):
        for i in range(a,b+1):
            for m in lockre.finditer(lines[i]):
                locks.append((i+1, m.group(0)[m.group(0).find("spin_"):m.group(0).find("(")], m.group(1), depth_name))
    scan(a,b,cb)
    for c in sorted(callees):
        if c in skip or c==cb: continue
        if c in funcs:
            ca,cbn=funcs[c]
            if ca>b+1 or cbn<a-1:  # defined outside body
                scan(ca,cbn,c)
    if locks:
        print(f"{f}\t{ln}\t{cb}\t{a+1}-{b+1}\t" + ";".join(f"{l}|{fn}|{n}|{src}" for l,fn,n,src in locks))
