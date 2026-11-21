import re, os, sys, subprocess
sys.path.insert(0, "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i042-explore/i042")
from find_func_v2 import strip_comments_strings, find_all_funcs

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"
out = subprocess.run(["grep","-rln","--include=*.c","netif_napi_add","drivers/","net/"],cwd=root,capture_output=True,text=True).stdout.split()

lockre = re.compile(r'\bspin_(?:try)?lock(?:_bh|_irq|_irqsave|_irqrestore|_nested|_bh_nested|_irqsave_nested)?\s*\(\s*&?\s*([A-Za-z0-9_\>\.\-\[\]\(\)-> ]+?)\s*[,)]')
skip=set("if for while switch return sizeof else do spin_lock spin_unlock spin_lock_irqsave spin_unlock_irqrestore spin_lock_bh spin_unlock_bh kmalloc kzalloc dev_warn dev_err dev_info netdev_warn cpu_relax udelay mdelay printk pr_info pr_err pr_warn memcpy memset".split())

for f in out:
    p=os.path.join(root,f)
    raw=open(p,errors="ignore").read()
    stripped=strip_comments_strings(raw)
    lines=stripped.split("\n")
    funcs=find_all_funcs(lines)
    for i,l in enumerate(lines):
        m=re.search(r'netif_napi_add(?:_weight|_tx)?\s*\(\s*[^,]+,\s*&?\s*([A-Za-z0-9_\>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,',l)
        if m:
            poll=m.group(2)
            if poll in funcs:
                a,b=funcs[poll]
                locks=[]
                def scan(a,b,src):
                    for k in range(a,b+1):
                        for mm in lockre.finditer(lines[k]):
                            locks.append((k+1, mm.group(0)[mm.group(0).find("spin_"):mm.group(0).find("(")], mm.group(1), src))
                scan(a,b,poll)
                callees=set(re.findall(r'\b([a-z_][a-z0-9_]{2,})\s*\(', "\n".join(lines[a:b+1])))
                for c in sorted(callees):
                    if c in skip or c==poll: continue
                    if c in funcs:
                        ca,cbn=funcs[c]
                        if ca>b+1 or cbn<a-1:
                            scan(ca,cbn,c)
                if locks:
                    print(f"{f}\t{i+1}\t{poll}\t{a+1}-{b+1}\t" + ";".join(f"{ln}|{fn}|{n}|{src}" for ln,fn,n,src in locks))
            else:
                print(f"{f}\t{i+1}\t{poll}\tNOFUNCDEF")
