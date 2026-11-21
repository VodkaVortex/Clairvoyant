import os, re
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
lockcall_re = re.compile(r'\b(spin_(?:un)?lock(?:_bh|_irqsave|_irqrestore|_irq|_nested)?|spin_trylock(?:_bh)?)\s*\(')
def mode(fn):
    if 'irqsave' in fn or 'irqrestore' in fn: return 'irqsave'
    if '_bh' in fn: return 'bh'
    if 'irq' in fn: return 'irq'
    return 'plain'
def find_funcs(lines):
    out=[]
    for i,l in enumerate(lines):
        m=re.match(r'^(?:static\s+|inline\s+)*(?:const\s+)?[A-Za-z_][A-Za-z0-9_ \t\*&]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
        if m and not l.lstrip().startswith(('if','for','while','switch','return')) and '=' not in l.split('(')[0]:
            d=0;st=False
            for k in range(i,min(i+400,len(lines))):
                d+=lines[k].count('{')-lines[k].count('}')
                if '{' in lines[k]: st=True
                if st and d<=0 and k>i:
                    out.append((m.group(1),i,k)); break
    return out
targets = [
 ("drivers/net/eql.c", None),
 ("drivers/net/tun.c", [(430,485)]),
 ("drivers/net/ethernet/broadcom/bcm63xx_enet.c", [(280,300),(495,515)]),
 ("drivers/net/wireless/ath/ath9k/htc_drv_txrx.c", [(660,700),(760,800)]),
 ("drivers/net/wireless/ath/ath11k/wmi.c", [(6515,6600)]),
 ("drivers/net/ethernet/adaptec/starfire.c", [(580,620)]),
 ("drivers/net/wireless/intersil/hostap/hostap_ap.c", None),
]
for rel, ranges in targets:
    fp=os.path.join(ROOT,rel)
    if not os.path.exists(fp): print("MISSING",rel); continue
    lines=open(fp,errors='ignore').read().split('\n')
    funcs=find_funcs(lines)
    def fn_of(n):
        for (nm,s,e) in funcs:
            if s< n <=e: return f"{nm}({s+1}-{e+1})"
        return "?"
    print("="*100); print("FILE:",rel)
    for i,l in enumerate(lines):
        for m in lockcall_re.finditer(l):
            print(f"  L{i+1} [{mode(m.group(1))}] in {fn_of(i+1)}: {l.strip()[:130]}")
    if ranges:
        for (a,b) in ranges:
            print(f"  ---- exact {a}-{b} ----")
            for i in range(a-1,min(b,len(lines))):
                print(f"  {i+1}: {lines[i]}")
