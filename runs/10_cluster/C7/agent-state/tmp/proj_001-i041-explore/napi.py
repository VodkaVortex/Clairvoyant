import re, subprocess
root="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
out=subprocess.run(["grep","-rn","netif_napi_add","--include=*.c","."],cwd=root,capture_output=True,text=True).stdout
pairs=[]
for line in out.splitlines():
    m=re.search(r'^(\S+):(\d+):(.*)$',line)
    if not m: continue
    path,ln,txt=m.group(1),int(m.group(2)),m.group(3)
    for mm in re.finditer(r'netif_napi_add(?:_weight)?\s*\(([^;]*?)\)\s*;',txt):
        args=mm.group(1)
        toks=[t.strip() for t in args.split(',')]
        if len(toks)>=3:
            fn=re.sub(r'[^A-Za-z_0-9].*$','',toks[2])
            if fn: pairs.append((path,ln,fn))
seen=set(); res=[]
for path,ln,fn in pairs:
    k=(path,fn)
    if k in seen: continue
    seen.add(k); res.append((path,ln,fn))
print(len(res))
with open("napi_cbs.txt","w") as f:
    for path,ln,fn in res:
        f.write(f"{path}:{ln}:{fn}\n")
