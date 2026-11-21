import re, subprocess, os
root="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
out=subprocess.run(["grep","-rn","-e","tasklet_init","-e","DECLARE_TASKLET","--include=*.c","."],cwd=root,capture_output=True,text=True).stdout
pairs=[]
for line in out.splitlines():
    m=re.search(r'^(\S+):(\d+):(.*)$',line)
    if not m: continue
    path,ln,txt=m.group(1),int(m.group(2)),m.group(3)
    for mm in re.finditer(r'tasklet_init\([^,]+,\s*([A-Za-z_0-9]+)\s*,',txt):
        pairs.append((path,ln,mm.group(1)))
    for mm in re.finditer(r'DECLARE_TASKLET(?:_DISABLED)?\w*\(\s*(\w+)\s*,\s*(\w+)',txt):
        pairs.append((path,ln,mm.group(2)))
seen=set(); res=[]
for p in pairs:
    k=(p[0],p[2])
    if k in seen: continue
    seen.add(k); res.append(p)
print(len(res))
with open("tasklet_cbs.txt","w") as f:
    for path,ln,fn in res:
        f.write(f"{path}:{ln}:{fn}\n")
