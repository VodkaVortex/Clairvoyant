import re, os, sys, subprocess

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"
# get file list from grep
out = subprocess.run(["grep","-rln","--include=*.c","--include=*.h","tasklet_init\\|tasklet_setup","drivers/","net/"],cwd=root,capture_output=True,text=True).stdout.split()
results=[]
func_def = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*$')
for f in out:
    p=os.path.join(root,f)
    try:
        lines=open(p,errors="ignore").read().split("\n")
    except: continue
    for i,l in enumerate(lines):
        if "tasklet_init(" in l or "tasklet_setup(" in l:
            m=re.search(r'tasklet_(?:init|setup)\s*\(\s*&?([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,',l)
            if not m:
                m=re.search(r'tasklet_(?:init|setup)\s*\(\s*&?([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,',l+"\n".join(lines[i:i+2]))
            if m:
                results.append((f,i+1,m.group(1),m.group(2)))
for r in results:
    print("\t".join(map(str,r)))
