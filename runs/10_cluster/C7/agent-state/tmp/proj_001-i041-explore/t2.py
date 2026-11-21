import re, os
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
count=0; found=0
def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
for dirpath, dirnames, filenames in os.walk(ROOT):
    if '/Documentation' in dirpath: continue
    for f in filenames:
        if f.endswith('.c'):
            count+=1
            p=os.path.join(dirpath,f)
            if 'sc92031' in f:
                for i,ln in enumerate(open(p,errors='replace')):
                    if def_re.match(ln.rstrip('\n')):
                        if 'sc92031_tasklet' in ln: found+=1
print("c files:",count,"sc92031_tasklet defs matched:",found)
