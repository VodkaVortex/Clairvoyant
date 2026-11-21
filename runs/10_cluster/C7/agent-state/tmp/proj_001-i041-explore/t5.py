import re
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
p = ROOT + "/drivers/net/ethernet/silan/sc92031.c"
lines = open(p, errors='replace').readlines()
def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
matched=0
for i,ln in enumerate(lines):
    m=def_re.match(ln)
    if m:
        matched+=1
        if i<5 or 'tasklet' in ln:
            print(i+1, repr(ln[:60]), '->', m.group(1))
print("total matched:", matched)
