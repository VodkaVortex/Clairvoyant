# take the sc92031 tasklet cb and run scan_function to see where it fails
import re, os
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
p = ROOT + "/drivers/net/ethernet/silan/sc92031.c"
lines = open(p, errors='replace').readlines()
defs={}
for i,ln in enumerate(lines):
    m = def_re.match(ln)
    if m and not ln.lstrip().startswith(('#','//','*','/*')):
        name=m.group(1)
        defs.setdefault(name,(p,i))
print("defs found in file:", len(defs))
print("sc92031_tasklet def:", defs.get('sc92031_tasklet'))
