import re
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01/arch/alpha/kernel/irq_alpha.c"
src = open(path, errors='replace').read()
# search for "handler(" anywhere
for m in re.finditer(r'\bhandler\s*\(', src):
    line = src.count('\n',0,m.start())+1
    print("hit at", line, repr(src[max(0,m.start()-80):m.end()+40]))
