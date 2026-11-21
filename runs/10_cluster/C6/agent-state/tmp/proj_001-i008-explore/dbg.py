import sys
sys.path.insert(0, "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/tmp/proj_001-i008-explore")
from find_stale import split_functions, PULL_RE, ROOT
import os, re
p = os.path.join(ROOT, "net/phonet/pep.c")
src = open(p).read()
funcs = split_functions(src)
print("functions found:", len(funcs))
for f in funcs[:10]:
    print(f[0], f[1], len(f[2]))
