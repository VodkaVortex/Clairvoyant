path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01/arch/alpha/kernel/irq_alpha.c"
src = open(path, errors='replace').read()
print("len", len(src))
print("handler in src:", 'handler' in src)
print("request_irq in src:", 'request_irq' in src)
import re
for m in re.finditer('handler', src):
    print(m.start())
    break
