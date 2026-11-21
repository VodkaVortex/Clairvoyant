path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01/arch/alpha/kernel/irq_alpha.c"
src = open(path, errors='replace').read()
print(repr(src[5800:6244]))
