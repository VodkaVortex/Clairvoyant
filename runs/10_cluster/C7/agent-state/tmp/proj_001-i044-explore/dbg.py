import re, os
root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)
src = open("arch/alpha/kernel/irq_alpha.c", errors='replace').read()
h = 'handler'
for m in re.finditer(r'(?:^|\n)((?:[A-Za-z_][A-Za-z_0-9]*\s+)*'+re.escape(h)+r'\s*\()', src):
    start = src.rfind('\n', 0, m.start(1))+1
    defline = src.count('\n',0,m.start(1))+1
    prefix = src[start:m.start(1)]
    print(repr(prefix), defline, 'irqreturn' in prefix)
i = src.find('irqreturn')
print(src[max(0,i-200):i+300])
