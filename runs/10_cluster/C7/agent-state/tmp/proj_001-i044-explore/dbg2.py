import re
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01/arch/alpha/kernel/irq_alpha.c"
src = open(path, errors='replace').read()
h = 'handler'
pat = re.compile(r'(?:^|\n)((?:[A-Za-z_][A-Za-z_0-9]*\s+)*'+re.escape(h)+r'\s*\()', re.M)
found = pat.findall(src)
print("finds:", found[:5])
for m in pat.finditer(src):
    start = src.rfind('\n', 0, m.start(1))+1
    defline = src.count('\n',0,m.start(1))+1
    prefix = src[start:m.start(1)]
    print(repr(prefix), defline, 'irqreturn' in prefix)
i = src.find('irqreturn')
print(repr(src[max(0,i-300):i+400]))
