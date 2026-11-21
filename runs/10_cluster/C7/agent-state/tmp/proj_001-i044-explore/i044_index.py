import re, os, subprocess

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)
pat = re.compile(r'\b(request_irq|devm_request_irq|devm_request_threaded_irq|request_threaded_irq)\s*\(')
files = subprocess.run(['grep','-rl','--include=*.c','-e','request_irq(','-e','request_threaded_irq(','.'],capture_output=True,text=True).stdout.split()
out = []
for f in files:
    try:
        src = open(f, errors='replace').read()
    except: continue
    lines = src.split('\n')
    for i,l in enumerate(lines):
        m = pat.search(l)
        if not m: continue
        blob = '\n'.join(lines[i:i+9])
        argm = re.search(r'(request_irq|devm_request_irq|devm_request_threaded_irq|request_threaded_irq)\s*\(\s*([^,]+?),\s*([A-Za-z_0-9.>\-]+)', blob)
        if argm:
            out.append((f, i+1, argm.group(1), argm.group(3)))
for f,l,k,h in out:
    print(f"{f}\t{l}\t{k}\t{h}")
