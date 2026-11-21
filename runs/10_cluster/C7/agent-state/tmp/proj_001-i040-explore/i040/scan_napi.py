import re, subprocess, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11"
files = subprocess.check_output(["/usr/bin/rg","-l","netif_napi_add|napi_schedule","--type","c", ROOT+"/drivers", ROOT+"/net"], text=True).splitlines()

napi_re = re.compile(r'netif_napi_add(?:_compatible|_weight)?\s*\([^;]*?,\s*([A-Za-z_0-9]+)\s*,')
# also netif_napi_add(dev, &x->napi, poll) forms with final arg weight

results = {}
for f in files:
    try:
        src = open(f, errors="replace").read()
    except Exception:
        continue
    cbs = set()
    for m in napi_re.finditer(src):
        cbs.add(m.group(1))
    if not cbs: continue
    for cb in cbs:
        fm = re.search(r'(?:^|\n)[A-Za-z_0-9 \t\*]+\b'+re.escape(cb)+r'\s*\(', src)
        if not fm: continue
        start = src.find('{', fm.start())
        if start < 0: continue
        depth=0; i=start
        while i < len(src):
            if src[i]=='{': depth+=1
            elif src[i]=='}':
                depth-=1
                if depth==0: break
            i+=1
        body = src[start:i]
        linestart = src[:fm.start()].count('\n')+1
        locks = []
        for lm in re.finditer(r'spin_lock\s*\(\s*([^;]+?)\s*\)', body):
            locks.append((linestart + body[:lm.start()].count('\n'), lm.group(1)))
        if locks:
            results.setdefault(f, []).append({"poll": cb, "line": linestart, "plain_locks": locks})

print(json.dumps(results, indent=1))
