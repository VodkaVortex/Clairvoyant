import re, os, subprocess, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11"

# Get files under net-related dirs that schedule tasklets
files = subprocess.check_output(["/usr/bin/rg","-l","tasklet_schedule|tasklet_hi_schedule|tasklet_setup|DECLARE_TASKLET|tasklet_init","--type","c", ROOT], text=True).splitlines()

tasklet_re = re.compile(r'(?:tasklet_setup\s*\(\s*&?[^,]+,\s*([A-Za-z_0-9]+)\s*\)|DECLARE_TASKLET[^ (]*\s*\(\s*[A-Za-z_0-9]+\s*,\s*([A-Za-z_0-9]+)|tasklet_init\s*\([^;]*?,\s*([A-Za-z_0-9]+)\s*,)')

results = {}
for f in files:
    try:
        src = open(f, errors="replace").read()
    except Exception:
        continue
    cbs = set()
    for m in tasklet_re.finditer(src):
        for g in m.groups():
            if g: cbs.add(g)
    if not cbs: continue
    # find function bodies of callbacks and plain spin_lock within
    for cb in cbs:
        # find function definition "cb(...)" possibly static
        fm = re.search(r'(?:^|\n)[A-Za-z_0-9 \t\*]+\b'+re.escape(cb)+r'\s*\(', src)
        if not fm: continue
        start = src.find('{', fm.start())
        if start < 0: continue
        # match braces
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
            results.setdefault(f, []).append({"callback": cb, "line": linestart, "plain_locks": locks})

print(json.dumps(results, indent=1))
