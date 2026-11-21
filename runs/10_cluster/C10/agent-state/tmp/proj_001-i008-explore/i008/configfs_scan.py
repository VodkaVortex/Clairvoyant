import re, os, json, subprocess

S02 = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"

# configfs store functions: CONFIGFS_ATTR / CONFIGFS_ATTR_RO / CONFIGFS_BIN_ATTR / __CONFIGFS_ATTR
pat = re.compile(r'__CONFIGFS_ATTR(?:_RO|_WO)?\s*\(\s*(\w+)\s*,\s*\d*\s*,\s*\w+\s*,\s*(\w+)\s*\)')
pat2 = re.compile(r'CONFIGFS_ATTR(?:_RO|_WO)?\s*\(\s*(\w+)\s*,\s*\w+\s*\)')

results = []
for root, dirs, fs_ in os.walk(S02):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for fname in fs_:
        if not fname.endswith('.c'): continue
        p = os.path.join(root, fname)
        try: src = open(p, errors='replace').read()
        except: continue
        for m in pat.finditer(src):
            results.append((os.path.relpath(p, S02), m.group(1), m.group(2)))
        for m in pat2.finditer(src):
            results.append((os.path.relpath(p, S02), m.group(1), None))

stores = {}
for f, name, store in results:
    if store:
        stores.setdefault(f, []).append((name, store))
print("configfs attrs with explicit store fn:", sum(len(v) for v in stores.values()), "in", len(stores), "files")
for f, v in sorted(stores.items()):
    print(f, [s for _, s in v])
json.dump(stores, open('configfs_stores.json','w'), indent=1)
