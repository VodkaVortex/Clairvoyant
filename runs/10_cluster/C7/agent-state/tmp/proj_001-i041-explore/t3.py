import re, os
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
pat_init = re.compile(r'tasklet_init\s*\(\s*&?[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
pat_decl = re.compile(r'DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
cbs={}
nfiles=0
for dirpath, dirnames, filenames in os.walk(ROOT):
    if '/Documentation' in dirpath: continue
    for f in filenames:
        if f.endswith('.c') or f.endswith('.h'):
            p=os.path.join(dirpath,f); nfiles+=1
            try: txt=open(p,errors='replace').read()
            except: continue
            for m in pat_init.finditer(txt): cbs.setdefault(m.group(1),[]).append(p)
            for m in pat_decl.finditer(txt): cbs.setdefault(m.group(1),[]).append(p)
print("files scanned:",nfiles,"unique tasklet callbacks:",len(cbs))
print("sc92031_tasklet in cbs:", 'sc92031_tasklet' in cbs)
print(list(cbs)[:10])
