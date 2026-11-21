import re, os, json, sys
root='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s03'
sites=json.load(open(sys.argv[1]))
SAFE=re.compile(r'(>=\s*sizeof|>\s*sizeof\([^)]*\)\s*-\s*1|>\s*\d+\s*$|>=\s*\d+|!=\s*\d+|min\(count,\s*sizeof\([A-Za-z_]+\)\s*-\s*1|min_t\([^)]*sizeof\([A-Za-z_]+\)\s*-\s*1|-\s*1\s*\)|cnt\s*=\s*63|count\s*=\s*63)')
for s in sites:
    p=os.path.join(root,s['file']); lines=open(p,errors='ignore').read().splitlines()
    i=s['line']-1
    win='\n'.join(lines[max(0,i-20):i])
    verdict='SUSPECT'
    if SAFE.search(win): verdict='safe-guard-present'
    clamped = re.search(r'\b'+re.escape(s['idx'])+r'\s*=\s*min(?:_t\(\s*\w+\s*,\s*)?\(\s*[^,]+,\s*sizeof\(([^)]+)\)\s*\)',win)
    if not clamped:
        m=re.search(r'if\s*\(\s*(?:count|cnt|len|size|user_len|read_len|buf_size)\s*([<>]=?)\s*sizeof\(\1?\w*\)',win)
        if m: verdict='explicit-bound-check'
    print(f"{verdict}\t{s['file']}:{s['line']}\t{s['var']}[{s['idx']}] decl={s['decl']} clamp_to={clamped.group(1) if clamped else None}")
