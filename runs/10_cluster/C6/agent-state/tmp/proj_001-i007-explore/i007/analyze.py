import re, sys, os, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s02"
W = os.environ["W"]

CALL_RE = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|skb_share_check|pskb_expand_head)\s*\(')

def load(path):
    with open(os.path.join(ROOT, path), errors='replace') as fh:
        return fh.read().split('\n')

def find_functions(lines):
    starts = []
    for i, ln in enumerate(lines):
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*?)\s*\(', ln)
        if m:
            name = m.group(1).split()[-1]
            if '{' in ln:
                starts.append((i+1, name)); continue
            ok = False
            for j in range(i, min(i+4, len(lines))):
                if '{' in lines[j]: ok = True; break
                if lines[j].strip().endswith(';') and j != i: break
            if ok:
                starts.append((i+1, name))
    return starts

results = []
with open(os.path.join(W, 'files.txt')) as fh:
    files = [l.strip() for l in fh if l.strip()]

for path in files:
    try:
        lines = load(path)
    except Exception as e:
        print("ERR", path, e); continue
    starts = find_functions(lines)
    for i, ln in enumerate(lines):
        m = CALL_RE.search(ln)
        if not m: continue
        fn = None
        for (ls, name) in starts:
            if ls <= i+1: fn = (ls, name)
            else: break
        if fn is None: continue
        fs, fname = fn
        idx = starts.index(fn)
        end = starts[idx+1][0]-1 if idx+1 < len(starts) else len(lines)
        body = lines[fs-1:end]
        decls = []
        for k, bl in enumerate(body):
            dm = re.match(r'^\t(?:static\s+)?(?:const\s+)?(?:register\s+)?(?:volatile\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\s+\*+\s*([A-Za-z_][A-Za-z0-9_]*)', bl)
            dm2 = re.match(r'^\t(?:static\s+)?(?:const\s+)?(u8|u16|u32|u64|unsigned char|char|void|__be16|__be32|__le16|__le32|__wsum)\s+\*+\s*([A-Za-z_][A-Za-z0-9_]*)', bl)
            d = None
            if dm: d = dm.group(2)
            elif dm2: d = dm2.group(2)
            if d: decls.append((fs+k, d))
        if not decls: continue
        for (dl, name) in decls:
            assign_lines = [fs+k for k,bl in enumerate(body) if re.search(r'\b'+name+r'\s*=(?!=)', bl)]
            use_after = []
            for k,bl in enumerate(body):
                lineno = fs+k
                if lineno <= i+1: continue
                if re.search(r'\b'+name+r'\b', bl):
                    use_after.append((lineno, bl.strip()[:130]))
            if assign_lines and use_after:
                results.append({
                    'file': path, 'func': fname, 'func_line': fs,
                    'call_line': i+1, 'call': ln.strip()[:130],
                    'ptr': name, 'assign': assign_lines,
                    'uses_after': use_after[:10],
                })

with open(os.path.join(W, 'candidates.json'), 'w') as fh:
    json.dump(results, fh, indent=1)
print(len(results))
