import os, re
ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03'
T = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore'
regs = [l.rstrip('\n').split('\t') for l in open(T+'/handlers.txt')]
# per-file cache
filecache = {}
def get_lines(rel):
    if rel not in filecache:
        try:
            filecache[rel] = open(os.path.join(ROOT, rel), errors='ignore').read().splitlines()
        except Exception:
            filecache[rel] = []
    return filecache[rel]

func_start = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\([A-Za-z0-9_, \t\*]*\)\s*$|^\{')
def find_handler_body(rel, handler):
    lines = get_lines(rel)
    # find definition: "static irqreturn_t handler(" possibly across lines
    pat = re.compile(r'\b' + re.escape(handler) + r'\s*\(')
    for idx, ln in enumerate(lines):
        if pat.search(ln) and ('irqreturn_t' in ln or 'static' in ln or 'irq_handler_t' in ln):
            # walk back to include return type line if needed
            start = idx
            # find opening brace
            k = idx
            while k < len(lines) and '{' not in lines[k] and k - idx < 12:
                k += 1
            if k >= len(lines):
                continue
            # find closing brace at column 0
            end = k
            while end < len(lines) and lines[end] != '}':
                end += 1
            return (start, end, lines)
    return None

out = open(T+'/handler_locks.txt','w')
plain_lock = re.compile(r'spin_lock\s*\(')
stats = {'resolved':0, 'unresolved':0, 'with_plain_lock':0}
for rel, line, handler in regs:
    r = find_handler_body(rel, handler)
    if not r:
        stats['unresolved'] += 1
        continue
    stats['resolved'] += 1
    start, end, lines = r
    body = lines[start:end+1]
    locks = []
    for off, bl in enumerate(body):
        m = plain_lock.search(bl)
        if m:
            # extract lock argument
            arg = bl[bl.find('(', m.start())+1:]
            arg = arg[:arg.find(')')] if ')' in arg else arg
            locks.append((start+off+1, arg.strip()))
    if locks:
        stats['with_plain_lock'] += 1
        for ll, arg in locks:
            out.write(f"{rel}\t{ll}\t{handler}\t{arg}\n")
out.close()
print(stats)
