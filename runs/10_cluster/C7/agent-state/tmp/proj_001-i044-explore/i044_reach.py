import re, os, sys
from collections import defaultdict

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)

hlock = [l.rstrip('\n').split('\t') for l in open(os.path.join(os.environ['TMPDIR'],'handlers_locks.tsv'))]

# group handler->(file,lock)
targets = defaultdict(set)  # file -> set of (handler, lock)
for f,l,h,kind,lock in hlock:
    targets[f].add((h,lock))

funcdef = re.compile(r'^([A-Za-z_][A-Za-z_0-9]*)\s*\(')

def parse_file(f):
    src = open(f, errors='replace').read()
    lines = src.split('\n')
    funcs = {}  # name -> (startline, endline)
    callmap = defaultdict(set)  # func -> called names
    cur = None; depth = 0
    callpat = re.compile(r'([A-Za-z_][A-Za-z_0-9]*)\s*\(')
    for i,l in enumerate(lines):
        if cur is None:
            m = funcdef.match(l.strip())
            if m and depth==0 and '{' in (l + (lines[i+1] if i+1<len(lines) else '')):
                cur = m.group(1); funcs[cur]=(i+1,i+1); depth = l.count('{') - l.count('}')
                continue
        else:
            depth += l.count('{') - l.count('}')
            for c in callpat.findall(l):
                callmap[cur].add(c)
            if depth<=0:
                funcs[cur]=(funcs[cur][0], i+1)
                cur=None; depth=0
    return funcs, callmap, lines

out = []
for f, hs in targets.items():
    try:
        funcs, callmap, lines = parse_file(f)
    except Exception as e:
        continue
    for handler, lock in hs:
        if handler not in funcs: continue
        # BFS within file
        seen = {handler}; q=[handler]
        while q:
            x = q.pop()
            for c in callmap.get(x,()):
                if c in funcs and c not in seen:
                    seen.add(c); q.append(c)
        lockesc = re.escape(lock)
        plainpat = re.compile(r'(?<![_\w])spin_lock\s*\(\s*&?\s*'+lockesc+r'\s*\)')
        for i,l in enumerate(lines):
            if plainpat.search(l):
                # find enclosing function
                enc = None
                for name,(s,e) in funcs.items():
                    if s <= i+1 <= e:
                        enc = name; break
                reach = enc in seen if enc else False
                out.append((f, i+1, handler, lock, enc, reach))

with open(os.path.join(os.environ['TMPDIR'],'reach.tsv'),'w') as o:
    for r in out:
        o.write('\t'.join(map(str,r))+'\n')
print("plain sites total:", len(out), "non-handler-reachable:", sum(1 for r in out if not r[5]))
