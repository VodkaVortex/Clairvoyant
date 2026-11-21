import re, sys, os
S='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/public/snapshots/s03'
targets=[]
import subprocess
out=subprocess.run(['grep','-rn','\\.changelink','drivers','net','--include=*.c'],cwd=S,capture_output=True,text=True).stdout
for line in out.splitlines():
    path,ln,txt=line.split(':',2)
    if '= NULL' in txt or 'NULL,' in txt: continue
    m=re.search(r'= (\w+),',txt)
    if m: targets.append((path,int(ln),m.group(1)))

def func_body(src, name):
    # find definition start
    pat=re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*]*?\b'+re.escape(name)+r'\s*\(', re.M)
    m=pat.search(src)
    if not m: return None,None
    start=src.rfind('\n',0,m.start())+1
    # find matching closing brace at col 0
    idx=src.find('{', m.end())
    if idx<0: return None,None
    depth=0
    i=idx
    while i<len(src):
        c=src[i]
        if c=='{': depth+=1
        elif c=='}':
            depth-=1
            if depth==0:
                return start, src.count('\n',0,i)+1, src[start:i+1]
        i+=1
    return start,None,None

attr_re=re.compile(r'(data|tb)\[([A-Z][A-Z0-9_]+)\]')
guard_re=re.compile(r'if\s*\([^)]*\b(data|tb)\[([A-Z][A-Z0-9_]+)\][^)]*\)')
use_re=re.compile(r'(?:nla_data|nla_get_\w+|nla_len|nla_is_nested|nla_nest_start|memcmp|memcpy)\s*\(\s*(?:data|tb)\[([A-Z][A-Z0-9_]+)\]')

for path,ln,name in targets:
    full=os.path.join(S,path)
    src=open(full,errors='ignore').read()
    res=func_body(src,name)
    if not res or res[1] is None:
        print(f"## {path}:{ln} {name}: FAILED to extract"); continue
    start,end,body=res
    guarded=set()
    for m in guard_re.finditer(body):
        guarded.add(m.group(2))
    # also 'if (data[X] || ...)' forms and 'if (!data[X])' handled; also 'switch (data[X])'? treat separately
    for m in re.finditer(r'if\s*\(\s*!(?:data|tb)\[([A-Z][A-Z0-9_]+)\]',body):
        guarded.add(m.group(1))
    problems=[]
    for m in use_re.finditer(body):
        a=m.group(1)
        if a not in guarded:
            line_no=start+body[:m.start()].count('\n')
            problems.append((a,line_no,body.splitlines()[body[:m.start()].count('\n')].strip()))
    if problems:
        print(f"## {path} {name} (def lines {start}-{end}):")
        for a,l,t in problems:
            print(f"   line {l}: attr {a}: {t}")
