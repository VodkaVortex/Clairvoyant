import os, re, sys, json
root="."
# 1) build map: function -> (file, startline, endline) for all .c files
func_re = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\([^;]*\)\s*$')
def scan_funcs(path):
    out={}
    try:
        lines=open(path,encoding='utf-8',errors='replace').read().split('\n')
    except Exception:
        return out
    cur=None; depth=0; start=0
    for i,l in enumerate(lines):
        if cur is None:
            m=func_re.match(l)
            if m and not l.strip().endswith(';'):
                cur=m.group(1); depth=l.count('(')-l.count(')'); start=i
                if depth==0:
                    out[cur]=(path,start+1,i+1); cur=None
                continue
        else:
            depth += l.count('(')-l.count(')')
            if depth<=0:
                out[cur]=(path,start+1,i+1); cur=None
    return out

funcmap={}
for dirpath,dirs,files in os.walk(root):
    if '/.git' in dirpath: continue
    for f in files:
        if f.endswith('.c'):
            p=os.path.join(dirpath,f)
            funcmap.update(scan_funcs(p))
print("funcs indexed:", len(funcmap), file=sys.stderr)
json.dump({k:v for k,v in funcmap.items()}, open('/tmp/i041_funcmap.json' if False else os.environ.get('TMPDIR','/tmp')+'/i041/funcmap.json','w'))
