import os,re,sys,json
T=os.environ.get('TMPDIR','/tmp')+'/i041'
sys.path.insert(0,T)
from funcbody import find_func
lockre=re.compile(r'spin_(?:un)?lock(?:_irqsave(?:_nested)?|_irq|_bh|_irqrestore)?\s*\(\s*&?\s*([^,()]+?)\s*[,)]')
plainre=re.compile(r'spin_lock\s*\(\s*&?\s*([^,()]+?)\s*\)')
reg_patterns=[
  (re.compile(r'DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*(\w+)\s*,\s*(\w+)'), 'DECLARE_TASKLET'),
  (re.compile(r'tasklet_init\s*\(\s*&?\s*([\w\.\->]+)\s*,\s*(\w+)\s*,'), 'tasklet_init'),
]
regs=[]
filecache={}
def gettext(p):
    if p not in filecache:
        filecache[p]=open(p,encoding='utf-8',errors='replace').read()
    return filecache[p]
for dirpath,dirs,files in os.walk('.'):
    if '/.git' in dirpath: continue
    for f in files:
        if not f.endswith(('.c','.h')): continue
        p=os.path.join(dirpath,f)
        for pat,kind in reg_patterns:
            for m in pat.finditer(gettext(p)):
                line=gettext(p)[:m.start()].count('\n')+1
                regs.append((p,line,m.group(1),m.group(2),kind))
print("tasklet regs:",len(regs),file=sys.stderr)
out=[]
for p,ln,tname,cb,kind in regs:
    try:
        text=gettext(p)
    except Exception:
        out.append([p,ln,tname,cb,kind,'ERR',0,0,[]]); continue
    r=find_func(text,cb)
    if not r:
        out.append([p,ln,tname,cb,kind,None,0,0,[]]); continue
    fs,fe=r
    body='\n'.join(text.split('\n')[fs-1:fe])
    locks=lockre.findall(body)
    out.append([p,ln,tname,cb,kind,p,fs,fe,sorted(set(locks))])
json.dump(out,open(T+'/tasklet_regs2.json','w'),indent=0)
miss=0
for o in out:
    if len(o)>7 and o[7]:
        print(o[0],o[1],o[2],'->',o[3],'def',o[6],o[7],o[8],'locks:',o[9])
    elif len(o)<=5 or o[5] is None:
        miss+=1
print("NOTFOUND:",miss,file=sys.stderr)
