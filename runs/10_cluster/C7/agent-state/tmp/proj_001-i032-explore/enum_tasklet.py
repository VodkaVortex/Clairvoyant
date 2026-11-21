import os, re, subprocess, json, sys
root = os.getcwd()
# 1) find tasklet callback registrations: tasklet_init(&x, cb, data), DECLARE_TASKLET(name, cb, data), DECLARE_TASKLET_OLD
reg = re.compile(r'(tasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)\s*,|DECLARE_TASKLET(?:_OLD)?\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)\s*,?)')
files = subprocess.run(['grep','-rln','--include=*.c','tasklet_init\\|DECLARE_TASKLET','drivers','net','kernel','mm','fs','block','ipc','security','lib','sound','crypto','arch','samples'],capture_output=True,text=True).stdout.split()
cbs = {}
for f in files:
    try: txt = open(os.path.join(root,f),errors='ignore').read()
    except: continue
    for m in reg.finditer(txt):
        name = m.group(2) or m.group(3)
        if name: cbs.setdefault(name, []).append(f)
# 2) extract each callback body and look for plain spin_lock
def body(txt, fname):
    m = re.search(r'\b'+re.escape(fname)+r'\s*\([^;{]*\)\s*\{', txt)
    if not m: return None
    i = m.end()-1; depth=0
    for j in range(i,len(txt)):
        if txt[j]=='{': depth+=1
        elif txt[j]=='}':
            depth-=1
            if depth==0: return txt[i:j+1]
    return None
plain = re.compile(r'spin_lock\s*\(&?[^)]*\)')
out=[]
for cb, fl in sorted(cbs.items()):
    for f in fl:
        txt=open(os.path.join(root,f),errors='ignore').read()
        b=body(txt,cb)
        if not b: continue
        # plain spin_lock (not _bh/_irq/_irqsave/trylock)
        for mm in re.finditer(r'spin_lock\s*\(', b):
            out.append((f,cb,mm.group(0)))
print(json.dumps({'count_cb':len(cbs),'plain_hits':out},indent=1))
