import os,re,sys,json
T=os.environ.get('TMPDIR','/tmp')+'/i041'
funcmap=json.load(open(T+'/funcmap.json'))
lockre=re.compile(r'spin_lock(?:_irqsave|_irq|_bh|_irqsave_nested)?\s*\(\s*&?([^,)]+)')
lockre2=re.compile(r'spin_unlock(?:_irqrestore|_irq|_bh)?\s*\(\s*&?([^,)]+)')

# find tasklet callback registrations
# patterns: DECLARE_TASKLET(name, func, ...), DECLARE_TASKLET_DISABLED, tasklet_init(&t, func, ...)
reg_patterns=[
  (re.compile(r'DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*(\w+)\s*,\s*(\w+)'), 'DECLARE_TASKLET'),
  (re.compile(r'tasklet_init\s*\(\s*&?\s*([\w\.\->]+)\s*,\s*(\w+)\s*,'), 'tasklet_init'),
  (re.compile(r'tasklet_init\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*'), 'tasklet_init'),
]
regs=[]
for dirpath,dirs,files in os.walk('.'):
    if '/.git' in dirpath: continue
    for f in files:
        if not f.endswith(('.c','.h')): continue
        p=os.path.join(dirpath,f)
        try: lines=open(p,encoding='utf-8',errors='replace').read().split('\n')
        except Exception: continue
        for i,l in enumerate(lines):
            for pat,kind in reg_patterns:
                m=pat.search(l)
                if m:
                    regs.append((p,i+1,m.group(1),m.group(2),kind))
print("tasklet registrations:", len(regs), file=sys.stderr)
out=[]
for p,ln,tname,cb,kind in regs:
    fl=funcmap.get(cb)
    if not fl:
        # maybe defined in same file after; try search same file
        out.append((p,ln,tname,cb,kind,None,None,None))
        continue
    fp,fs,fe=fl
    body='\n'.join(open(fp,encoding='utf-8',errors='replace').read().split('\n')[fs-1:fe])
    locks=lockre.findall(body)
    plain=[l for l in locks if 'spin_lock(' in ''.join(lockre.findall(body)) ]
    out.append((p,ln,tname,cb,kind,fp,fs,fe,sorted(set(locks))))
json.dump(out,open(T+'/tasklet_regs.json','w'),indent=0)
for o in out:
    if len(o)>=9 and o[8]:
        print(o[0],o[1],o[2],'->',o[3],'def',o[5],o[6],o[7],'locks:',o[8])
