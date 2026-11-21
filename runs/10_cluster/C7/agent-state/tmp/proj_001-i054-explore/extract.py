import os, re, json, collections

ROOT="."
spin_re = re.compile(r'\b(spin_lock|spin_trylock|spin_lock_irq|spin_lock_irqsave|spin_lock_bh|spin_unlock|spin_unlock_irq|spin_unlock_irqrestore|spin_unlock_bh)\s*\(')

def walk():
    for dp,dn,fn in os.walk(ROOT):
        if any(x in dp for x in ('/Documentation','/scripts','/tools','/.git')):
            continue
        for f in fn:
            if f.endswith(('.c','.h')):
                yield os.path.join(dp,f)

# 1) collect request_irq registrations
reg_re = re.compile(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(')
handler_re = re.compile(r'^\s*[\w\.\-\>\&]+\s*[,]?\s*$', re.M)

regs=[]   # (file, line, kind, handler)
for path in walk():
    try:
        txt=open(path, errors='ignore').read()
    except Exception:
        continue
    for m in reg_re.finditer(txt):
        start=txt.rfind('\n',0,m.start())+1
        # find matching close paren
        depth=0; i=m.end()-1
        while i < len(txt):
            if txt[i]=='(': depth+=1
            elif txt[i]==')':
                depth-=1
                if depth==0: break
            i+=1
        argtxt=txt[m.end():i]
        # split top-level commas
        args=[]; d=0; cur=''
        for ch in argtxt:
            if ch in '([': d+=1
            elif ch in ')]': d-=1
            elif ch==',' and d==0:
                args.append(cur.strip()); cur=''
                continue
            cur+=ch
        args.append(cur.strip())
        kind='threaded' if 'request_threaded_irq' in m.group(0) else 'irq'
        h = args[1] if len(args)>1 else ''
        line = txt.count('\n',0,m.start())+1
        regs.append({'file':path,'line':line,'kind':kind,'handler':h,'argc':len(args)})

print("total registrations:", len(regs))
with open(os.path.join(os.environ['TMPDIR'],'regs.json'),'w') as f:
    json.dump(regs,f)
