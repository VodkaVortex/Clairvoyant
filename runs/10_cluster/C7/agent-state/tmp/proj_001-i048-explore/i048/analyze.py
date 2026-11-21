import os,re,subprocess,collections
TMP=os.path.join(os.environ["TMPDIR"],"i048")
regs=[]
for line in open(os.path.join(TMP,"irq_regs.txt")):
    parts=line.rstrip("\n").split("\t")
    if len(parts)<4: continue
    f,ln,kind,text=parts[0],int(parts[1]),parts[2],parts[3]
    # skip macros / comment lines
    if text.lstrip().startswith("#") or text.startswith("*") or text.startswith("/*"):
        continue
    regs.append((f,ln,kind,text))
print("non-macro regs",len(regs))

func_def_re=re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
lock_re=re.compile(r'\bspin_(?:lock|unlock)(?:_irqsave|_irqrestore|_irq|_bh|_nested)?\s*\(([^;]*)\)')
plain_lock_re=re.compile(r'\bspin_lock\s*\(([^;]*)\)')

def extract_handler_name(text):
    # find first argument that looks like a function name: skip flags/devname
    inner=text[text.find("(")+1:]
    # naive: capture the argument that is an identifier not a number/flag
    # typical order: request_irq(irq, handler, flags, name, dev)
    args=[]
    depth=0;cur=""
    for ch in inner:
        if ch=="(":
            depth+=1;cur+=ch
        elif ch==")":
            if depth==0: break
            depth-=1;cur+=ch
        elif ch=="," and depth==0:
            args.append(cur.strip());cur=""
        else: cur+=ch
    args.append(cur.strip())
    # handler is arg idx 1 for request_irq/devm_request_irq(request_irq(irq,handler,...)) 
    # devm_request_irq(dev, irq, handler,...): idx2 ; request_threaded_irq(irq,handler,thread,flags,...): idx1 primary
    # devm_request_threaded_irq(dev,irq,handler,thread,flags,..): idx2
    idx_map={"request_irq":1,"request_threaded_irq":1,"devm_request_irq":2,"devm_request_threaded_irq":2}
    idx=idx_map.get(text.strip().split("(")[0])
    if idx is None:
        m=re.match(r'(\w+)\s*\(',text.strip()); idx=idx_map.get(m.group(1)) if m else None
    if idx is None or idx>=len(args): return None,inner
    h=args[idx]
    h=re.sub(r'\s+','',h)
    return h,args

handler_site={}  # handlername -> list of (file,line,regtext)
unresolved=0
for f,ln,kind,text in regs:
    h,args=extract_handler_name(text)
    if not h or not re.fullmatch(r'&?[A-Za-z_][A-Za-z0-9_]*',h):
        unresolved+=1;continue
    handler_site.setdefault(h.lstrip("&"),[]).append((f,ln,text))

print("handler names resolved:",len(handler_site),"unresolved:",unresolved)
# save
with open(os.path.join(TMP,"handlers.txt"),"w") as fh:
    for h,sites in sorted(handler_site.items()):
        fh.write(h+"\t"+";".join(f"{s[0]}:{s[1]}" for s in sites)+"\n")

# Now: for each handler defined in same file, find lock acquisitions inside its body
def find_function_range(lines,name):
    # find definition line where name( appears at start-ish and followed by { possibly later
    pat=re.compile(r'\b'+re.escape(name)+r'\s*\(')
    for i,l in enumerate(lines):
        if pat.search(l) and not l.lstrip().startswith("//") and not l.lstrip().startswith("*"):
            # walk forward to find '{' then matching brace
            j=i;depth=0;started=False
            while j<len(lines) and j<i+400:
                if "{" in lines[j]: started=True
                if started:
                    depth+=lines[j].count("{")-lines[j].count("}")
                    if depth<=0 and started:
                        return i+1,j+1
                j+=1
    return None

results=[]
handler_missing=0
for h,sites in handler_site.items():
    files={s[0] for s in sites}
    for f in files:
        try: lines=open(f,errors="ignore").read().split("\n")
        except: continue
        rng=find_function_range(lines,h)
        if not rng:
            handler_missing+=1;continue
        s,e=rng
        body="\n".join(lines[s-1:e])
        locks=[]
        for m in re.finditer(r'\bspin_lock(?:_irqsave|_irq|_bh|_nested)?\s*\(([^;]{0,120})',body):
            locks.append((m.group(0),m.start()))
        if locks:
            results.append((f,h,s,e,[l for l,_ in locks],sites))

print("handlers with in-body spinlocks:",len(results),"defs-not-found:",handler_missing)
with open(os.path.join(TMP,"handler_locks.tsv"),"w") as out:
    for f,h,s,e,locks,sites in results:
        out.write(f"{f}\t{h}\t{s}\t{e}\t"+"|".join(locks).replace("\t"," ")+"\t"+";".join(f"{a}:{b}" for (a,b,_) in sites)+"\n")
