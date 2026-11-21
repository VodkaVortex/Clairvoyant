import os,re,subprocess
TMP=os.path.join(os.environ["TMPDIR"],"i048")
# Read full registrations with multi-line join (up to 6 lines) so handler arg resolves
reg_re=re.compile(r'\b(devm_)?request(_threaded)?_irq\s*\(')
idx_map={("request_irq",0):1,("request_irq",1):2,("request_threaded_irq",0):1,("request_threaded_irq",1):2}
regs=[]
filecache={}
def getlines(f):
    if f not in filecache:
        try: filecache[f]=open(f,errors="ignore").read().split("\n")
        except: filecache[f]=[]
    return filecache[f]

subprocess_args=["/usr/bin/grep","-rl","request_irq","--include=*.c"]
files=subprocess.run(subprocess_args,capture_output=True,text=True).stdout.split()
files=[f for f in files if not f.startswith("./Documentation") and not f.startswith("./tools")]
nreg=0
for f in files:
    lines=getlines(f)
    for i,l in enumerate(lines):
        m=reg_re.search(l)
        if not m: continue
        s=l.lstrip()
        if s.startswith("#") or s.startswith("*") or s.startswith("/*") or s.startswith("//"): continue
        key=("request"+("_threaded" if m.group(2) else "")+"_irq",1 if m.group(1) else 0)
        if key[0]=="request_irq" and "fd_request" in l: continue
        idx=idx_map[key]
        # join up to 8 lines until parens balance
        text=l; j=i; depth=0; done=False
        seg=l
        while j<len(lines) and j<i+8:
            seg=lines[j] if j>i else l
            text=("\n".join(lines[i:j+1]))
            depth=text.count("(")-text.count(")")
            # stop when the call closes and we have a semicolon or the closing at end
            if depth<=0:
                break
            j+=1
        inner_start=text.find("(")
        # extract args of the FIRST request* call occurrence properly
        # find position of the matched call
        pos=m.start()
        # walk chars from m.end()-1 (the paren)
        k=m.end()-1
        depth=0;args=[];cur=""
        src=text  # includes only joined region; char offsets relative to text with newlines
        while k<len(src):
            ch=src[k]
            if ch=="(":
                depth+=1
                if depth==1: k+=1; continue
            elif ch==")":
                depth-=1
                if depth==0:
                    args.append(cur.strip());break
            elif ch=="," and depth==1:
                args.append(cur.strip());cur=""
                k+=1;continue
            if depth>=1: cur+=ch
            k+=1
        line_of_call=i+1
        if len(args)>idx:
            h=re.sub(r'\s+','',args[idx])
            regs.append((f,line_of_call,key[0],h,"\n".join(lines[i:min(j+1,i+8)])))
            nreg+=1
        else:
            regs.append((f,line_of_call,key[0],"?","\n".join(lines[i:min(j+1,i+8)])))
print("regs parsed:",nreg)
uniq={}
for f,ln,kind,h,txt in regs:
    if not re.fullmatch(r'&?[A-Za-z_][A-Za-z0-9_]*',h): continue
    uniq.setdefault(h.lstrip("&"),set()).add(f)
print("handler names:",len(uniq))
with open(os.path.join(TMP,"handlers.txt"),"w") as fh:
    for h in sorted(uniq):
        fh.write(h+"\t"+";".join(sorted(uniq[h]))+"\n")
with open(os.path.join(TMP,"regs2.tsv"),"w") as out:
    for f,ln,kind,h,txt in regs:
        out.write(f"{f}\t{ln}\t{kind}\t{h}\n")
