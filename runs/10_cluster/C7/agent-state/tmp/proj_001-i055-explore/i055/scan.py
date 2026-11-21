import os, re, sys, json, collections

ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11"
DIRS=["drivers","net","sound","arch","fs"]
EXT=(".c",".h")

irqre = re.compile(r'\b(devm_)?request_irq\s*\(')
thre = re.compile(r'\b(devm_)?request_threaded_irq\s*\(')
# lock acquisition regex: capture variant and the argument expression
lockre = re.compile(r'\b(spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested|_bh_nested)?|raw_spin_lock(?:_irqsave|_irq|_bh)?)\s*\(\s*([^,;]+?)\s*[,)]')
# plain only
plainre = re.compile(r'\b(?:spin_lock|raw_spin_lock)\s*\(\s*([^,;]+?)\s*[,)]')

handler_def = {}   # handler name -> file of definition (in-file)
plain_handler_locks = []  # (file, handler, lock, line)
file_plain_locks = collections.defaultdict(list)  # file -> list of (line, lock)
file_all_locks = collections.defaultdict(list)    # file -> list of (line, lock, kind)

def handlers_in_args(args):
    # return candidate function-name tokens from the args (positional approach risky; collect identifiers used as args)
    # split at commas top-level
    parts=[]; depth=0; cur=""
    for ch in args:
        if ch in "(<": depth+=1
        elif ch in ")>": depth-=1
        if ch=="," and depth==0:
            parts.append(cur); cur=""
        else:
            cur+=ch
    parts.append(cur)
    names=[]
    for p in parts:
        for m in re.finditer(r'(?<![\w.>])([a-zA-Z_]\w{2,})\s*(?=\s*$|[,)&])', p.strip()):
            names.append(m.group(1))
    return names

files=[]
for d in DIRS:
    for dp,_,fns in os.walk(os.path.join(ROOT,d)):
        for fn in fns:
            if fn.endswith(EXT):
                files.append(os.path.join(dp,fn))
print("files scanned:", len(files), file=sys.stderr)

for path in files:
    rel=os.path.relpath(path,ROOT)
    try:
        src=open(path,encoding="utf-8",errors="replace").read()
    except Exception:
        continue
    lines=src.split("\n")
    # strip comments for analysis (keep offsets via same-length replacement)
    def strip_comments(s):
        out=[];i=0;n=len(s);mode=0
        while i<n:
            c=s[i]
            if mode==0:
                if c=='/' and i+1<n and s[i+1]=='/':
                    mode=1;i+=2;out.append('  ');continue
                if c=='/' and i+1<n and s[i+1]=='*':
                    mode=2;i+=2;out.append('  ');continue
                out.append(c);i+=1
            elif mode==1:
                if c=='\n': mode=0;out.append('\n')
                else: out.append(' ')
                i+=1
            else:
                if c=='*' and i+1<n and s[i+1]=='/':
                    mode=0;i+=2;out.append('  ');continue
                out.append('\n' if c=='\n' else ' ');i+=1
        return ''.join(out)
    sc=strip_comments(src)
    slines=sc.split("\n")
    # all lock acquisitions with kind
    for m in lockre.finditer(sc):
        ln=sc.count("\n",0,m.start())+1
        file_all_locks[rel].append((ln,m.group(1),m.group(2)))
        if m.group(1) in ("spin_lock","raw_spin_lock"):
            file_plain_locks[rel].append((ln,m.group(2)))
    # function definitions: simple brace matcher for name( ... ) { 
    defs={}
    for m in re.finditer(r'(?m)^(?:[A-Za-z_][\w\s\*,\(\)\[\]]*?)\b([a-zA-Z_]\w*)\s*\(([^;{)]*)\)\s*(?:[A-Za-z_][\w\s]*?)?\{', sc):
        name=m.group(1)
        if name in ("if","for","while","switch","sizeof","return"): continue
        defs.setdefault(name, (sc.count(chr(10),0,m.start())+1, m.end()))
    for name,(ln0,off) in defs.items():
        handler_def.setdefault(name, rel)
    # find request_irq calls and handler names
    for m in irqre.finditer(sc):
        # capture full call args
        i=m.end()-1; depth=0; start=i
        while i<len(sc):
            if sc[i]=='(': depth+=1
            elif sc[i]==')':
                depth-=1
                if depth==0: break
            i+=1
        args=sc[start+1:i]
        names=handlers_in_args(args)
        ln=sc.count("\n",0,m.start())+1
        for nm in names:
            if nm in defs:
                plain_handler_locks.append((rel,nm,ln))

# for handler defs with locks, we need the handler body lock usage: recompute per handler
result_handler_locks=[]
handler_bodies={}
# second pass: extract lock usage inside each registered handler's body
hcache={}
def get_body(rel, name):
    key=(rel,name)
    if key in hcache: return hcache[key]
    path=os.path.join(ROOT,rel)
    try: src=open(path,encoding="utf-8",errors="replace").read()
    except Exception: hcache[key]=None; return None
    # find def with brace matcher
    m=re.search(r'\b'+re.escape(name)+r'\s*\(', src)
    body=None
    while m:
        # ensure it's a definition: next non-space after matching paren is '{' and preceding char not '->' or '.' or alpha
        pre=src[max(0,m.start()-3):m.start()]
        if not re.search(r'(->|\.|\w)$', pre):
            i=m.end()-1;depth=0
            while i<len(src):
                if src[i]=='(':depth+=1
                elif src[i]==')':
                    depth-=1
                    if depth==0:break
                i+=1
            j=i+1
            while j<len(src) and src[j] in ' \t\n': j+=1
            if j<len(src) and src[j]=='{':
                # match braces
                d=0;k=j
                while k<len(src):
                    if src[k]=='{':d+=1
                    elif src[k]=='}':
                        d-=1
                        if d==0:break
                    k+=1
                body=(src.count("\n",0,m.start())+1, src[j:k+1])
                break
        nxt=re.search(r'\b'+re.escape(name)+r'\s*\(', src[m.end():])
        if nxt:
            class _M:
                def __init__(self,s,e): self._s=s; self._e=e
                def start(self): return self._s
                def end(self): return self._e
            m=_M(m.end()+nxt.start(), m.end()+nxt.end())
        else:
            m=None
    hcache[key]=body
    return body

# unique handler names from plain_handler_locks entries plus definitions found anywhere
reg_handlers={}
for rel,handler,ln in plain_handler_locks:
    reg_handlers.setdefault(handler,set()).add((rel,ln))

for handler,sites in reg_handlers.items():
    rel=handler_def.get(handler)
    if not rel: continue
    body=get_body(rel,handler)
    if not body: continue
    ln0,btxt=body
    for lm in lockre.finditer(btxt):
        kind=lm.group(1); lock=lm.group(2)
        bl=ln0+btxt.count("\n",0,lm.start())
        result_handler_locks.append((rel,handler,bl,kind,lock,[ (r,l) for r,l in sorted(sites)]))

json.dump({"handler_locks":result_handler_locks,
           "plain_locks":{k:v for k,v in file_plain_locks.items()},
           "all_locks":{k:v for k,v in file_all_locks.items()},
           "handler_def":handler_def},
          open(os.path.join(os.environ["TMPDIR"],"i055","scan.json"),"w"))
plain_only=[x for x in result_handler_locks if x[3] in ("spin_lock","raw_spin_lock")]
print("registered handlers with defs:",len(reg_handlers),"handler lock sites:",len(result_handler_locks),"plain handler locks:",len(plain_only), file=sys.stderr)
