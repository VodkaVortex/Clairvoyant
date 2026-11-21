import re, os, json, collections
S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
sites = []
for line in open(os.environ["TMPDIR"]+"/i047/irq_sites.tsv"):
    line=line.rstrip("\n")
    parts=line.split(":",2)
    if len(parts)<3: continue
    path,ln,rest=parts
    sites.append((path,int(ln),rest.strip()))
print("sites",len(sites),"files",len(set(s[0] for s in sites)))

# For each file with a registration, resolve the handler identifier and find the handler function def.
callre = re.compile(r'\b(devm_)?request_(threaded_)?(any_context_)?(percpu_)?(irq)\s*\(')
def parse_args(text, start):
    # start at index of '('
    depth=0; i=start
    while i < len(text):
        c=text[i]
        if c=='(': depth+=1
        elif c==')':
            depth-=1
            if depth==0: return text[start+1:i]
        i+=1
    return None
def split_args(argstr):
    args=[]; depth=0; cur=''
    for c in argstr:
        if c in '([': depth+=1
        elif c in ')]': depth-=1
        elif c==',' and depth==0:
            args.append(cur.strip()); cur=''
            continue
        cur+=c
    args.append(cur.strip())
    return args

# handler lock map: file -> handler name -> list of (line, lockexpr)
plain_lock_re = re.compile(r'\bspin_lock\s*\(\s*([^)&]+?)\s*\)')
results=[]
handler_defs={}  # file -> {handlername: (defline, endline)}
funcdef_re = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{', re.M)

lockname_cache={}
def extract_locks(path, body, baseln):
    out=[]
    for m in plain_lock_re.finditer(body):
        ln = baseln + body.count("\n",0,m.start())
        out.append((ln, m.group(1).strip()))
    return out

unresolved=0
for path,ln,rest in sites:
    try:
        text=open(os.path.join(S,path),errors='replace').read()
    except OSError:
        continue
    # find the call on this line
    m=callre.search(rest)
    if not m: 
        # registration may be split across lines; join next 5 lines
        lines=text.split('\n')
        seg='\n'.join(lines[ln-1:ln+6])
        m=callre.search(seg)
        if not m:
            unresolved+=1; continue
        call=m
        start=text.find(seg[:40])
        # safer: find call position near line ln
        idx=0
        for i,l in enumerate(lines):
            if i>=ln-1: 
                idx=sum(len(x)+1 for x in lines[:i]); break
        call=None
        for cm in callre.finditer(text, idx, idx+1200):
            call=cm; break
        if not call: unresolved+=1; continue
    else:
        # locate in full text
        # find first occurrence of rest's prefix in text near that line
        lines=text.split('\n')
        idx=sum(len(x)+1 for x in lines[:ln-1])
        call=None
        for cm in callre.finditer(text, idx, idx+1200):
            call=cm; break
        if not call: unresolved+=1; continue
    argstr=parse_args(text, call.end()-1)
    if not argstr: unresolved+=1; continue
    args=split_args(argstr)
    handler=None
    if 'threaded' in call.group(0):
        # request_threaded_irq(irq, handler, thread_fn, ...)
        if len(args)>=2 and args[1] not in ('NULL','0',''): handler=args[1]
    elif 'any_context' in call.group(0) or 'percpu' in call.group(0):
        if len(args)>=2: handler=args[1]
    else:
        # request_irq(irq, handler, ...)
        if len(args)>=2: handler=args[1]
    if not handler: 
        # threaded with NULL primary -> thread only, skip
        continue
    handler=handler.strip()
    hname=handler.split('=')[-1].strip()
    # strip casts/paren
    hname=re.sub(r'\(.*?\)\s*','',hname).strip()
    hname=hname.replace('&','').strip()
    results.append((path,ln,hname,call.group(0).strip()))

print("parsed handlers",len(results),"unresolved",unresolved)
json.dump(results, open(os.environ["TMPDIR"]+"/i047/handlers.json","w"))
