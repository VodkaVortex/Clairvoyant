import os, re, json, collections
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"
T=os.environ['TMPDIR']+'/i048'
regfiles=json.load(open(T+'/regfiles.json'))
reg_re = re.compile(r'\b(request_irq|request_threaded_irq|devm_request_irq|devm_request_threaded_irq|request_any_context_irq|request_percpu_irq)\s*\(')
call_re = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
lock_plain = re.compile(r'\bspin_lock\s*\(\s*&?\s*([^),]+?)\s*\)')
lock_plain_nested = re.compile(r'\bspin_lock_nested\s*\(')
lock_safe = re.compile(r'\bspin_lock(?:_nested)?_(?:irq|irqsave|bh|irqrestore)')

# pass 1: build function map per file: name -> (start,end)
# simple brace matcher
def functions(lines):
    out={}
    i=0; n=len(lines)
    # strip comments crudely for matching (keep for lock scan later separately)
    sig_re=re.compile(r'^\s*(?:static\s+|inline\s+|const\s+|__always_inline\s+|__maybe_unused\s+|noinline\s+)*[A-Za-z_][A-Za-z0-9_]*[\s\*]+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    while i<n:
        l=lines[i]
        m=sig_re.match(l)
        if m and '{' in l:
            name=m.group(1)
            depth=l.count('{')-l.count('}')
            j=i
            while j<n-1 and depth>0:
                j+=1
                depth+=lines[j].count('{')-lines[j].count('}')
            out[name]=(i+1, j+1)  # 1-based inclusive
            i=j+1
        else:
            i+=1
    return out

stats=collections.Counter()
rows=[]   # (file, lock, handler, regcall, regline, handler_line)
file_plain_locks={}  # file -> {lock: [ (line, funcname) ]}
handler_plain_locks={} # file -> {lock: [(line, handler)]}
reginfo={} # file -> [ (func, regcall, regline, handler) ]

for rel, regs in regfiles.items():
    p=os.path.join(ROOT,rel)
    lines=open(p,encoding='utf-8',errors='replace').read().splitlines()
    funcs=functions(lines)
    # handler names from registrations: parse args of the call across lines
    text='\n'.join(lines)
    # find each registration call and its first arg list
    reg_handlers=[]
    for ln, call in regs:
        # gather up to 12 lines from ln-1 for the call
        chunk='\n'.join(lines[ln-1:ln+11])
        # first arg (handler) is last arg before devname for request_irq; for threaded it's (dev, handler, thread_fn, flags,...)
        # heuristics: capture identifiers in args region
        # find matching paren
        start=chunk.find('(')
        depth=0; k=start; instr=False
        while k<len(chunk):
            c=chunk[k]
            if c=='(': depth+=1
            elif c==')':
                depth-=1
                if depth==0: break
            k+=1
        args=chunk[start:k+1] if depth==0 else chunk[start:]
        ids=re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?=[,\)\n])', args)
        # remove call name and known non-handler tokens
        skip={'request_irq','request_threaded_irq','devm_request_irq','devm_request_threaded_irq','request_any_context_irq','request_percpu_irq','devm','device','dev','IRQF_SHARED','IRQF_TRIGGER_RISING','IRQF_TRIGGER_FALLING','IRQF_TRIGGER_HIGH','IRQF_TRIGGER_LOW','NULL','GFP_KERNEL','irq','IRQ_NONE','IRQ_HANDLED','int','void'}
        cand=[x for x in ids if x not in skip and x not in call and (x.isupper()==False)][:6]
        reg_handlers.append((ln, call, cand))
    reginfo[rel]=reg_handlers

    # plain lock sites per file with enclosing function
    fpl={}
    lock_to_func=[]
    for i,l in enumerate(lines):
        if lock_plain.search(l) or lock_plain_nested.search(l):
            m=lock_plain.search(l)
            lock=m.group(1).strip() if m else None
            if lock is None: continue
            # find enclosing function
            fn=None
            for name,(s,e) in funcs.items():
                if s<=i+1<=e: fn=name; break
            lock_to_func.append((i+1, lock, fn))
            fpl.setdefault(lock, []).append((i+1, fn))
    file_plain_locks[rel]=fpl

    # handler-side plain locks
    hpl=collections.defaultdict(list)
    for ln, call, cand in reg_handlers:
        for h in cand:
            if h in funcs:
                s,e=funcs[h]
                for i in range(s-1, e):
                    m=lock_plain.search(lines[i])
                    if m and not lock_safe.search(lines[i]):
                        lock=m.group(1).strip()
                        hpl[lock].append((i+1, h, call, ln))
    if hpl:
        handler_plain_locks[rel]=dict(hpl)

json.dump({'file_plain_locks':file_plain_locks,'handler_plain_locks':handler_plain_locks,'reginfo':reginfo}, open(T+'/index.json','w'))
tot_handler_locks=sum(len(v) for v in handler_plain_locks.values())
print("files with handler-plain locks:", len(handler_plain_locks), "distinct handler-plain (file,lock) pairs:", tot_handler_locks)
