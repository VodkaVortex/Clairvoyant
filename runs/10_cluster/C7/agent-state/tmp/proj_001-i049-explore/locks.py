import re, json, os, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"

def strip_comments(src):
    out=[]; i=0; n=len(src); mode=None
    while i<n:
        c=src[i]
        if mode is None:
            if c=='/' and i+1<n and src[i+1]=='/':
                mode='line'; i+=2; continue
            if c=='/' and i+1<n and src[i+1]=='*':
                mode='block'; i+=2; continue
            if c=='"':
                mode='str'; out.append(c); i+=1; continue
            out.append(c); i+=1
        elif mode=='line':
            if c=='\n': mode=None; out.append(c)
            i+=1
        elif mode=='block':
            if c=='*' and i+1<n and src[i+1]=='/':
                mode=None; i+=2; continue
            if c=='\n': out.append('\n')
            i+=1
        else:
            out.append(c)
            if c=='\\' and i+1<n: out.append(src[i+1]); i+=2; continue
            if c=='"': mode=None
            i+=1
    return ''.join(out)

funcs = {}   # file -> {name: (start_line, body_text)}
SPIN = re.compile(r"\bspin_(?:lock|lock_irq|lock_irqsave|lock_bh|unlock|unlock_irq|unlock_irqrestore|unlock_bh)\s*\(")
funcdef = re.compile(r"^[ \t]*(?:[A-Za-z_][\w\s\*,\(\)\[\]]*?)[ \t\*]([A-Za-z_]\w*)\s*\(([^;]*)\)\s*(?:\{|$)", re.M)

def parse_file(path):
    src = open(path, encoding='utf8', errors='replace').read()
    # record comment spans on ORIGINAL for line mapping: simpler: build stripped with same length via mask
    mask = strip_comments_keep_len(src)
    names = set()
    fdict = {}
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", mask):
        names.add(m.group(1))
    for m in funcdef.finditer(mask):
        nm = m.group(1)
        # find body
        i = mask.find('{', m.end()-1)
        if i < 0: continue
        depth=0; j=i
        while j < len(mask):
            if mask[j]=='{': depth+=1
            elif mask[j]=='}':
                depth-=1
                if depth==0: break
            j+=1
        body = mask[i:j+1]
        start_line = mask.count('\n',0,m.start())+1
        fdict[nm] = (start_line, body)
    return fdict

def strip_comments_keep_len(src):
    # replace comment content with spaces, keep quotes content
    out = list(src); i=0; n=len(src); mode=None
    while i<n:
        c=src[i]
        if mode is None:
            if c=='/' and i+1<n and src[i+1]=='/':
                mode='line'; out[i]=' '; out[i+1]=' '; i+=2; continue
            if c=='/' and i+1<n and src[i+1]=='*':
                mode='block'; out[i]=' '; out[i+1]=' '; i+=2; continue
            if c=='"': mode='str'; i+=1; continue
            i+=1
        elif mode=='line':
            if c=='\n': mode=None
            else: out[i]=' '
            i+=1
        elif mode=='block':
            if c=='*' and i+1<n and src[i+1]=='/':
                out[i]=' '; out[i+1]=' '; mode=None; i+=2; continue
            if c!='\n': out[i]=' '
            i+=1
        else:
            if c=='\\': i+=2; continue
            if c=='"': mode=None
            i+=1
    return ''.join(out)

def extract_locks(body, baseline):
    res=[]
    for m in re.finditer(r"spin_lock\s*\(\s*(.+?)\s*\)\s*;", body):
        expr=m.group(1)
        line = baseline + body.count('\n',0,m.start())
        res.append((line, expr))
    return res

def canonical(expr):
    e = expr.replace(' ','').replace('\n','')
    return e

regs = json.load(open("regs.json"))
by_file = {}
for path, line, fn, handler in regs:
    by_file.setdefault(path, []).append((line, fn, handler))

files = sorted(by_file.keys())
stats = {"parsed":0, "nohandler":0}
handler_locks = {}
for path in files:
    if not (path.endswith('.c')): 
        # allow headers
        pass
    try:
        fdict = parse_file(path)
    except Exception as ex:
        continue
    for (line, fn, handler) in by_file[path]:
        if not handler: stats["nohandler"]+=1; continue
        h = handler.strip()
        # normalize handler expression to plain identifier if possible
        ident = h
        mm = re.match(r"^([A-Za-z_]\w*)$", h)
        if not mm:
            # take last identifier of expression
            ids = re.findall(r"[A-Za-z_]\w*", h)
            ident = ids[-1] if ids else None
        if not ident:
            stats["nohandler"]+=1; continue
        if ident not in fdict:
            stats["nohandler"]+=1; continue
        start, body = fdict[ident]
        locks = extract_locks(body, start)
        if locks:
            handler_locks.setdefault(path, []).append({
                "handler": ident, "handler_line": start, "reg_line": line, "reg_fn": fn,
                "handler_expr": h, "locks": [(l, canonical(e)) for l,e in locks],
            })
        stats["parsed"]+=1

print(stats)
json.dump(handler_locks, open("handler_locks.json","w"))
# summary: count handlers with plain locks
n=0
for path, hs in handler_locks.items():
    for h in hs:
        if h["locks"]: n+=1
print("handlers with locks:", n, "files:", len(handler_locks))
