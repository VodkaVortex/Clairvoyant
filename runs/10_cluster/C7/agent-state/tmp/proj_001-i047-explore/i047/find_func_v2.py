import re, os, json, collections
S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
handlers = json.load(open(os.environ["TMPDIR"]+"/i047/handlers.json"))
by_file = collections.defaultdict(list)
for path,ln,hname,call in handlers:
    by_file[path].append((ln,hname,call))
plain_lock_re = re.compile(r'\bspin_lock\s*\(\s*([^)&]+?)\s*\)')

def find_func_body(text, name):
    # any occurrence of name( ... ) { ... } - allow leading whitespace/static etc.
    pat = re.compile(r'\b'+re.escape(name)+r'\s*\(')
    for m in pat.finditer(text):
        # must not be preceded by -> or . or & (call vs def is hard; just try all)
        prev = text[max(0,m.start()-2):m.start()]
        if prev.endswith('->') or prev.endswith('.') or prev.endswith('&'): continue
        i = m.end()-1
        depth=0
        # skip to matching close paren
        k=i
        while k < len(text):
            if text[k]=='(': depth+=1
            elif text[k]==')':
                depth-=1
                if depth==0: break
            k+=1
        if k>=len(text): continue
        j = text.find('{', k)
        if j==-1 or j-k>300: continue
        if ';' in text[k:j]: continue
        depth=0
        for e in range(j, min(len(text), j+60000)):
            if text[e]=='{': depth+=1
            elif text[e]=='}':
                depth-=1
                if depth==0:
                    return (text.count('\n',0,m.start())+1, text[j+1:e], e)
    return None

out=[]
notfound_names=collections.Counter()
for path, items in by_file.items():
    try:
        text=open(os.path.join(S,path),errors='replace').read()
    except OSError:
        continue
    for ln,hname,call in items:
        r=find_func_body(text,hname)
        if not r:
            notfound_names[hname]+=1
            continue
        defln, body, endoff = r
        locks=[]
        for m in plain_lock_re.finditer(body):
            l = defln + body.count("\n",0,m.start())
            locks.append((l, m.group(1).strip()))
        if locks:
            out.append({"file":path,"regline":ln,"handler":hname,"call":call,
                        "defline":defln,"plain_locks":locks})
print("handlers-with-plain-locks",len(out),"defs-not-found",sum(notfound_names.values()))
json.dump(out, open(os.environ["TMPDIR"]+"/i047/handler_plain_locks.json","w"))
json.dump(dict(notfound_names), open(os.environ["TMPDIR"]+"/i047/notfound.json","w"))
