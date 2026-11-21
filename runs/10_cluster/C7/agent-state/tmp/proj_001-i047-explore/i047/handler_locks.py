import re, os, json, collections
S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
handlers = json.load(open(os.environ["TMPDIR"]+"/i047/handlers.json"))
by_file = collections.defaultdict(list)
for path,ln,hname,call in handlers:
    by_file[path].append((ln,hname,call))

func_start_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.M)
plain_lock_re = re.compile(r'\bspin_lock\s*\(\s*([^)&]+?)\s*\)')
irqsave_re = re.compile(r'\bspin_lock_(irqsave|irq|bh)\s*\(')

def find_func_body(text, name):
    # find definition: 'name(' at start of a line-ish, followed by {...} block
    for m in re.finditer(r'(?m)^[^\n]*?\b'+re.escape(name)+r'\s*\(', text):
        # ensure it looks like a definition: find matching ) then optional stuff then {
        i = text.find(')', m.end()-1)
        if i==-1: continue
        j = text.find('{', i)
        if j==-1 or j-i>200: continue
        # ensure no ';' between ) and { (would be a prototype/decl)
        if ';' in text[i:j]: continue
        depth=0
        for k in range(j, len(text)):
            if text[k]=='{': depth+=1
            elif text[k]=='}':
                depth-=1
                if depth==0:
                    return (text.count('\n',0,m.start())+1, text[j+1:k], k)
    return None

out=[]
notfound=0
for path, items in by_file.items():
    try:
        text=open(os.path.join(S,path),errors='replace').read()
    except OSError:
        continue
    for ln,hname,call in items:
        r=find_func_body(text,hname)
        if not r:
            notfound+=1
            continue
        defln, body, endoff = r
        baseln = defln
        locks=[]
        for m in plain_lock_re.finditer(body):
            l = baseln + body.count("\n",0,m.start())
            locks.append((l, m.group(1).strip()))
        if locks:
            out.append({"file":path,"regline":ln,"handler":hname,"call":call,
                        "defline":defln,"plain_locks":locks})
print("handlers-with-plain-locks",len(out),"defs-not-found",notfound)
json.dump(out, open(os.environ["TMPDIR"]+"/i047/handler_plain_locks.json","w"))
