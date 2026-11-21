import os, re, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref2 import read_lines, clean_lines, LOCKRE, PLAIN, split_args, REQ
from findfun import find_functions, ROOT

OUT=os.path.join(os.environ.get("TMPDIR","/tmp"),"i049")
xref=json.load(open(os.path.join(OUT,"xref.json")))
plain=xref["plain"]

def norm(lock):
    # canonical: remove spaces
    return re.sub(r'\s+','',lock)

def lock_uses(clean, lockname):
    """find all spin_lock-family uses of this lock expression (any flavor) in file, with line + flavor"""
    uses=[]
    target=norm(lockname)
    for ln,t in enumerate(clean):
        for m in LOCKRE.finditer(t):
            arg=re.sub(r',\s*[A-Za-z_0-9&\.\->\s]+$','',m.group(2)).strip()
            if norm(arg)==target:
                uses.append((ln+1,m.group(1),m.group(2).strip()))
    return uses

rows=[]
for rel, locks in plain.items():
    raw=read_lines(rel)
    clean=clean_lines(raw)
    funcs=find_functions(raw)
    # map line -> enclosing function name
    line2fun={}
    for name,defs in funcs.items():
        for (s,e) in defs:
            for ln in range(s,e+1):
                line2fun.setdefault(ln,name)
    for lock, sites_ in locks.items():
        uses=lock_uses(clean,lock)
        for (ln,fl,arg) in uses:
            fn=line2fun.get(ln,"?")
            rows.append({"file":rel,"lock":lock,"line":ln,"flavor":fl,"func":fn,
                         "handler_site":sites_})
json.dump(rows, open(os.path.join(OUT,"all_uses.json"),"w"), indent=1)
print("total non-handler uses of handler-taken locks:", len(rows))
# now rank files where a lock has BOTH a handler-side ENABLING acquisition AND non-handler-side plain acquisition
from collections import defaultdict
cand=defaultdict(list)
for r in rows:
    hs={h for (h,reg,ln,fl) in r["handler_site"]}
    if r["func"] in hs: continue   # use is inside the handler itself
    if r["flavor"] in PLAIN:       # plain or bh (no hard-irq disable)
        cand[(r["file"],r["lock"])].append(r)
print("candidate (file,lock) pairs:",len(cand))
out=[]
for (f,l),rs in sorted(cand.items()):
    hsites=[(h,reg,ln,fl) for (h,reg,ln,fl) in rs[0]["handler_site"]]
    out.append({"file":f,"lock":l,"handler_side":hsites,"nonirq_side":[{k:r[k] for k in ("line","flavor","func")} for r in rs]})
json.dump(out, open(os.path.join(OUT,"candidates.json"),"w"), indent=1)
for o in out:
    print(o["file"], "|", o["lock"], "| handler:", o["handler_side"][0][0], "line", o["handler_side"][0][2], o["handler_side"][0][3], "| nonirq:", [(r["func"],r["line"],r["flavor"]) for r in o["nonirq_side"]][:6])
