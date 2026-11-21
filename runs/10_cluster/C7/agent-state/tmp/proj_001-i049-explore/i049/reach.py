import os, re, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref2 import read_lines, clean_lines, LOCKRE, PLAIN, split_args
from findfun import find_functions, ROOT

OUT=os.path.join(os.environ.get("TMPDIR","/tmp"),"i049")
xref=json.load(open(os.path.join(OUT,"xref.json")))
plain=xref["plain"]

CALLRE_TMPL = r'\b%s\s*\('

def build(rel):
    raw=read_lines(rel)
    clean=clean_lines(raw)
    funcs=find_functions(raw)
    # in-file call edges
    edges={}
    for name,defs in funcs.items():
        parts=[]
        for d in defs:
            if isinstance(d, tuple) and len(d)==2 and isinstance(d[0], int):
                parts.append("\n".join(clean[d[0]-1:d[1]]))
            elif isinstance(d, list):
                for dd in d:
                    if isinstance(dd, tuple) and len(dd)==2 and isinstance(dd[0], int):
                        parts.append("\n".join(clean[dd[0]-1:dd[1]]))
        body="\n".join(parts)
        callees=set()
        for other in funcs:
            if other==name: continue
            if re.search(r'\b%s\s*\('%re.escape(other), body):
                callees.add(other)
        edges[name]=callees
    return raw, clean, funcs, edges

def reachable(edges, start):
    seen={start}; stack=[start]
    while stack:
        cur=stack.pop()
        for c in edges.get(cur,()):
            if c not in seen:
                seen.add(c); stack.append(c)
    return seen

def enclosing(funcs, ln):
    for name,defs in funcs.items():
        for (s,e) in defs:
            if s<=ln<=e: return name
    return None

out=[]
for rel, locks in sorted(plain.items()):
    raw,clean,funcs,edges=build(rel)
    for lock, sites_ in locks.items():
        hs=sorted(set(h for (h,reg,ln,fl) in sites_))
        reach=set()
        for h in hs:
            if h in funcs:
                reach |= reachable(edges,h)
        # non-handler acquisitions of same lock
        target=re.sub(r'\s+','',lock)
        others=[]
        for ln,t in enumerate(clean):
            for m in LOCKRE.finditer(t):
                arg=re.sub(r',\s*[A-Za-z_0-9&\.\->\s]+$','',m.group(2)).strip()
                if re.sub(r'\s+','',arg)!=target: continue
                fl=m.group(1)
                fn=enclosing(funcs,ln+1)
                if fn is None: continue
                if fn in hs: continue
                if fn in reach: continue   # called from handler -> same side
                others.append({"line":ln+1,"flavor":fl,"func":fn})
        if others:
            out.append({"file":rel,"lock":lock,
                        "handler_side":[{"handler":h,"regline":reg,"lockline":ln,"flavor":fl} for (h,reg,ln,fl) in sites_],
                        "handler_reach_n":len(reach),
                        "other_side":others})
json.dump(out, open(os.path.join(OUT,"candidates2.json"),"w"), indent=1)
print("candidate pairs (other-side functions NOT called from handler):",len(out))
for o in out:
    fl=set(x["flavor"] for x in o["other_side"])
    print("%-58s %-26s h=%s(%s) others=%d %s" % (o["file"][:58], o["lock"][:26], o["handler_side"][0]["handler"][:24], o["handler_side"][0]["flavor"], len(o["other_side"]), sorted(fl)))
