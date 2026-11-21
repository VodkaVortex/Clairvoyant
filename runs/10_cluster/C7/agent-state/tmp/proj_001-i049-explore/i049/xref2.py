import os, re, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from findfun import find_functions, ROOT

OUT=os.path.join(os.environ.get("TMPDIR","/tmp"),"i049")
REQ=re.compile(r'\b(devm_)?request(_threaded)?_irq(_wr)?\s*\(')
LOCKRE=re.compile(r'\b(spin_(?:try)?lock(?:_irqsave(?:_nested)?|_irq|_bh(?:_nested)?|_nested)?|read_lock(?:_irqsave|_irq|_bh)?|write_lock(?:_irqsave|_irq|_bh)?|raw_spin_(?:try)?lock(?:_irqsave|_irq|_bh)?|local_irq_save|local_irq_disable|local_bh_disable)\s*\(([^;{]*?)\)\s*;')
UNLOCKRE=re.compile(r'\b(spin_unlock|read_unlock|write_unlock|raw_spin_unlock|local_irq_restore|local_irq_enable|local_bh_enable)')
PLAIN={"spin_lock","spin_trylock","spin_lock_nested","spin_lock_bh","spin_lock_bh_nested","spin_trylock_bh",
       "read_lock","read_lock_bh","write_lock","write_lock_bh","raw_spin_lock","raw_spin_lock_bh","local_bh_disable"}
# flavors that leave hard IRQs enabled:
ENABLING=PLAIN  # plain and _bh keep hard IRQs enabled

def read_lines(rel):
    with open(os.path.join(ROOT,rel),errors="replace") as fh: return fh.read().split("\n")

def c_files():
    for dp,dn,fn in os.walk(ROOT):
        if "/.git" in dp: continue
        for f in fn:
            if f.endswith(".c"): yield os.path.relpath(os.path.join(dp,f), ROOT)

def strip_comments_code(t, state):
    # state: None | 'block'
    out=[]
    p=0
    while p<len(t):
        if state=="block":
            i=t.find("*/",p)
            if i<0: return "".join(out), "block"
            p=i+2; state=None; continue
        i=t.find("/*",p)
        j=t.find("//",p)
        if i>=0 and (j<0 or i<j):
            out.append(t[p:i]); state="block"; p=i+2; continue
        if j>=0:
            out.append(t[p:j]); return "".join(out), state
        out.append(t[p:]); return "".join(out), state
    return "".join(out), state

def clean_lines(lines):
    res=[]; state=None
    for t in lines:
        c,state=strip_comments_code(t,state)
        res.append(c)
    return res

def lock_entries(lines, s, e):
    out=[]
    for ln in range(s-1,e):
        t=lines[ln]
        for m in LOCKRE.finditer(t):
            out.append((ln+1,m.group(1),m.group(2).strip()))
    return out

def split_args(args):
    parts=[];dep=0;cur="";p=0;in_str=None
    while p<len(args):
        ch=args[p]
        if in_str:
            if ch=="\\": cur+=args[p:p+2]; p+=2; continue
            if ch==in_str: in_str=None
            cur+=ch;p+=1;continue
        if ch=='"' or ch=="'": in_str=ch;cur+=ch;p+=1;continue
        if ch in "([{": dep+=1
        elif ch in ")]}":
            if dep==0: break
            dep-=1
        if ch=="," and dep==0: parts.append(cur.strip());cur=""
        else: cur+=ch
        p+=1
    if cur.strip(): parts.append(cur.strip())
    return parts

def handler_sites():
    res={}
    for rel in c_files():
        try: raw=read_lines(rel)
        except: continue
        clean=clean_lines(raw)
        for i,t in enumerate(clean):
            m=REQ.search(t)
            if not m: continue
            txt=t[m.start():]; j=i
            while ");" not in txt and j+1<min(i+15,len(clean)):
                j+=1; txt+=" "+clean[j]
            mm=re.search(r'(devm_)?request(_threaded)?_irq(_wr)?\s*\((.*)\);',txt)
            if not mm: continue
            args=split_args(mm.group(4)); names=[]
            threaded=mm.group(2)=="_threaded"
            for idx,a in enumerate(args[:4]):
                if re.fullmatch(r'[A-Za-z_]\w*',a):
                    if idx==1: names.append(a)
                    elif idx==2 and threaded: names.append(a)
            for hn in names:
                res.setdefault(rel,[]).append((hn,i+1))
    return res

def main():
    sites=handler_sites()
    print("files w/ named-handler registrations:",len(sites))
    handlers={}; plain={}; unresolved={}
    for rel,hs in sorted(sites.items()):
        try: raw=read_lines(rel)
        except: continue
        clean=clean_lines(raw)
        funcs=find_functions(raw)
        entries=[]
        for hname,regline in hs:
            defs=funcs.get(hname)
            if not defs:
                unresolved.setdefault(rel,[]).append(hname); continue
            defline,end=defs[0]
            for (ln,fl,arg) in lock_entries(clean,defline,end):
                entries.append((hname,regline,ln,fl,arg))
        if entries:
            handlers[rel]=entries
            for (h,reg,ln,fl,arg) in entries:
                lock=re.sub(r',\s*[A-Za-z_0-9&\.\->\s]+$','',arg).strip()
                if fl in ENABLING:
                    plain.setdefault(rel,{}).setdefault(lock,[]).append((h,reg,ln,fl))
    with open(os.path.join(OUT,"xref.json"),"w") as fh:
        json.dump({"handlers":handlers,"plain":plain,"unresolved":unresolved},fh,indent=1)
    print("files w/ handler lock entries:",len(handlers))
    print("files w/ ENABLING handler locks:",len(plain))
    print("distinct (file,lock):",sum(len(v) for v in plain.values()))

if __name__=="__main__": main()
