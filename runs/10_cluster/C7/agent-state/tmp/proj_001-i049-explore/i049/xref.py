import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"
OUT  = os.path.join(os.environ.get("TMPDIR","/tmp"),"i049")
REQ  = re.compile(r'\b(devm_)?request(_threaded)?_irq(_wr)?\s*\(')

LOCKRE = re.compile(r'\b(spin_(?:try)?lock(?:_irqsave(?:_nested)?|_irq|_bh(?:_nested)?|_nested)?|read_lock(?:_irqsave|_irq|_bh)?|write_lock(?:_irqsave|_irq|_bh)?|raw_spin_(?:try)?lock(?:_irqsave|_irq|_bh)?|local_irq_save|local_irq_disable|local_bh_disable)\s*\(([^;{]*?)\)\s*;')

PLAIN = {"spin_lock","spin_trylock","spin_lock_nested","spin_lock_bh","spin_lock_bh_nested","spin_trylock_bh",
         "read_lock","read_lock_bh","write_lock","write_lock_bh","raw_spin_lock","raw_spin_lock_bh","local_bh_disable"}

def read_lines(rel):
    with open(os.path.join(ROOT, rel), errors="replace") as fh:
        return fh.read().split("\n")

def strip_code(line):
    # remove line comments; keep block comments handled by caller
    if "//" in line: line=line.split("//")[0]
    return line

def c_files():
    for dp,dn,fn in os.walk(ROOT):
        if "/.git" in dp: continue
        for f in fn:
            if f.endswith(".c"):
                yield os.path.relpath(os.path.join(dp,f), ROOT)

def find_functions(lines):
    """dict name -> (start_line, end_line) 1-based body inclusive; brace matching w/ comment+string awareness."""
    funcs={}
    i=0; n=len(lines)
    while i<n:
        t=strip_code(lines[i])
        # candidate def: identifier(...) with ')' then optional stuff then '{' on same or following lines
        m=re.match(r'^([A-Za-z_][\w]*)\s*\(', t)
        if not m:
            i+=1; continue
        name=m.group(1)
        if name in ("if","for","while","switch","return","sizeof","defined","else","do"):
            i+=1; continue
        # find opening brace within next 10 lines
        j=i; depth=0; brace_line=None
        while j<min(i+12,n):
            tt=strip_code(lines[j])
            if ";" in tt:
                break
            if "{" in tt:
                brace_line=j; depth=tt.count("{")-tt.count("}"); break
            if ")" in tt and j>i:
                # closing paren then newline; continue
                pass
            j+=1
        if brace_line is None:
            i+=1; continue
        # brace matching from brace_line, tracking comments and strings
        in_block=False; in_str=None; k=brace_line; col=0; started=False
        while k<n:
            raw=lines[k]
            p=0
            while p<len(raw):
                ch=raw[p]
                if in_block:
                    if ch=="*" and p+1<len(raw) and raw[p+1]=="/":
                        in_block=False; p+=1
                    p+=1; continue
                if in_str:
                    if ch=="\\": p+=2; continue
                    if ch==in_str: in_str=None
                    p+=1; continue
                if ch=="/" and p+1<len(raw) and raw[p+1]=="*":
                    in_block=True; p+=2; continue
                if ch=="/" and p+1<len(raw) and raw[p+1]=="/":
                    break
                if ch=='"' : in_str='"'; p+=1; continue
                if ch=="'": in_str="'"; p+=1; continue
                if ch=="{":
                    depth+=1; started=True
                elif ch=="}":
                    depth-=1
                    if started and depth<=0:
                        funcs.setdefault(name,[]).append((i+1,k+1))
                        break
                p+=1
            if in_block or in_str or (started and depth>0 and k==n-1):
                pass
            k+=1
            if started and depth<=0:
                break
        i=k if k>i else i+1
    return funcs

def lock_entries(lines, s, e):
    out=[]
    in_block=False
    for ln in range(s-1, e):
        t=lines[ln]
        if in_block:
            if "*/" in t: in_block=False; t=t.split("*/",1)[1]
            else: continue
        if "/*" in t and "*/" not in t.split("/*",1)[1]:
            in_block=True; t=t.split("/*")[0]
        for m in LOCKRE.finditer(t):
            out.append((ln+1, m.group(1), m.group(2).strip()))
    return out

def split_args(args):
    parts=[]; dep=0; cur=""; p=0; in_str=None
    while p<len(args):
        ch=args[p]
        if in_str:
            if ch=="\\": cur+=args[p:p+2]; p+=2; continue
            if ch==in_str: in_str=None
            cur+=ch; p+=1; continue
        if ch=='"' or ch=="'": in_str=ch; cur+=ch; p+=1; continue
        if ch in "([{": dep+=1
        elif ch in ")]}":
            if dep==0: break
            dep-=1
        if ch=="," and dep==0:
            parts.append(cur.strip()); cur=""
        else:
            cur+=ch
        p+=1
    if cur.strip(): parts.append(cur.strip())
    return parts

def handler_sites():
    res={}
    for rel in c_files():
        try: lines=read_lines(rel)
        except: continue
        buf=None
        for i,t in enumerate(lines):
            if REQ.search(t):
                # gather the full call text until ");" 
                txt=t[REQ.search(t).start():]
                j=i
                while ");" not in txt and j+1<min(i+15,len(lines)):
                    j+=1; txt+=" "+lines[j]
                m=re.search(r'(devm_)?request(_threaded)?_irq(_wr)?\s*\((.*)\);', txt)
                if not m: continue
                args=split_args(m.group(4))
                names=[]
                threaded = m.group(2)=="_threaded"
                for idx, a in enumerate(args[:4]):
                    if re.fullmatch(r'[A-Za-z_]\w*', a):
                        if idx==1: names.append(a)
                        elif idx==2 and threaded: names.append(a)
                for hn in names:
                    res.setdefault(rel,[]).append((hn, i+1))
    return res

def main():
    sites=handler_sites()
    print("files with irq registrations w/ named handler:", len(sites))
    handlers={}   # rel -> list entries
    plain={}      # rel -> lock -> list of (handler, regline, lockline, flavor)
    unresolved={}
    for rel, hs in sorted(sites.items()):
        try: lines=read_lines(rel)
        except: continue
        funcs=find_functions(lines)
        entries=[]
        for hname, regline in hs:
            defs=funcs.get(hname)
            if not defs:
                unresolved.setdefault(rel,[]).append(hname); continue
            defline,end = defs[0]
            for (ln, fl, arg) in lock_entries(lines, defline, end):
                entries.append((hname, regline, ln, fl, arg))
        if entries:
            handlers[rel]=entries
            for (h, reg, ln, fl, arg) in entries:
                lock=re.sub(r',\s*[A-Za-z_0-9&->.\s]+$', '', arg).strip()
                if fl in PLAIN:
                    plain.setdefault(rel,{}).setdefault(lock,[]).append((h,reg,ln,fl))
    with open(os.path.join(OUT,"xref.json"),"w") as fh:
        json.dump({"handlers":handlers,"plain":plain,"unresolved":unresolved}, fh, indent=1)
    print("files w/ handler lock entries:", len(handlers))
    print("files w/ PLAIN handler locks:", len(plain))
    total=sum(len(v) for v in plain.values())
    print("distinct (file,lock) plain:", total)

if __name__=="__main__":
    main()
