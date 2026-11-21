import os,re
TMP=os.path.join(os.environ["TMPDIR"],"i048")
spin_re=re.compile(r'\bspin_lock\s*\(')
spin_irqsave_re=re.compile(r'\bspin_lock_irqsave\s*\(')
lockcall_re=re.compile(r'\bspin_lock(?:_irqsave|_irq|_bh|_nested)?\s*\(\s*([^,;)]{1,100})')
locknames={}
def lockname(arg):
    return re.sub(r'\s+','',arg)

# handler -> files
handlers=[]
for line in open(os.path.join(TMP,"handlers.txt")):
    parts=line.rstrip("\n").split("\t")
    if len(parts)<2: continue
    h,fs=parts[0],parts[1].split(";")
    if h=="NULL" or not h: continue
    handlers.append((h,fs))

def find_def(lines,name):
    """return (start,end) 1-based of function definition body containing name( ... ) { ... }"""
    # definition pattern: name at start of a "word" followed by ( and not preceded by . -> etc
    pat=re.compile(r'(?<![\w.>])(?:static\s+)?[A-Za-z_][\w\s\*&]*?\b'+re.escape(name)+r'\s*\(')
    for i,l in enumerate(lines):
        if name+"(" not in l.replace(" ","").replace("\t",""): 
            continue
        if l.lstrip().startswith("//") or l.lstrip().startswith("*") or l.lstrip().startswith("#"): continue
        if re.search(r'\b'+re.escape(name)+r'\s*\(\s*\)\s*;?',l): continue # macro or prototype
        # heuristic: candidate def line
        j=i;depth=0;started=False
        while j<len(lines) and j<i+600:
            for ch in lines[j]:
                if ch=="{":
                    depth+=1;started=True
                elif ch=="}":
                    depth-=1
            if started and depth<=0:
                return (i+1,j+1)
            # if we hit a ';' at depth 0 before '{', it's a prototype/decl -> skip
            if not started and ";" in lines[j] and j>i:
                break
            if not started and ";" in lines[j] and j==i and re.search(name+r'\s*\([^)]*\)\s*;',lines[j]):
                break
            j+=1
    return None

out=open(os.path.join(TMP,"handler_locks.tsv"),"w")
found=0;notfound=0;withlocks=0
for h,fs in handlers:
    for f in fs:
        try: lines=open(f,errors="ignore").read().split("\n")
        except: continue
        rng=find_def(lines,h)
        if not rng:
            notfound+=1;continue
        found+=1
        s,e=rng
        body_lines=lines[s-1:e]
        locks=[]
        for k,bl in enumerate(body_lines):
            for m in lockcall_re.finditer(bl):
                locks.append((s+k,m.group(1).strip(), "irqsave" if "irqsave" in m.group(0) else ("plain" if re.match(r'\bspin_lock\s*\(',bl) else "other")))
        if locks:
            withlocks+=1
            for ln,lnm,kind in locks:
                # re-derive kind precisely from the line
                bl=lines[ln-1]
                if re.search(r'\bspin_lock\s*\(',bl): kind="plain"
                elif re.search(r'\bspin_lock_irqsave\s*\(',bl): kind="irqsave"
                elif re.search(r'\bspin_lock_irq\s*\(',bl): kind="irq"
                elif re.search(r'\bspin_lock_bh\s*\(',bl): kind="bh"
                else: kind="other"
                out.write(f"{f}\t{h}\t{ln}\t{kind}\t{lnm}\n")
out.close()
print("defs found",found,"notfound",notfound,"handlers-with-locks",withlocks)
