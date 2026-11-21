import subprocess, re, os
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"
def run(cmd):
    return subprocess.run(cmd,shell=True,capture_output=True,text=True,cwd=ROOT).stdout

files = run("grep -rln --include=*.c 'tasklet_init' drivers net sound block").split()
report=[]
for f in files:
    src=open(os.path.join(ROOT,f),errors='ignore').read()
    lines=src.split('\n')
    # plain spin_lock lines
    plain=[]
    for i,l in enumerate(lines,1):
        if re.search(r'(?<![a-z_])spin_lock\s*\(', l) or 'spin_lock_nested' in l:
            plain.append(i)
    if not plain: continue
    cbs = re.findall(r'tasklet_init\s*\(\s*&?[\w\->\.]+,\s*(\w+)', src)
    cbs += re.findall(r'tasklet_setup\s*\(\s*&?[\w\->\.]+,\s*(\w+)', src)
    cbs += [m for m in re.findall(r'DECLARE_TASKLET\s*\(\s*\w+\s*,\s*(\w+)', src)]
    if not cbs: continue
    # extract body of each cb
    def body(name):
        m=re.search(r'\b\w[\w\s\*]*?\b'+re.escape(name)+r'\s*\(', src)
        if not m: return ""
        st=src.find('{', m.end())
        if st<0: return ""
        d=0
        for k in range(st,len(src)):
            if src[k]=='{':d+=1
            elif src[k]=='}':
                d-=1
                if d==0: return src[st:k+1]
        return ""
    cblocks={c:body(c) for c in set(cbs)}
    cb_plain_locks=set()
    for c,b in cblocks.items():
        for m in re.finditer(r'spin_lock(?:_nested)?\s*\(\s*([^;]+?)\s*\)', b):
            cb_plain_locks.add(m.group(1).strip().rstrip(',').split(',')[0])
    if not cb_plain_locks: continue
    # candidate lock names: base identifiers of cb plain locks
    base=set()
    for lk in cb_plain_locks:
        base |= set(re.findall(r'[A-Za-z_]\w*', lk))
    # plain sites in file whose lock expr shares base tokens with cb locks and are NOT inside any cb body
    hits=[]
    for ln in plain:
        expr=None
        for i in range(ln, 0, -1):
            m=re.search(r'spin_lock(?:_nested)?\s*\(\s*([^;]+?)\s*\)', lines[i-1])
            if m:
                expr=m.group(1); break
        if expr is None: continue
        # skip if inside a cb body line range
        inside=False
        for c,b in cblocks.items():
            # find start line of cb def
            m=re.search(r'\b'+re.escape(c)+r'\s*\(', src)
            if m:
                startline=src[:m.start()].count('\n')+1
                if startline<=ln<=startline+b.count('\n')+2:
                    inside=True;break
        if inside: continue
        toks=set(re.findall(r'[A-Za-z_]\w*', expr))
        if toks & base:
            hits.append((ln,expr))
    if hits:
        report.append((f,sorted(cb_plain_locks),hits))
for f,locks,hits in report:
    print(f)
    print("  cb plain locks:",sorted(locks))
    for ln,e in hits: print(f"   noncb plain: {ln}: {e}")
