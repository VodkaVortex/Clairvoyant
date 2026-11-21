import os, re, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"
TMP = os.environ.get('TMPDIR','/tmp')
handlers = json.load(open(TMP+'/handlers.json'))

def find_funcs(txt):
    # return list of (start, end, name) of function bodies
    funcs = []
    for m in re.finditer(r'^[A-Za-z_][A-Za-z0-9_ \t\*,\(\)]*?([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{', txt, re.M):
        name = m.group(1)
        # find matching brace
        i = m.end()-1
        depth = 0; j = i; n=len(txt)
        while j < n:
            c = txt[j]
            if c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0: break
            elif c == '"' or c == "'":
                q=c; j+=1
                while j<n and txt[j]!=q:
                    if txt[j]=='\\': j+=1
                    j+=1
            j += 1
        funcs.append((m.start(), j, name))
    return funcs

def extract_braced(txt, start):
    depth=0; i=start; n=len(txt)
    while i<n:
        c=txt[i]
        if c=='{': depth+=1
        elif c=='}':
            depth-=1
            if depth==0: return txt[start:i+1]
        elif c in '"\'':
            q=c; i+=1
            while i<n and txt[i]!=q:
                if txt[i]=='\\': i+=1
                i+=1
        i+=1
    return None

def find_handler_spans(txt, name):
    spans=[]
    for m in re.finditer(r'(?<![\w.>])(?:static\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\**\s*' + re.escape(name) + r'\s*\(', txt):
        j=m.start()-1
        while j>=0 and txt[j] in ' \t\n': j-=1
        if j>=0 and txt[j] not in ';}{\n#': continue
        k=txt.find('(',m.end()-1); depth=0;i=k
        while i<len(txt):
            if txt[i]=='(':depth+=1
            elif txt[i]==')':
                depth-=1
                if depth==0: break
            i+=1
        i2=i+1
        while i2<len(txt) and txt[i2] in ' \t\n': i2+=1
        if i2<len(txt) and txt[i2]=='{':
            b=extract_braced(txt,i2)
            if b: spans.append((i2, i2+len(b)))
    return spans

report = []
for f in handlers:
    path = os.path.join(ROOT, f['file'])
    txt = open(path, errors='ignore').read()
    hnames = set()
    for h in f['handlers']:
        hnames.add(h['handler'])
    # all handler function spans
    spans = []
    for nm in hnames:
        spans += find_handler_spans(txt, nm)
    # helper callees inside handlers (one level) - skip; manual later
    plain_sites = []
    for m in re.finditer(r'\bspin_lock\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z0-9_]*)*)', txt):
        pos = m.start()
        in_handler = any(s <= pos < e for s,e in spans)
        line = txt[:pos].count('\n')+1
        fn = None
        for (fs, fe, name) in find_funcs(txt):
            if fs <= pos < fe:
                fn = name; break
        plain_sites.append((line, re.sub(r'\s+','',m.group(1)), fn, in_handler))
    outside = [p for p in plain_sites if not p[3]]
    if outside:
        report.append({'file': f['file'], 'outside_plain': outside, 'handlers': [h['handler'] for h in f['handlers']]})
json.dump(report, open(TMP+'/outside.json','w'), indent=1)
# print summary sorted by count of outside plain sites matching handler locks
rows=[]
for r in report:
    hlocks = set()
    txt = None
    for f in handlers:
        if f['file']==r['file']:
            for h in f['handlers']:
                for lk in h['plain_locks']: hlocks.add(lk)
    outs = [p for p in r['outside_plain'] if p[1] in hlocks]
    if outs:
        rows.append((len(outs), r['file'], outs, r['handlers']))
rows.sort(key=lambda x:-x[0])
for cnt, file, outs, hnds in rows[:40]:
    print(f"== {file} (handlers: {','.join(hnds[:4])}) outside-plain-on-handler-lock: {cnt}")
    for (line, lk, fn, _) in outs[:14]:
        print(f"   {line}: {lk}  in {fn}()")
print("files with outside plain sites:", len(rows))
