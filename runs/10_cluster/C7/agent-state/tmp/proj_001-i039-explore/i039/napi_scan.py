import re, os, sys, subprocess
root = sys.argv[1]
files = subprocess.run(['grep','-rl','--include=*.c','-E','netif_napi_add|napi_schedule'] + sys.argv[2:],
                       cwd=root, capture_output=True, text=True).stdout.split()
def find_def(text, fname):
    pat = re.compile(r'^[^\n]*?\b' + re.escape(fname) + r'\s*\(', re.M)
    for m in pat.finditer(text):
        start = m.start()
        linestart = text.rfind('\n', 0, start)+1
        b = text.find('{', m.end())
        if b == -1: continue
        if ';' in text[m.end():b]: continue
        depth=0; i=b
        while i < len(text):
            if text[i]=='{': depth+=1
            elif text[i]=='}':
                depth-=1
                if depth==0: break
            i+=1
        return linestart, i+1
    return None
for f in files:
    path = os.path.join(root, f)
    text = open(path, errors='replace').read()
    # netif_napi_add(dev, &x->napi, poll, weight)
    for m in re.finditer(r'netif_napi_add\s*\(([^;]*?)\);', text, re.S):
        args = m.group(1)
        parts = [a.strip() for a in args.split(',')]
        # poll fn is typically 3rd arg; also match netif_napi_add(dev, napi, fn)
        cand = None
        for p in parts:
            if re.match(r'^[a-zA-Z_]\w*$', p) and not p in ('NAPI_POLL_WEIGHT',) and not p.endswith('_WEIGHT'):
                # heuristic: identifier that has a def in this file
                if find_def(text, p):
                    cand = p
        if not cand: continue
        r = find_def(text, cand)
        if not r: continue
        s,e = r
        body = text[s:e]
        locks = set(re.findall(r'spin_lock\s*\(\s*&([\w>\.\[\]~-]+)', body))
        if not locks: continue
        defline = text[:s].count('\n')+1
        for lk in sorted(locks):
            plain = [text[:mm.start()].count('\n')+1 for mm in re.finditer(r'spin_lock\s*\(\s*&' + re.escape(lk), text)]
            bh = [text[:mm.start()].count('\n')+1 for mm in re.finditer(r'spin_lock_bh\s*\(\s*&' + re.escape(lk), text)]
            print(f"{f}\tpoll={cand}:{defline}\tlock={lk}\tplain={plain}\tbh={bh}")
