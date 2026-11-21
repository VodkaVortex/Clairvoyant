import re, os, sys, subprocess

root = sys.argv[1]
files = subprocess.run(['grep','-rl','--include=*.c','-E','tasklet_schedule|tasklet_hi_schedule'] + sys.argv[2:],
                       cwd=root, capture_output=True, text=True).stdout.split()

def find_def(text, fname):
    # find "static ... fname(...)" up to matching closing brace at col 0
    pat = re.compile(r'^[^\n]*?\b' + re.escape(fname) + r'\s*\(', re.M)
    for m in pat.finditer(text):
        start = m.start()
        # take from start of line
        linestart = text.rfind('\n', 0, start)+1
        # find opening brace after
        b = text.find('{', m.end())
        if b == -1: continue
        # ensure no ';' between signature end and '{' (prototype)
        if ';' in text[m.end():b]:
            continue
        # match braces
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
    lines = text.split('\n')
    # tasklet_init sites
    for m in re.finditer(r'tasklet_init\s*\(\s*&?[^,]+,\s*(\w+)\s*,', text):
        cb = m.group(1)
        r = find_def(text, cb)
        if not r: continue
        s,e = r
        body = text[s:e]
        # plain spin_lock in body
        locks = set(re.findall(r'spin_lock\s*\(\s*&([\w>\.\[\]~-]+)', body))
        if not locks: continue
        # line number of callback def
        defline = text[:s].count('\n')+1
        for lk in locks:
            # all other sites of this lock in the same file
            sites = []
            for mm in re.finditer(r'spin_lock\s*\(\s*&' + re.escape(lk), text):
                ln = text[:mm.start()].count('\n')+1
                sites.append(ln)
            bh = len(re.findall(r'spin_lock_bh\s*\(\s*&' + re.escape(lk), text))
            irq = len(re.findall(r'spin_lock_irq\w*\s*\(\s*&' + re.escape(lk), text))
            print(f"{f}\tcallback={cb}:{defline}\tlock={lk}\tplain_in_cb\tother_plain_sites={sites}\tbh={bh}\tirq={irq}")
