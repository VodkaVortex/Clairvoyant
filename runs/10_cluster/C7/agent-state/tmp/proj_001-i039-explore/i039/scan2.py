import re, os, sys, subprocess
root = sys.argv[1]
files = subprocess.run(['grep','-rl','--include=*.c','-E','tasklet_schedule|tasklet_hi_schedule'] + sys.argv[2:],
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
    for m in re.finditer(r'tasklet_init\s*\(\s*&?[^,]+,\s*(\w+)\s*,', text):
        cb = m.group(1)
        r = find_def(text, cb)
        if not r: continue
        s,e = r
        body = text[s:e]
        locks = set(re.findall(r'spin_lock\s*\(\s*&([\w>\.\[\]~-]+)', body))
        locks |= set(re.findall(r'spin_lock_bh\s*\(\s*&([\w>\.\[\]~-]+)', body))
        if not locks: continue
        defline = text[:s].count('\n')+1
        for lk in sorted(locks):
            plain = [text[:mm.start()].count('\n')+1 for mm in re.finditer(r'spin_lock\s*\(\s*&' + re.escape(lk), text)]
            bh = [text[:mm.start()].count('\n')+1 for mm in re.finditer(r'spin_lock_bh\s*\(\s*&' + re.escape(lk), text)]
            irq = [text[:mm.start()].count('\n')+1 for mm in re.finditer(r'spin_lock_irq\w*\s*\(\s*&' + re.escape(lk), text)]
            ld = [text[:mm.start()].count('\n')+1 for mm in re.finditer(r'local_bh_disable', text)]
            print(f"{f}\tcb={cb}:{defline}\tlock={lk}\tplain={plain}\tbh={bh}\tirq={irq}\tlbd={ld}")
