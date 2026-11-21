import re, sys, os, json

# Static analysis: for each file registering a tasklet, extract tasklet callback names,
# then check whether the callback body (and same-file direct callees) take plain spin_lock,
# and whether the same lock expression (base name) is taken plainly elsewhere in the file
# from functions NOT in the softirq set.
files = [l.strip() for l in open(os.environ['W']+'/tasklet_files.txt')]
outdir = {}
for f in files:
    try:
        src = open(f, errors='replace').read()
    except Exception:
        continue
    outdir[f] = src

def find_callsites(src, name):
    # find name( ... ) with balanced parens
    sites = []
    for m in re.finditer(re.escape(name)+r'\s*\(', src):
        i = m.end()
        depth = 1
        while i < len(src) and depth:
            if src[i]=='(': depth+=1
            elif src[i]==')': depth-=1
            i+=1
        sites.append((m.start(), i))
    return sites

def get_text(src, s, e):
    # return the call text
    return src[s:e]

def func_body_span(src, fname):
    # find "fname(...)" followed by "{"
    for m in re.finditer(r'\b'+re.escape(fname)+r'\b\s*\(', src):
        i = m.end(); depth=1
        while i < len(src) and depth:
            if src[i]=='(': depth+=1
            elif src[i]==')': depth-=1
            i+=1
        # skip whitespace, expect '{'
        j = i
        while j < len(src) and src[j] in ' \t\r\n': j+=1
        if j < len(src) and src[j]=='{':
            depth=0; k=j
            while k < len(src):
                if src[k]=='{': depth+=1
                elif src[k]=='}':
                    depth-=1
                    if depth==0:
                        return j, k+1
                k+=1
    return None

def line_of(src, pos):
    return src.count('\n', 0, pos)+1

LOCKRE = re.compile(r'spin_lock\s*\(&?([^);]+)\)?')
results = []
for f, src in outdir.items():
    # tasklet callback names
    cbs = []
    for m in re.finditer(r'tasklet_setup\s*\(\s*&?([\w\.\->]+)\s*,\s*(\w+)\s*\)', src):
        cbs.append(m.group(2))
    for m in re.finditer(r'tasklet_init\s*\(\s*&?([\w\.\->]+)\s*,\s*(?:\(void\s*\*\)\s*)?(\w+)\s*,', src):
        cbs.append(m.group(2))
    cbs = list(dict.fromkeys(cbs))
    if not cbs: continue
    # collect locks taken inside tasklet callback bodies (plain)
    softirq_locks = {}   # lock base -> list of (func, line)
    for cb in cbs:
        span = func_body_span(src, cb)
        if not span: continue
        body = src[span[0]:span[1]]
        for lm in LOCKRE.finditer(body):
            lock = lm.group(1).strip().rstrip(')')
            softirq_locks.setdefault(lock, []).append((cb, line_of(src, span[0])+src[span[0]:span[1]].count('\n',0,lm.start())))
    if not softirq_locks: continue
    # now find plain spin_lock on same base lock in other functions
    lockbases = set()
    for lk in softirq_locks:
        base = lk.split('.')[-1].split('->')[-1]
        lockbases.add(base)
    for m in re.finditer(r'spin_lock\s*\(\s*&?([^);]+)\s*\)', src):
        lock = m.group(1).strip()
        base = lock.split('.')[-1].split('->')[-1]
        if base in lockbases:
            ln = line_of(src, m.start())
            # is it inside a tasklet callback body?
            inside = False
            for cb in cbs:
                span = func_body_span(src, cb)
                if span and span[0] <= m.start() < span[1]:
                    inside = True; break
            if not inside:
                results.append((f, ln, lock, ",".join(sorted(softirq_locks.keys())), ",".join(cbs)))

for r in sorted(set(results)):
    print(json.dumps(list(r)))
