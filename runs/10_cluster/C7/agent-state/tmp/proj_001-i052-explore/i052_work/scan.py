import os, re, sys, json, collections

ROOT = "."
OUT = os.path.join(os.environ.get("TMPDIR","/tmp"), "i052_work")

# Patterns for IRQ registration
irq_reg_re = re.compile(r'\b((?:devm_)?request_irq|request_threaded_irq|request_any_context_irq)\s*\(')
handler_def_re = re.compile(r'^\s*(?:static\s+)?(?:irqreturn_t|irq_handler_t|enum\s+irqreturn)\s+\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')

# spin lock acquisition forms
plain_re  = re.compile(r'\bspin_lock\s*\(\s*&?([A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)*(?:\[[A-Za-z0-9_]+\])?)')
nested_re = re.compile(r'\bspin_lock_nested\s*\(\s*&?([A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z0-9_]*)*(?:\[[A-Za-z0-9_]+\])?)')
irq_re    = re.compile(r'\bspin_lock_irq(?:save)?(?:_nested)?\s*\(\s*&?([A-Za-z_][A-Za-z0-9_]*)')
bh_re     = re.compile(r'\bspin_lock_bh\s*\(\s*&?([A-Za-z_][A-Za-z0-9_]*)')

def lock_base(expr):
    # normalize: take last member component, strip index
    parts = expr.split('->')
    last = parts[-1]
    last = re.sub(r'\[.*?\]', '', last)
    return last.strip()

results = {}  # file -> {handler_name: {'reg_line':int,'plain':[(line,lockexpr)],'irqsafe':[(line,expr)]}}

files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if fn.endswith(('.c','.h')):
            files.append(os.path.join(dirpath, fn))
print(f"scanning {len(files)} files", file=sys.stderr)

for fp in files:
    try:
        with open(fp, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        continue
    regs = []  # (line, handler_name)
    for i, line in enumerate(lines, 1):
        m = irq_reg_re.search(line)
        if m:
            # find handler argument - usually first or second arg
            # get rest of the line and next lines for multi-line call
            call = line[m.end()-1:]
            # accumulate up to 4 lines
            idx = i-1
            txt = line[idx:idx+1][max(0,m.start()):]
            blob = "".join(lines[idx:idx+6])
            # crude: take text after request_irq( up to matching paren depth
            start = blob.find('(')
            depth=0; endp=-1
            for ci,ch in enumerate(blob):
                if ch=='(': depth+=1
                elif ch==')':
                    depth-=1
                    if depth==0:
                        endp=ci; break
            args_txt = blob[start+1:endp] if endp>0 else blob[start+1:start+400]
            # split top-level commas
            args=[]; depth=0; cur=''
            for ch in args_txt:
                if ch=='(' : depth+=1
                if ch==')': depth-=1
                if ch==',' and depth==0:
                    args.append(cur.strip()); cur=''
                else:
                    cur+=ch
            args.append(cur.strip())
            hname=None
            # request_irq: irq, handler,... ; request_threaded_irq: irq, handler, thread_fn
            if len(args)>=2:
                cand=args[1].strip()
                cand=re.sub(r'^&','',cand).strip()
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', cand) and cand not in ('NULL','0'):
                    hname=cand
            if hname:
                regs.append((i, hname))
    if not regs:
        continue
    # find handler definitions in same file
    for (rl, hn) in regs:
        # locate definition
        defline=None
        for i, line in enumerate(lines,1):
            if hn in line:
                dm = re.search(r'\b'+re.escape(hn)+r'\s*\(', line)
                if dm:
                    # crude def check: previous non-space token is type like irqreturn_t or line starts a function
                    pre = line[:dm.start()].strip()
                    if pre.endswith('irqreturn_t') or 'irqreturn_t' in pre or pre.endswith('irq_handler_t') or 'irqreturn' in pre:
                        defline=i; break
                    # also allow static irqreturn_t on its own
                    if re.match(r'^\s*(static\s+)?irqreturn_t\s+\**'+re.escape(hn)+r'\b', line):
                        defline=i; break
        entry={'reg_line':rl,'def_line':defline,'plain':[],'irqsafe':[]}
        if defline:
            # find function body extent: from defline, find first '{' then match braces
            bl=None
            for i in range(defline-1, min(len(lines), defline+15)):
                if '{' in lines[i]:
                    bl=i; break
            if bl is not None:
                depth=0; end=bl
                started=False
                for i in range(bl, min(len(lines), bl+3000)):
                    for ch in lines[i]:
                        if ch=='{': depth+=1; started=True
                        elif ch=='}':
                            depth-=1
                            if started and depth==0:
                                end=i; break
                    if started and depth==0: break
                # scan body lines for locks; also include called local functions later (not resolved here)
                body=lines[bl:end+1]
                for j,ll in enumerate(body):
                    for m in plain_re.finditer(ll):
                        entry['plain'].append((bl+j+1, m.group(1)))
                    for m in nested_re.finditer(ll):
                        entry['plain'].append((bl+j+1, m.group(1)+' (nested)'))
                    for m in irq_re.finditer(ll):
                        entry['irqsafe'].append((bl+j+1, m.group(1)))
                    for m in bh_re.finditer(ll):
                        entry['irqsafe'].append((bl+j+1, m.group(1)))
        results.setdefault(fp, []).append({hn: entry})

with open(os.path.join(OUT,'handler_locks.json'),'w') as f:
    json.dump(results, f, indent=1)

# Build cross index: for each (file, handler-plain lock base), find all plain acquisitions of same lock base elsewhere in file
plain_sites = collections.defaultdict(list)  # file -> {lockbase: [(line,ctxline)]}
for fp in results:
    pass

cross=[]
for fp, hs in results.items():
    try:
        with open(fp,'r',errors='replace') as f: lines=f.readlines()
    except Exception: continue
    all_plain_bases=set()
    for h in hs:
        for hn, entry in h.items():
            for (ln, expr) in entry['plain']:
                all_plain_bases.add(lock_base(expr.split(' (nested)')[0]))
    if not all_plain_bases:
        continue
    # scan file for all plain acquisitions of those bases
    file_plain=[]
    for i, ll in enumerate(lines,1):
        for m in plain_re.finditer(ll):
            file_plain.append((i, lock_base(m.group(1))))
        for m in nested_re.finditer(ll):
            file_plain.append((i, lock_base(m.group(1))))
    for h in hs:
        for hn, entry in h.items():
            for (ln, expr) in entry['plain']:
                base=lock_base(expr.split(' (nested)')[0])
                others=[(i,b) for (i,b) in file_plain if b==base]
                others_irq=[(i) for i,ll in enumerate(lines,1) for m in irq_re.finditer(ll) if lock_base(m.group(1))==base]
                cross.append({'file':fp,'handler':hn,'reg_line':entry['reg_line'],'def_line':entry['def_line'],
                              'handler_plain':(ln,expr),'lock_base':base,
                              'all_plain_count':len(others),'all_plain_lines':[o[0] for o in others][:40],
                              'irqsafe_lines':others_irq[:40]})

with open(os.path.join(OUT,'cross.json'),'w') as f:
    json.dump(cross,f,indent=1)

# rank: files where handler-plain lock has many plain sites and few irqsave
ranked=[]
for c in cross:
    if c['all_plain_count']>=2:
        ranked.append((c['all_plain_count']-len(c['irqsafe_lines']), c['all_plain_count'], len(c['irqsafe_lines']), c['file'], c['handler'], c['lock_base'], c['handler_plain'][0], c['reg_line'], c['all_plain_lines']))
ranked.sort(reverse=True)
with open(os.path.join(OUT,'ranked.txt'),'w') as f:
    for r in ranked:
        f.write(f"{r[0]:4d} plain={r[1]:3d} irqsafe={r[2]:3d} {r[3]} handler={r[4]} lock={r[5]} hline={r[6]} reg={r[7]} plainlines={r[8]}\n")
print("done", len(cross), "handler-plain sites", file=sys.stderr)
import collections as _c
nreg = sum(len(hs) for hs in results.values())
uniq_h = _c.Counter()
for fp, hs in results.items():
    for h in hs:
        for hn,_ in h.items(): uniq_h[hn]+=1
print("registrations:", nreg, "unique handlers:", len(uniq_h), file=sys.stderr)
with open(os.path.join(OUT,"regs_summary.txt"),"w") as f:
    for fp, hs in results.items():
        for h in hs:
            for hn, entry in h.items():
                f.write(f"{fp}\t{hn}\treg={entry['reg_line']}\tdef={entry['def_line']}\n")

