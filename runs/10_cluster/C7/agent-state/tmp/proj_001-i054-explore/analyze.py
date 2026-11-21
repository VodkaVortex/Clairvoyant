import os, re, json, collections

T=os.environ['TMPDIR']
regs=json.load(open(os.path.join(T,'regs.json')))

spin_re = re.compile(r'\b(spin_lock|spin_trylock|spin_lock_irq|spin_lock_irqsave|spin_lock_bh)\s*\(\s*([^;]*?)\s*\)')
func_re = re.compile(r'^[A-Za-z_][\w\s\*,\(\)\[\]\.]*?\b(\w+)\s*\([^;]*$')

def load(path):
    try:
        return open(path, errors='ignore').read()
    except Exception:
        return None

def find_func_body(lines, name):
    # find definition of function `name` at col 0
    pat = re.compile(r'^(?:static\s+|inline\s+|__always_inline\s+|const\s+|unsigned\s+|struct\s+[\w\d_]+\s+|enum\s+[\w\d_]+\s+|[A-Za-z_][\w\d_]*\s*)*'+re.escape(name)+r'\s*\(')
    for idx,l in enumerate(lines):
        if pat.match(l) or (l.startswith(name+'(')):
            # ensure it's a definition: find opening brace on same or later line before semicolon
            j=idx; header=''
            while j < len(lines) and j < idx+8:
                header += lines[j]
                if '{' in header:
                    if ';' in header.split('{')[0][-200:]:
                        break
                    # count braces to find end
                    depth=header.count('{')-header.count('}')
                    end=j
                    while depth>0 and end < len(lines)-1:
                        end+=1
                        depth += lines[end].count('{')-lines[end].count('}')
                    return idx, end
                if header.rstrip().endswith(';'):
                    break
                j+=1
    return None

def parse_locks(body_lines):
    out=[]
    for i,l in enumerate(body_lines):
        for m in spin_re.finditer(l):
            out.append((i, m.group(1), m.group(2)))
    return out

byfile=collections.defaultdict(list)
for r in regs:
    byfile[r['file']].append(r)

handler_plain=[]  # (file, handler, hline, lockexpr, lockvariant, regline)
handler_irq=[]
stats={'resolved':0,'unresolved_expr':0,'notfound':0}
unresolved_names=collections.Counter()

for path, rs in byfile.items():
    txt=load(path)
    if txt is None: continue
    lines=txt.split('\n')
    for r in rs:
        h=r['handler']
        name=None
        # normalize handler expr
        m=re.search(r'(\w+)\s*$', h)
        if h and (m:=re.match(r'^(\w+)$', h.strip())):
            name=h.strip()
        elif h and (m:=re.search(r'&?(\w+)\s*$', h.strip())):
            name=m.group(1)
        if not name:
            stats['unresolved_expr']+=1
            unresolved_names[h]+=1
            continue
        fb=find_func_body(lines, name)
        if not fb:
            stats['notfound']+=1
            unresolved_names[name]+=1
            continue
        stats['resolved']+=1
        start,end=fb
        body=lines[start:end+1]
        for (i,var,lk) in parse_locks(body):
            entry={'file':path,'handler':name,'hdefline':start+1+i,'variant':var,'lock':lk,
                   'regline':r['line'],'regkind':r['kind'],'argc':r['argc']}
            if var in ('spin_lock','spin_trylock'):
                handler_plain.append(entry)
            elif var in ('spin_lock_irq','spin_lock_irqsave','spin_lock_bh'):
                handler_irq.append(entry)

print("stats:", stats)
print("handler plain-lock sites:", len(handler_plain))
json.dump(handler_plain, open(os.path.join(T,'handler_plain.json'),'w'), indent=0)
json.dump(stats, open(os.path.join(T,'stats.json'),'w'))

# show top unresolved handler names
print("top unresolved:", unresolved_names.most_common(15))
