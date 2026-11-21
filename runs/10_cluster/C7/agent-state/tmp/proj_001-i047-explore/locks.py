import re, os, json, collections

tdir = os.environ["TMPDIR"]
defs = json.load(open(os.path.join(tdir, "handler_defs.json")))

spin_plain = re.compile(r'\bspin_lock\s*\(\s*([^;]+?)\s*\)\s*;')
spin_bh   = re.compile(r'\bspin_lock_bh\s*\(\s*([^;]+?)\s*\)\s*;')
spin_irq  = re.compile(r'\bspin_lock_irq\s*\(\s*([^;]+?)\s*\)\s*;')
spin_irqsave = re.compile(r'\bspin_lock_irqsave\s*\(\s*([^,;]+?)\s*,')

def body_of(path, startline):
    try:
        lines = open(path, errors='replace').readlines()
    except Exception:
        return None, None
    i = startline - 1
    depth = 0
    started = False
    j = i
    while j < len(lines) and '{' not in lines[j]:
        if ';' in lines[j]:
            return None, None
        j += 1
    if j >= len(lines):
        return None, None
    body = []
    k = i
    while k < len(lines):
        body.append(lines[k])
        depth += lines[k].count('{') - lines[k].count('}')
        if depth <= 0 and k > j:
            break
        k += 1
    return body, k + 1

handler_locks = {}
for h, defsites in defs.items():
    ent = {}
    for (p, line) in defsites:
        body, end = body_of(p, line)
        if not body:
            continue
        text = ''.join(body)
        plain = set(spin_plain.findall(text))
        bh = set(spin_bh.findall(text))
        irq = set(spin_irq.findall(text))
        irqsave = set(spin_irqsave.findall(text))
        if plain:
            ent.setdefault(p, []).append({
                'line': line, 'end': end,
                'plain': sorted(plain), 'bh': sorted(bh),
                'irq': sorted(irq), 'irqsave': sorted(irqsave)})
    if ent:
        handler_locks[h] = ent

with open(os.path.join(tdir, "handler_locks.json"), "w") as out:
    json.dump(handler_locks, out, indent=0)
nlocks = sum(1 for h, files in handler_locks.items()
             for p, lst in files.items() for e in lst if e['plain'])
print("handler-def sites with plain spin_lock:", nlocks)
