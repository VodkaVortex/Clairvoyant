import os, re, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"

req_re = re.compile(r'\b(?:devm_)?request(?:_threaded|_percpu|_any_context|_noprobes)?_irq\s*\(')
spin_re = re.compile(r'\bspin_(?:un)?lock(?:_irqsave|_irq|_bh|_trylock)?\s*\(')
lock_irq_re = re.compile(r'\bspin_(?:un)?lock_irqsave\s*\(|\bspin_(?:un)?lock_irq\s*\(|\blocal_irq_(?:save|disable)\s*\(')
plain_re = re.compile(r'\bspin_lock\s*\(')
irq_re = re.compile(r'\bspin_lock_irq(?:save)?\s*\(')
bh_re = re.compile(r'\bspin_lock_bh\s*\(')
unlock_re = re.compile(r'\bspin_unlock\s*\(')
unirq_re = re.compile(r'\bspin_unlock_irq(?:restore)?\s*\(')

def read(p):
    with open(p, 'r', errors='replace') as f:
        return f.read()

results = []
for dirpath, dirs, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith('.c'): continue
        p = os.path.join(dirpath, fn)
        try: src = read(p)
        except: continue
        if 'request_irq' not in src and 'request_threaded_irq' not in src: continue
        lines = src.split('\n')
        for i, ln in enumerate(lines):
            if req_re.search(ln):
                # find handler arg: request_irq(irq, handler, ...) -> arg2 (index1)
                # gather full call possibly multiline
                call = ln
                j = i
                while call.count('(') > call.count(')') and j+1 < len(lines) and j - i < 8:
                    j += 1
                    call += ' ' + lines[j]
                m = re.search(r'_irq\s*\(([^;]*?)\)', call)
                if not m: continue
                args = m.group(1)
                # split top-level commas
                parts, depth, cur = [], 0, ''
                for ch in args:
                    if ch == '(': depth += 1
                    if ch == ')': depth -= 1
                    if ch == ',' and depth == 0:
                        parts.append(cur.strip()); cur = ''
                    else: cur += ch
                parts.append(cur.strip())
                handler = parts[1] if len(parts) > 1 else ''
                handler = handler.strip()
                results.append((os.path.relpath(p, ROOT), i+1, handler))

print(len(results))
with open(os.environ['TMPDIR'] + '/irq_sites.json', 'w') as f:
    json.dump(results, f)
