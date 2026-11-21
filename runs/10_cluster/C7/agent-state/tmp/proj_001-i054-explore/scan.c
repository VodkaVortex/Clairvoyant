import re, os, sys, collections, json
ROOT = os.getcwd()
handler_re = re.compile(r'^(?:static\s+)?(?:irqreturn_t|enum\s+irqreturn|irq_handler_t)\s+(\w+)\s*\(', re.M)
req_re = re.compile(r'(?:devm_)?request(?:_threaded)?_irq\s*\(')
results = []
file_handlers = {}
for dirpath, dirnames, filenames in os.walk(ROOT):
    if '/.git' in dirpath: continue
    for fn in filenames:
        if not fn.endswith(('.c','.h')): continue
        p = os.path.join(dirpath, fn)
        try:
            src = open(p, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        if 'request_irq' not in src and 'request_threaded_irq' not in src: continue
        handlers = set(handler_re.findall(src))
        if not handlers: continue
        lines = src.split('\n')
        # find handler bodies: from def to next def at col 0
        bodies = {}
        for i, ln in enumerate(lines):
            m = re.match(r'^(?:static\s+)?(?:irqreturn_t|enum\s+irqreturn)\s+(\w+)\s*\(', ln)
            if m:
                name = m.group(1)
                # collect body until next line starting with '}' at col0 or next def
                j = i
                body = []
                while j < len(lines):
                    body.append(lines[j])
                    if j > i and re.match(r'^\}', lines[j]):
                        break
                    j += 1
                bodies[name] = (i+1, j+1, '\n'.join(body))
        for name, (s, e, body) in bodies.items():
            locks = []
            for m in re.finditer(r'spin_lock(?:_irqsave|_irq|_bh)?\s*\(\s*(?:&)?([^,)]+)', body):
                locks.append(m.group(0))
            if locks:
                rel = os.path.relpath(p, ROOT)
                file_handlers.setdefault(rel, []).append((name, s, e, locks))
print(json.dumps(file_handlers, indent=1))
