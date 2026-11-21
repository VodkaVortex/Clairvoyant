import os, re, sys, json, subprocess

W = os.environ.get('TMPDIR','/tmp') + '/i046'
# Read candidate file list
files = [l.strip() for l in open(W + '/files_irq_and_plainlock.txt') if l.strip()]

req_re = re.compile(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(')
plain_lock_re = re.compile(r'\bspin_lock\s*\(\s*([^)]*?)\s*\)')
irq_lock_res = [re.compile(p) for p in [
    r'\bspin_lock_irq\s*\(', r'\bspin_lock_irqsave\s*\(', r'\bspin_lock_bh\s*\(',
    r'\blocal_irq_save\s*\(', r'\blocal_irq_disable\s*\(', r'\braw_spin_lock_irq', r'\bspin_lock_irqsave_nested\s*\(']]

results = []
for path in files:
    try:
        src = open(path, errors='replace').read()
    except Exception:
        continue
    if not req_re.search(src):
        continue
    # parse functions crudely: split by lines; find function bodies via indentation tracking
    lines = src.split('\n')
    # build function map: start line, end line, name
    funcmap = []
    func_start_re = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    brace = 0
    in_func = False
    start = 0
    name = None
    depth = 0
    for i, l in enumerate(lines):
        if not in_func:
            m = func_start_re.match(l)
            if m and not l.rstrip().endswith(';'):
                # heuristics: previous line not starting with typical decl keywords that continue
                name = m.group(1)
                start = i
                depth = l.count('{') - l.count('}')
                if depth > 0:
                    in_func = True
                elif depth == 0 and '{' in l:
                    in_func = True  # single-line function
        else:
            depth += l.count('{') - l.count('}')
            if depth <= 0:
                funcmap.append((name, start, i))
                in_func = False
    if in_func:
        funcmap.append((name, start, len(lines)-1))
    # find request_irq call sites and extract handler name (first arg when 2-arg, or first arg for threaded)
    handlers = {}
    for i, l in enumerate(lines):
        if req_re.search(l):
            # gather up to 6 lines to capture multiline call
            blob = '\n'.join(lines[i:i+8])
            m = re.search(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(\s*([^,]+),\s*([A-Za-z_][A-Za-z0-9_]*)', blob)
            if m:
                h = m.group(2)
                handlers.setdefault(h, i)
    if not handlers:
        continue
    # for each handler, find its function body and collect plain locks and irqsave locks
    for h, regline in handlers.items():
        body = None
        for (fname, s, e) in funcmap:
            if fname == h:
                body = (s, e)
                break
        if body is None:
            continue
        s, e = body
        bodytext = '\n'.join(lines[s:e+1])
        if 'spin_lock' not in bodytext and 'local_irq' not in bodytext:
            continue
        plain = []
        for m in plain_lock_re.finditer(bodytext):
            plain.append((s+1 + bodytext[:m.start()].count('\n'), m.group(1)))
        if not plain:
            continue
        # record
        results.append({'file': path, 'handler': h, 'regline': regline+1,
                        'body': [s+1, e+1], 'plain_locks': plain})

json.dump(results, open(W + '/handler_plain_locks.json','w'), indent=1)
print(len(results))
for r in results[:200]:
    print(r['file'], r['handler'], r['regline'], r['plain_locks'][:4])
