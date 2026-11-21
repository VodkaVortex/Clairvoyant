import os, re, sys, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"
TMP = os.environ.get('TMPDIR','/tmp')
SKIP_DIRS = {"Documentation", "tools", "scripts", "samples", "usr"}
req_re = re.compile(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(')
lock_any_re = re.compile(r'\bspin_lock(?:_irqsave|_irq|_bh|_irqsave_nest_lock)?\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*)')

def norm(e): return re.sub(r'\s+','',e)

def extract_braced(txt, start):
    # start: index of '{' 
    depth = 0
    i = start
    n = len(txt)
    while i < n:
        c = txt[i]
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: return txt[start:i+1], i
        elif c == '"' or c == "'":
            q = c; i += 1
            while i < n and txt[i] != q:
                if txt[i] == '\\': i += 1
                i += 1
        i += 1
    return None, None

def find_handler_def(txt, name):
    # find "<ret> name(...)" followed by '{'
    for m in re.finditer(r'(?<![\w.>])(?:static\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\**\s*' + re.escape(name) + r'\s*\(', txt):
        # ensure not a call: previous non-space char should be one of ; { } or start
        j = m.start()-1
        while j >= 0 and txt[j] in ' \t\n': j -= 1
        if j >= 0 and txt[j] not in ';}{\n#':
            continue
        # find the brace after the paren
        k = txt.find('(', m.end()-1)
        depth = 0; i = k
        while i < len(txt):
            if txt[i] == '(': depth += 1
            elif txt[i] == ')':
                depth -= 1
                if depth == 0: break
            i += 1
        # scan to first '{' skipping whitespace/simple stuff
        i2 = i+1
        while i2 < len(txt) and txt[i2] in ' \t\n': i2 += 1
        if i2 < len(txt) and txt[i2] == '{':
            body, _ = extract_braced(txt, i2)
            if body: return body
    return None

out = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    parts = dirpath[len(ROOT):].strip('/').split('/')
    if parts and parts[0] in SKIP_DIRS:
        dirnames[:] = []
        continue
    for fn in filenames:
        if not fn.endswith('.c'):
            continue
        path = os.path.join(dirpath, fn)
        try:
            txt = open(path, errors='ignore').read()
        except OSError:
            continue
        if not req_re.search(txt):
            continue
        # find registrations and parse handler name (first arg of request_irq is name; for request_threaded_irq first handler may be NULL)
        # collect (line_no, kind, handler_name)
        regs = []
        for m in re.finditer(r'\b(devm_)?request(_threaded)?_irq\s*\(', txt):
            kind = 'threaded' if m.group(2) else 'plain'
            # grab args region
            k = txt.find('(', m.end()-1)
            # naive: take next 400 chars, find first two identifiers that are not NULL
            seg = txt[m.end():m.end()+400]
            # split by commas at depth 0
            args = []
            depth = 0; cur = ''
            for ch in seg:
                if ch == '(': depth += 1
                if ch == ')':
                    if depth == 0: break
                    depth -= 1
                if ch == ',' and depth == 0:
                    args.append(cur); cur = ''
                else:
                    cur += ch
            args.append(cur)
            names = []
            for a in args[:3]:
                a2 = a.strip()
                idm = re.match(r'&?([A-Za-z_][A-Za-z0-9_]*)\s*$', a2)
                if idm and idm.group(1) != 'NULL':
                    names.append(idm.group(1))
            line = txt[:m.start()].count('\n') + 1
            regs.append((line, kind, names))
        if not regs: continue
        # for each handler candidate, find def and lock usage
        fileinfo = []
        for line, kind, names in regs:
            # request_irq: names[0]=handler; threaded: names[0]=primary (may be NULL), names[1]=thread
            cands = []
            if kind == 'plain':
                if names: cands = [(names[0], 'primary')]
            else:
                if names: cands = [(names[0], 'primary' if len(names)==1 or True else '')]
                # for threaded, first non-NULL arg is primary; second could be thread fn
                # names list contains identifiers only; for threaded handler list = [primary, threadfn]
            for (nm, role) in cands:
                if nm in ('void','int','unsigned','char','long','static','struct'): continue
                body = find_handler_def(txt, nm)
                if body is None:
                    continue
                locks = lock_any_re.findall(body)
                plain = []
                for lm in re.finditer(r'\bspin_lock\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z0-9_]*)*)', body):
                    plain.append(norm(lm.group(1)))
                irqsafe = []
                for lm in re.finditer(r'\bspin_lock_(?:irqsave|irq|bh)(?:_nest_lock)?\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z0-9_]*)*)', body):
                    irqsafe.append(norm(lm.group(1)))
                if plain:
                    fileinfo.append({'handler': nm, 'reg_line': line, 'kind': kind, 'plain_locks': sorted(set(plain)), 'safe_locks': sorted(set(irqsafe)), 'all_locks': sorted(set(norm(l) for l in locks))})
        if fileinfo:
            out.append({'file': os.path.relpath(path, ROOT), 'handlers': fileinfo})
json.dump(out, open(TMP+'/handlers.json','w'), indent=1)
print("files:", len(out), "handlers with plain locks:", sum(len(f['handlers']) for f in out))
