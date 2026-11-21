import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"

reg_re = re.compile(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(')

files_c = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if fn.endswith('.c'):
            files_c.append(os.path.join(dirpath, fn))
files_c.sort()

handler_defs = {}
reg_sites = []

for path in files_c:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().split('\n')
    except Exception:
        continue
    rel = os.path.relpath(path, ROOT)
    n = len(lines)
    for i, ln in enumerate(lines):
        m = reg_re.search(ln)
        if m:
            buf = ln[m.start():]
            j = i
            while buf.count('(') > buf.count(')') and j + 1 < n and j - i < 15:
                j += 1
                buf += ' ' + lines[j]
            try:
                inner = buf[buf.index('(')+1 : buf.rindex(')')]
            except ValueError:
                continue
            args, depth, cur = [], 0, ''
            for ch in inner:
                if ch == '(': depth += 1
                elif ch == ')': depth -= 1
                if ch == ',' and depth == 0:
                    args.append(cur); cur = ''
                else:
                    cur += ch
            args.append(cur)
            h = None
            if 'threaded' in buf[:buf.index('(')] and len(args) >= 4:
                h = args[1].strip()
            elif len(args) >= 2:
                h = args[1].strip()
            if h:
                h = h.strip().lstrip('&').strip()
            reg_sites.append((rel, i+1, h))
            continue
        dm = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\(', ln)
        if dm:
            name = dm.group(1)
            body_start = None
            k = i
            while k < n and k - i < 12:
                chunk = lines[k]
                if ';' in chunk and '{' not in chunk:
                    break
                if '{' in chunk:
                    body_start = k
                    break
                k += 1
            if body_start is not None and not ln.startswith('#'):
                handler_defs.setdefault(name, (rel, i+1))

json.dump({'reg_sites': reg_sites, 'handler_defs': handler_defs}, open(os.path.join(os.environ['TMPDIR'], 'step1.json'), 'w'))
print('registrations:', len(reg_sites))
print('handler defs:', len(handler_defs))
