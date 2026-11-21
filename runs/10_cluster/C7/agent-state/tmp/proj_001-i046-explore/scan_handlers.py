import os, re, sys
ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03'
OUT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore/handlers.txt'

req_re = re.compile(r'(?:devm_)?request(?:_threaded)?_irq\s*\(')
spin_re = re.compile(r'\bspin_lock\s*\(')

results = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if not fn.endswith('.c'):
            continue
        path = os.path.join(dirpath, fn)
        try:
            lines = open(path, errors='ignore').read().splitlines()
        except Exception:
            continue
        # find registration lines and the handler name (3rd arg for request_irq, 2nd and 3rd for threaded)
        for i, ln in enumerate(lines):
            if req_re.search(ln) or ('request_irq' in ln and '(' in ln):
                # gather handler token: for request_irq(f, h, ...) h is 2nd arg
                # for request_threaded_irq(f, h1, h2, ...) h1 is 2nd, h2 is 3rd
                # crude: take identifiers on this line and next lines until ');'
                blob = ln
                j = i
                while ');' not in blob and j+1 < len(lines) and j - i < 8:
                    j += 1
                    blob += ' ' + lines[j]
                inner = blob[blob.find('(')+1:blob.rfind(')')] if ')' in blob else blob
                # strip comments
                inner = re.sub(r'/\*.*?\*/', ' ', inner)
                args = [a.strip() for a in inner.split(',')]
                handlers = []
                if 'request_threaded_irq' in blob:
                    if len(args) >= 3:
                        for a in args[1:3]:
                            m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', a)
                            if m and m.group(1) not in ('NULL','0'):
                                handlers.append(m.group(1))
                else:
                    if len(args) >= 2:
                        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', args[1])
                        if m and m.group(1) not in ('NULL','0'):
                            handlers.append(m.group(1))
                for h in handlers:
                    results.append((os.path.relpath(path, ROOT), i+1, h))
with open(OUT,'w') as f:
    for p,l,h in results:
        f.write(f"{p}\t{l}\t{h}\n")
print(len(results), "registrations")
