import re, os, sys, subprocess, json

DIRS = ["drivers/net", "drivers/staging", "drivers/atm", "drivers/tty", "drivers/usb", "net"]

pat_tasklet = re.compile(r'(?:tasklet_init|tasklet_setup)\s*\(\s*&?([^,\s]+)\s*,\s*([A-Za-z_0-9]+)')
pat_napi = re.compile(r'netif_napi_add(?:_dev)?\s*\(\s*([^;]*?),\s*([A-Za-z_0-9]+)\s*\(')

files = set()
out = subprocess.run(["grep","-rl","-e","tasklet_init","-e","tasklet_setup","-e","netif_napi_add","--include=*.c"]+DIRS, capture_output=True, text=True)
for f in out.stdout.split():
    files.add(f)

def func_body(src, name):
    m = re.search(r'(?:^|\n)[A-Za-z_0-9 \*\t\(\)\n,]+\b'+re.escape(name)+r'\s*\([^;{]*?\)\s*\{', src)
    if not m:
        return None, None
    i = src.index('{', m.start())
    depth = 0
    for j in range(i, len(src)):
        if src[j] == '{': depth += 1
        elif src[j] == '}':
            depth -= 1
            if depth == 0:
                return src[i:j+1], src[:i].count('\n')+1
    return None, None

results = []
for f in sorted(files):
    try:
        src = open(f, errors='replace').read()
    except Exception:
        continue
    callbacks = []
    for m in pat_tasklet.finditer(src):
        cb = m.group(2)
        if cb and cb not in ('NULL',):
            callbacks.append((cb, 'tasklet'))
    for m in pat_napi.finditer(src):
        # skip first arg(s); take function name right after napi struct pointer
        args = m.group(1)
        cb = m.group(2)
        if cb:
            callbacks.append((cb, 'napi'))
    for cb, kind in sorted(set(callbacks)):
        body, line = func_body(src, cb)
        if not body:
            continue
        for lm in re.finditer(r'spin_lock(?:_bh|_irqsave|_irq)?\s*\(\s*([^);]+?)\s*[,)]', body):
            variant = lm.group(0).split('(')[0]
            lockexpr = lm.group(1).strip()
            if variant != 'spin_lock':
                continue
            sites = []
            for m in re.finditer(r'spin_lock\s*\(\s*([^);]+?)\s*[,)]', src):
                if m.group(1).strip() == lockexpr:
                    sites.append(src[:m.start()].count('\n')+1)
            if len(sites) >= 1:
                results.append({"file": f, "cb": cb, "kind": kind, "defline": line, "lock": lockexpr, "plain_sites": sites})

for r in results:
    print(json.dumps(r))
