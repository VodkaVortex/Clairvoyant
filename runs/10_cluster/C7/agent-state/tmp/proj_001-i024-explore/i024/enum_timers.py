import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s09"
roots = ["drivers", "net", "kernel", "fs", "block", "mm", "ipc", "security", "lib", "sound", "crypto", "virt"]

timer_re = re.compile(
    r'(?:timer_setup|setup_timer)\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)'
    r'|DEFINE_TIMER\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)'
    r'|\.\s*function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)'
)

cb_names = {}
for root in roots:
    for dirpath, dirs, files in os.walk(os.path.join(ROOT, root)):
        for f in files:
            if not f.endswith(('.c', '.h')):
                continue
            p = os.path.join(dirpath, f)
            try:
                lines = open(p, errors='replace').read().splitlines()
            except OSError:
                continue
            for i, ln in enumerate(lines, 1):
                for m in timer_re.finditer(ln):
                    name = m.group(1) or m.group(2) or m.group(3)
                    if name:
                        cb_names.setdefault(name, []).append((os.path.relpath(p, ROOT), i))

sys.stderr.write("timer callbacks: %d\n" % len(cb_names))

def_re = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(')
plain_lock_re = re.compile(r'\bspin_lock\s*\(\s*&?')

hits = []
for name, sites in cb_names.items():
    for (relp, regline) in sites:
        p = os.path.join(ROOT, relp)
        try:
            lines = open(p, errors='replace').read().splitlines()
        except OSError:
            continue
        defl = None
        for i, ln in enumerate(lines):
            dm = def_re.match(ln)
            if dm and dm.group(1) == name and '(' in ln:
                defl = i
                break
        if defl is None:
            continue
        j = defl
        found_brace = False
        while j < min(defl + 6, len(lines)):
            if '{' in lines[j]:
                found_brace = True
                break
            if ';' in lines[j] and j > defl:
                break
            j += 1
        if not found_brace:
            continue
        depth = 0
        k = j
        started = False
        while k < len(lines):
            ln = lines[k]
            depth += ln.count('{') - ln.count('}')
            if '{' in ln:
                started = True
            if started and depth <= 0:
                break
            if started and plain_lock_re.search(ln):
                hits.append((relp, defl + 1, regline, k + 1, name, ln.strip()))
                break
            k += 1

sys.stderr.write("hits: %d\n" % len(hits))
for h in sorted(hits):
    print("%s:%s def=%s reg=%s plainlock=%s fn=%s :: %s" % (h[0], h[1], h[1], h[2], h[3], h[4], h[5][:100]))
