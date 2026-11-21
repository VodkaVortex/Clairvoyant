import re, os, sys, glob

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11"
DIRS = ["drivers/net", "drivers/staging", "drivers/bluetooth", "drivers/usb", "net"]

timer_setup_re = re.compile(r'timer_setup\(\s*&?[\w\.\->\[\]]+\s*,\s*(\w+)\s*,')
dwork_re = re.compile(r'INIT_DELAYED_WORK\(\s*&?[\w\.\->\[\]]+\s*,\s*(\w+)\s*\)')
fn_assign_re = re.compile(r'(\w+)\.function\s*=\s*&?(\w+)\s*;')
hrtimer_re = re.compile(r'hrtimer_init\(\s*&?[\w\.\->\[\]]+')

def find_func_body(src, name):
    # find definition: name(...) at start of logical line, then match braces
    m = re.search(r'^[A-Za-z_][\w\s\*,\(\)\[\]\.#]*\b' + re.escape(name) + r'\s*\(', src, re.M)
    if not m:
        return None
    i = src.find('{', m.end())
    if i < 0:
        return None
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                break
        j += 1
    return src[i:j+1], src[:m.start()].count('\n')+1, i

results = []
for d in DIRS:
    for path in glob.glob(os.path.join(ROOT, d, "**", "*.c"), recursive=True):
        try:
            src = open(path, errors='replace').read()
        except Exception:
            continue
        cbs = set()
        for m in timer_setup_re.finditer(src):
            cb = m.group(1)
            if cb not in ("NULL",):
                cbs.add((cb, 'timer_setup', src[:m.start()].count('\n')+1))
        for m in dwork_re.finditer(src):
            cbs.add((m.group(1), 'INIT_DELAYED_WORK', src[:m.start()].count('\n')+1))
        # hrtimer .function assignments
        for m in fn_assign_re.finditer(src):
            var, cb = m.group(1), m.group(2)
            if any(k in cb.lower() for k in ('fn','timer','handler','cb','expiry','expir','timeout','poll','tick','sample','simulate','_run','_fire','_done')):
                cbs.add((cb, 'hrtimer.function', src[:m.start()].count('\n')+1))
        for cb, kind, regline in cbs:
            fb = find_func_body(src, cb)
            if not fb:
                continue
            body, defline, _ = fb
            if re.search(r'\bspin_lock\s*\(', body):
                rel = os.path.relpath(path, ROOT)
                results.append((rel, cb, kind, regline, defline))

for r in sorted(set(results)):
    print("%-75s cb=%-35s %-18s reg@%-5d def@%d" % r)
print("TOTAL", len(set(results)))
