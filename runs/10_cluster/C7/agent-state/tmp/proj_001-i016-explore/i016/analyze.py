import os, re, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
SCAN_DIRS = ["drivers/net/wireless", "drivers/staging", "net", "drivers/net", "net/wireless", "drivers/usb", "sound", "drivers/tty", "drivers/media"]

func_def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{?\s*$')
lock_re = re.compile(r'\b(spin_lock|spin_unlock|spin_lock_bh|spin_unlock_bh|spin_lock_irq|spin_unlock_irq|spin_lock_irqsave|spin_unlock_irqrestore|spin_trylock|spin_trylock_bh|spin_lock_nested)\s*\(')
lockarg_re = re.compile(r'\(([^;{]*?)\)\s*;')

def lock_mode(fn):
    if 'irqsave' in fn or 'irqrestore' in fn: return 'irqsave'
    if '_bh' in fn: return 'bh'
    if 'irq' in fn: return 'irq'
    if 'nested' in fn: return 'plain'
    return 'plain'

def lock_field(arg):
    # extract last field name from &priv->foo.bar or priv->foo
    m = re.findall(r'->\s*([A-Za-z_][A-Za-z0-9_]*)|\.([A-Za-z_][A-Za-z0-9_]*)', arg)
    names = [a or b for a,b in m]
    if not names:
        return None
    return names[-1]

# 1) find timer callback function names (declared via timer_setup/setup_timer/DEFINE_TIMER/init_timer + function=)
timer_setup_re = re.compile(r'(?:timer_setup|setup_timer)\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
define_timer_re = re.compile(r'DEFINE_TIMER\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*')
timer_fn_re = re.compile(r'\.function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*')

timer_callbacks = {}  # fname -> (file, line, timer_object)
hrtimer_handlers = set()
files = []
for d in SCAN_DIRS:
    p = os.path.join(ROOT, d)
    if not os.path.isdir(p): continue
    for dirpath, _, fnames in os.walk(p):
        for f in fnames:
            if f.endswith(('.c','.h')):
                files.append(os.path.join(dirpath, f))

for fp in files:
    try: lines = open(fp, errors='ignore').read().split('\n')
    except: continue
    for i, l in enumerate(lines):
        for m in timer_setup_re.finditer(l):
            timer_callbacks[m.group(1)] = (os.path.relpath(fp, ROOT), i+1, l.strip()[:120])
        for m in define_timer_re.finditer(l):
            timer_callbacks[m.group(1)] = (os.path.relpath(fp, ROOT), i+1, l.strip()[:120])
        # hrtimer .function assignments: only if file mentions hrtimer
        if 'hrtimer' in l:
            for m in timer_fn_re.finditer(l):
                hrtimer_handlers.add((m.group(1), os.path.relpath(fp, ROOT), i+1))

# save raw
out = {"timer_callbacks": timer_callbacks, "hrtimer_handlers": sorted(hrtimer_handlers)}
json.dump(out, open(os.path.join(os.environ['TMPDIR'],'i016','timer_callbacks.json'),'w'), indent=1)
print("timer callbacks:", len(timer_callbacks), "hrtimer handlers:", len(hrtimer_handlers))
