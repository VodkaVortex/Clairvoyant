import re, os, subprocess, sys

# Collect timer_setup / .function / hrtimer callback registrations across drivers/ net/
root = '.'
files = []
for dirpath, dirs, fs in os.walk(root):
    if any(x in dirpath for x in ('/Documentation','/scripts','/tools','/.git')):
        continue
    for f in fs:
        if f.endswith(('.c','.h')):
            files.append(os.path.join(dirpath, f))

reg_re = re.compile(r'timer_setup\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
fn_re = re.compile(r'\.function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)')
setup_timer_re = re.compile(r'setup_timer\s*\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
hrt_re = re.compile(r'\.function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)')

# map: callback name -> set of files registering it
cb_regs = {}
def add(cb, path, kind):
    if cb.startswith('&'): cb = cb[1:]
    cb_regs.setdefault(cb, set()).add((path, kind))

for path in files:
    try:
        s = open(path, 'r', errors='replace').read()
    except Exception:
        continue
    for m in reg_re.finditer(s): add(m.group(1), path, 'timer_setup')
    for m in setup_timer_re.finditer(s): add(m.group(1), path, 'setup_timer')
    for m in fn_re.finditer(s): add(m.group(1), path, '.function')
    # hrtimer_init then .function handled above; also hrtimer_init(&t, clock, mode) with t.function set via struct init

# Now scan each callback body for plain spin_lock
lock_re = re.compile(r'spin_lock\s*\(\s*([^);]+)\)')
results = []
for path in files:
    try:
        s = open(path, 'r', errors='replace').read()
    except Exception:
        continue
    lines = s.split('\n')
    for i, ln in enumerate(lines):
        for m in re.finditer(r'^(?:static\s+)?(?:void|int|enum\s+hrtimer_restart|[A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', ln):
            fname = m.group(1)
            if fname not in cb_regs:
                continue
            # check this definition file matches a registration or the name is unique-ish; just record
            # extract body via brace matching from line i
            depth = 0; started = False
            body = []
            for j in range(i, min(i+400, len(lines))):
                body.append(lines[j])
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]: started = True
                if started and depth == 0:
                    break
            body_s = '\n'.join(body)
            locks = lock_re.findall(body_s)
            locks = [l.strip() for l in locks if 'irq' not in l and '_bh' not in 'spin_lock_bh(' + l]
            # filter actual plain: the regex only matches spin_lock( exactly so plain by construction
            if locks:
                results.append((path, fname, i+1, locks, cb_regs[fname]))

for path, fname, line, locks, regs in sorted(results):
    print(f"{path}:{line} {fname} locks={locks} regs={sorted(regs)}")
