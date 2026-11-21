import json, os, re, sys, collections

TMP = os.path.join(os.environ.get("TMPDIR","/tmp"), "i018")
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"

functions = json.load(open(f"{TMP}/functions.json"))      # name -> [(file, start, s, e)]
locksites = json.load(open(f"{TMP}/locksites.json"))      # (file, line, kind, lockexpr, funcname)

# timer callback registration patterns
timer_patterns = [
    (re.compile(r'\btimer_setup\s*\(\s*([^,]+)\s*,\s*([A-Za-z0-9_]+)\s*,'), 'timer_setup'),
    (re.compile(r'\bsetup_timer\s*\(\s*([^,]+)\s*,\s*([A-Za-z0-9_]+)\s*,'), 'setup_timer'),
    (re.compile(r'\b(\w+)\.function\s*=\s*([A-Za-z0-9_]+)\s*;'), 'timer.function='),
    (re.compile(r'\bhrtimer_init\s*\('), 'hrtimer_init'),
    (re.compile(r'\bINIT_DELAYED_WORK\s*\(\s*([^,]+)\s*,\s*([A-Za-z0-9_]+)\s*\)'), 'INIT_DELAYED_WORK'),
    (re.compile(r'\bINIT_DEFERRABLE_WORK\s*\(\s*([^,]+)\s*,\s*([A-Za-z0-9_]+)\s*\)'), 'INIT_DEFERRABLE_WORK'),
]

# find registration lines by grepping raw files (fast enough with ripgrep)
import subprocess
out = subprocess.run(["rg","-n","--no-heading","-e","timer_setup\\(|setup_timer\\(|INIT_DELAYED_WORK\\(|INIT_DEFERRABLE_WORK\\(|\\.function\\s*=\\s*\\w+\\s*;|hrtimer_init\\(", "--glob=*.c", "drivers/","net/","kernel/","mm/","fs/","block/","sound/","crypto/","security/"], cwd=ROOT, capture_output=True, text=True)
regs = []
for line in out.stdout.splitlines():
    try:
        floc, content = line.split(":", 1)
    except ValueError:
        continue
    regs.append((floc, content))
print("registration-ish lines:", len(regs), file=sys.stderr)

timer_callbacks = {}   # callback name -> (file, kind)
for floc, content in regs:
    for r, kind in timer_patterns:
        m = r.search(content)
        if m:
            if r.groups >= 2:
                cb = m.group(2)
            else:
                cb = None
            if cb:
                timer_callbacks.setdefault(cb, (floc, kind))
            break
print("timer callbacks:", len(timer_callbacks), file=sys.stderr)
json.dump(timer_callbacks, open(f"{TMP}/timer_callbacks.json","w"))

# map: for each timer callback function, find plain spin_lock sites inside its body
func_locations = {}  # name -> list of (file, s, e)
for name, defs in functions.items():
    func_locations.setdefault(name, []).extend(defs)

# body reader
bodies = {}
def get_body(name, path, s, e):
    try:
        lines = open(os.path.join(ROOT, path), errors='replace').readlines()
        return "".join(lines[s-1:e])
    except Exception:
        return ""

candidates = []
for cb, (regfile, kind) in timer_callbacks.items():
    if cb not in func_locations:
        continue
    for (path, _start, s, e) in func_locations[cb]:
        # quick scan: find plain spin_lock within body
        try:
            lines = open(os.path.join(ROOT, path), errors='replace').readlines()[s-1:e]
        except Exception:
            continue
        for idx, ln in enumerate(lines):
            m = re.search(r'\bspin_lock\s*\(\s*(.*?)\s*\)', ln)
            if m:
                candidates.append((cb, path, s+idx, m.group(1), kind, regfile))

print("timer-callback plain spin_lock sites:", len(candidates), file=sys.stderr)
for c in candidates:
    print(c[0], c[1], c[2], c[3], c[4], "REG:"+c[5], sep=" | ")
json.dump(candidates, open(f"{TMP}/timer_plain_locks.json","w"))
