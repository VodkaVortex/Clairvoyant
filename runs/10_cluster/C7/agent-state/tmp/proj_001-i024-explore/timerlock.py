import re, os, sys, subprocess, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s09"

def find_files():
    out = subprocess.run(["/usr/bin/rg","-l",
        r"timer_setup\(|setup_timer\(|DEFINE_TIMER\(|\.function\s*=|hrtimer_init\(|DEFINE_TIMER",
        "drivers","net","kernel","mm","fs","block","ipc","security","sound","crypto","virt","io_uring","lib",
        "--type","c"], cwd=ROOT, capture_output=True, text=True)
    return [f for f in out.stdout.splitlines() if f]

# callback registration patterns
REG = [
    re.compile(r"timer_setup\(\s*&?[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"),
    re.compile(r"setup_timer\(\s*&?[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"),
    re.compile(r"DEFINE_TIMER\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"),
    re.compile(r"\.function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*,?\s*\n"),
    re.compile(r"hrtimer_init\([^;]*?;"),
]

LOCK = re.compile(r"spin_lock(?:_bh|_irqsave|_irq)?\(\s*&([A-Za-z_][A-Za-z0-9_.>\-]*)")
PLAIN = re.compile(r"spin_lock\(\s*&([A-Za-z_][A-Za-z0-9_.>\-]*)")

def func_body(src, name):
    # find definition: name(...) at start of line-ish, followed by {
    pat = re.compile(r"(?:^|\n)[A-Za-z_][A-Za-z0-9_ \t\*]*\b" + re.escape(name) + r"\s*\([^;{]*?\)\s*\{")
    m = pat.search(src)
    if not m:
        # static inline / __always_inline variants
        pat = re.compile(r"(?:^|\n).*?\b" + re.escape(name) + r"\s*\([^;{]*?\)\s*\{")
        m = pat.search(src)
        if not m:
            return None, None, None
    start = src.find("{", m.start())
    depth = 0
    i = start
    while i < len(src):
        c = src[i]
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return start, src[start:i+1], src[:start].count("\n")+1
        i += 1
    return start, src[start:], src[:start].count("\n")+1

results = []
files = find_files()
print(f"files with timer registrations: {len(files)}", file=sys.stderr)
for rel in files:
    try:
        src = open(os.path.join(ROOT, rel), errors="replace").read()
    except Exception:
        continue
    callbacks = set()
    for rx in REG:
        for m in rx.finditer(src):
            for g in m.groups():
                if g and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", g):
                    callbacks.add(g)
    if not callbacks: continue
    for cb in callbacks:
        # only consider functions defined in this file
        s, body, lineno = func_body(src, cb)
        if body is None: continue
        locks = LOCK.findall(body)
        plainlocks = PLAIN.findall(body)
        if locks:
            results.append((rel, lineno, cb, sorted(set(locks)), sorted(set(plainlocks))))

for rel, lineno, cb, locks, plain in results:
    print(f"{rel}:{lineno} TIMER_CB {cb} locks={locks} plain_in_timer={plain}")
