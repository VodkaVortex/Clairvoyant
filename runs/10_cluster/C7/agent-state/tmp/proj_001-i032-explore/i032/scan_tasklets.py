import re, os, sys, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
# collect .c files
cfiles = []
for base in ["drivers", "net", "kernel", "mm", "fs", "block", "ipc", "security", "lib", "sound", "crypto", "virt", "arch"]:
    for dirpath, dirs, files in os.walk(os.path.join(ROOT, base)):
        for f in files:
            if f.endswith(".c"):
                cfiles.append(os.path.join(dirpath, f))
print("cfiles:", len(cfiles), file=sys.stderr)

tasklet_re = re.compile(r'\b(tasklet_init|tasklet_setup)\s*\(\s*&?[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]')
declare_re = re.compile(r'DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')

# funcname -> list of (file, line, taskletvar)
tasklet_callbacks = {}
for cf in cfiles:
    try:
        with open(cf, "r", errors="replace") as fh:
            src = fh.read()
    except OSError:
        continue
    for m in tasklet_re.finditer(src):
        line = src[:m.start()].count("\n") + 1
        tasklet_callbacks.setdefault(m.group(2), []).append((os.path.relpath(cf, ROOT), line, "tasklet_init/setup"))
    for m in declare_re.finditer(src):
        line = src[:m.start()].count("\n") + 1
        tasklet_callbacks.setdefault(m.group(2), []).append((os.path.relpath(cf, ROOT), line, "DECLARE_TASKLET"))

print("tasklet callbacks:", len(tasklet_callbacks), file=sys.stderr)

# find function definition and extract body (handles both styles)
def find_body(src, name):
    # match return-type ... name(args) newline? {
    pat = re.compile(r'\b' + re.escape(name) + r'\s*\([^;{]*?\)\s*\{', re.S)
    for m in pat.finditer(src):
        start = m.end()
        depth = 1
        i = start
        while i < len(src) and depth > 0:
            c = src[i]
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            i += 1
        line = src[:m.start()].count("\n") + 1
        return src[m.start():i], line
    return None, None

results = []
for fname, sites in tasklet_callbacks.items():
    # search files for definition
    for cf in set(s[0] for s in sites):
        path = os.path.join(ROOT, cf)
        try:
            with open(path, "r", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        body, defline = find_body(src, fname)
        if body is None:
            continue
        if re.search(r'\bspin_lock\s*\(', body):
            locks = sorted(set(re.findall(r'spin_lock\s*\(\s*&?([^)]+)\)', body)))
            locks = [l.split(',')[-1].strip() for l in locks]
            results.append((cf, defline, fname, sites, sorted(set(locks))))
        break

print("=== TASKLET callbacks taking plain spin_lock ===")
for cf, defline, fname, sites, locks in sorted(results):
    print(f"{cf}:{defline} func={fname} locks={locks} registered_at={sites}")
print(f"total: {len(results)}")
