import re, os, subprocess, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"

# Step 1: find all NAPI poll function names wired via netif_napi_add(...)
napi_polls = {}   # pollfn -> list of (file, line)
napi_calls = []   # (file, line, pollfn)
out = subprocess.run(["/usr/bin/rg", "-n", "--no-heading", "-g", "*.c",
                      r"netif_napi_add", "drivers", "net"],
                     cwd=ROOT, capture_output=True, text=True).stdout
for line in out.splitlines():
    m = re.match(r"([^:]+):(\d+):(.*)", line)
    if not m: continue
    f, ln, txt = m.group(1), int(m.group(2)), m.group(3)
    # netif_napi_add(dev, &napi, poll_fn, weight)
    mm = re.search(r"netif_napi_add(?:_exclusive|_weight|_irq)?\s*\(([^;]*)", txt)
    if not mm: continue
    args = mm.group(1)
    parts = [p.strip() for p in args.split(",")]
    # poll fn is typically 3rd arg
    fn = None
    for p in parts[1:4]:
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", p) and p not in ("NAPI_POLL_WEIGHT",):
            if parts.index(p) >= 1:
                fn = p; break
    if fn:
        napi_polls.setdefault(fn, []).append((f, ln))
        napi_calls.append((f, ln, fn))

print(f"NAPI poll fns found: {len(napi_polls)}")

# Step 2: find tasklet callbacks wired via tasklet_init/tasklet_setup/DECLARE_TASKLET
tasklet_cbs = {}
out2 = subprocess.run(["/usr/bin/rg", "-n", "--no-heading", "-g", "*.c",
                       r"tasklet_init\s*\(|tasklet_setup\s*\(|DECLARE_TASKLET", "drivers", "net"],
                      cwd=ROOT, capture_output=True, text=True).stdout
for line in out2.splitlines():
    m = re.match(r"([^:]+):(\d+):(.*)", line)
    if not m: continue
    f, ln, txt = m.group(1), int(m.group(2)), m.group(3)
    mm = re.search(r"tasklet_(?:init|setup)\s*\([^,]+,\s*([a-zA-Z_][a-zA-Z0-9_]*)", txt)
    if mm:
        tasklet_cbs.setdefault(mm.group(1), []).append((f, ln))
        continue
    mm = re.search(r"DECLARE_TASKLET(?:_DISABLED)?\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)", txt)
    if mm:
        tasklet_cbs.setdefault(mm.group(2), []).append((f, ln))

print(f"tasklet cbs found: {len(tasklet_cbs)}")

# Step 3: extract function bodies for all these callbacks, look for plain spin_lock
def extract_body(fname, fn):
    path = os.path.join(ROOT, fname)
    try:
        src = open(path, errors="replace").read()
    except OSError:
        return None, None
    # find definition: fn(...) {  ... may be multi-line signature
    pat = re.compile(r"^[ \t]*(?:static\s+)?(?:inline\s+)?(?:void|int|irqreturn_t|u\d+|unsigned|long|bool)\s+" + re.escape(fn) + r"\s*\(", re.M)
    m = pat.search(src)
    if not m:
        pat2 = re.compile(r"^[ \t]*" + re.escape(fn) + r"\s*\(", re.M)
        m = pat2.search(src)
        if not m:
            return None, None
    start = m.start()
    # find opening brace after signature
    bidx = src.find("{", m.end())
    if bidx == -1: return None, None
    depth = 0
    i = bidx
    while i < len(src):
        c = src[i]
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: break
        i += 1
    body = src[bidx:i+1]
    line_no = src[:start].count("\n") + 1
    return body, line_no

results = []
for kind, cmap in (("napi", napi_polls), ("tasklet", tasklet_cbs)):
    for fn, sites in cmap.items():
        for (f, ln) in sites:
            body, defline = extract_body(f, fn)
            if body is None: continue
            if "spin_lock" not in body: continue
            # find plain spin_lock( (not _bh, _irq, _irqsave, _nested...)
            plain = re.findall(r"spin_lock(?:_nested(?:_irqsave)?)?\s*\(\s*([^;]+?)\s*\)", body)
            plain = [p for p in plain if "flags" not in p.split(",")[-1:][0][:40] or True]
            bh = re.findall(r"spin_lock_bh\s*\(", body)
            irq = re.findall(r"spin_lock_irq(?:save)?\s*\(", body)
            if plain:
                results.append({
                    "kind": kind, "fn": fn, "file": f, "reg_line": ln, "def_line": defline,
                    "plain_locks": plain, "bh_sites": len(bh), "irq_sites": len(irq),
                })

print(f"callbacks with plain spin_lock in body: {len(results)}")
for r in results:
    print(f"[{r['kind']}] {r['fn']}  {r['file']}:{r['def_line']} (reg@{r['reg_line']}) plain={r['plain_locks']} bh={r['bh_sites']} irq={r['irq_sites']}")

with open(os.path.join(os.environ.get("TMPDIR","/tmp"), "i032", "scan_results.json"), "w") as fh:
    json.dump(results, fh, indent=2)
