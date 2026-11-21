import os, re, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"

# Pass 1: read all .c/.h files, store lines
files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if fn.endswith((".c", ".h")):
            files.append(os.path.join(dirpath, fn))
print("files:", len(files))

src = {}
for f in files:
    try:
        with open(f, "r", errors="replace") as fh:
            src[f] = fh.read().splitlines()
    except Exception:
        pass

# Pass 2: build function definition index per file
# crude: track brace depth; a definition starts at a line matching a func
# signature at depth 0.
funcdefs = {}  # fname -> list of (file, startline, endline) (0-based)
funcname_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*[\s\*]+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
for f, lines in src.items():
    depth = 0
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if depth == 0:
            m = funcname_re.match(line)
            if m and not line.lstrip().startswith(("#", "//", "*", "/*")):
                # find the opening brace on this or subsequent lines
                j = i
                sig_end = None
                while j < min(i+8, n):
                    if "{" in lines[j]:
                        sig_end = j
                        break
                    if ";" in lines[j] and "(" not in lines[j]:
                        break
                    j += 1
                if sig_end is not None and sig_end < i+8:
                    fname = m.group(1)
                    # skip control keywords
                    if fname not in ("if","for","while","switch","return","sizeof","else","do"):
                        # walk to matching close brace
                        d = 0
                        k = i
                        started = False
                        while k < n:
                            d += lines[k].count("{") - lines[k].count("}")
                            if "{" in lines[k]:
                                started = True
                            if started and d == 0:
                                break
                            k += 1
                        funcdefs.setdefault(fname, []).append((f, i, k))
        d2 = 0
        i += 1

print("funcdefs names:", len(funcdefs))

# Pass 3: find tasklet callback names and napi poll names
tasklet_cbs = {}   # cbname -> list of (file, line) where registered
napi_polls = {}

re_tasklet_init = re.compile(r'\btasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
re_tasklet_setup = re.compile(r'\btasklet_setup\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')
re_decl_tasklet = re.compile(r'\bDECLARE_TASKLET(?:_OLD)?\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
re_napi_add = re.compile(r'\bnetif_napi_add(?:_hw)?\s*\(')

for f, lines in src.items():
    for idx, line in enumerate(lines):
        for m in re_tasklet_init.finditer(line):
            tasklet_cbs.setdefault(m.group(1), []).append((f, idx, "tasklet_init"))
        for m in re_tasklet_setup.finditer(line):
            tasklet_cbs.setdefault(m.group(1), []).append((f, idx, "tasklet_setup"))
        for m in re_decl_tasklet.finditer(line):
            tasklet_cbs.setdefault(m.group(2), []).append((f, idx, "DECLARE_TASKLET"))
        for m in re_napi_add.finditer(line):
            args = line[line.find('('):]
            parts = args.split(',')
            if len(parts) >= 4:
                poll = parts[2].strip().lstrip('&').strip()
                poll = re.sub(r'^&', '', parts[2].strip())
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', poll):
                    napi_polls.setdefault(poll, []).append((f, idx))

json.dump({
  "tasklet_cbs": {k: [[os.path.relpath(a[0], ROOT), a[1]+1, a[2]] for a in v] for k, v in tasklet_cbs.items()},
  "napi_polls": {k: [[os.path.relpath(a[0], ROOT), a[1]+1] for a in v] for k, v in napi_polls.items()},
}, open(os.path.join(os.environ.get("TMPDIR","/tmp"), "softirq_cbs.json"), "w"), indent=0)
json.dump({k: [[os.path.relpath(x[0], ROOT), x[1]+1, x[2]+1] for x in v] for k, v in funcdefs.items()},
          open(os.path.join(os.environ.get("TMPDIR","/tmp"), "funcdefs.json"), "w"))
print("tasklet cbs:", len(tasklet_cbs), " napi polls:", len(napi_polls))
