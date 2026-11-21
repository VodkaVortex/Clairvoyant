import re, os, subprocess

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s01"
out = "$TMPDIR/i018".replace("$TMPDIR", os.environ.get("TMPDIR","/tmp"))
os.makedirs(out, exist_ok=True)

# find C files
files = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in (".git","tools","Documentation","samples","scripts","rust")]
    for fn in filenames:
        if fn.endswith((".c",".h")):
            files.append(os.path.join(dirpath, fn))

# Pattern A: X = min*(..., sizeof(BUF))  (bare sizeof, no -1)  -- then look for TERM[X] = 0 within 25 lines
clamp_re = re.compile(
    r'(\w+)\s*=\s*(?:min_t\s*\([^;{=]*?|min\s*\()'
    r'[;{=]*\s*(?:size_t\s*,\s*|u32\s*,\s*|int\s*,\s*|unsigned\s+int\s*,\s*|long\s*,\s*)?'
    r'(count|len|size|cnt|nbytes|buflen|datalen|length|bytes|n|count_left|user_len)\s*'
    r'([^;{=]*?)\)\s*;')

term_re = re.compile(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(?:0|\'\\0\'|\'\\n\'|0x00)\s*;')

results = []
for fp in files:
    try:
        with open(fp, errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        continue
    for i, line in enumerate(lines):
        m = clamp_re.search(line)
        if not m: continue
        var = m.group(1)
        rest = m.group(3)
        # bare sizeof without -1 (allow +1 which would be allocation; still flag separately)
        if "sizeof" not in rest: continue
        if re.search(r'sizeof\([^)]*\)\s*-\s*\d', rest): continue  # has -N, safe
        # look ahead for terminator write using var
        window = lines[i+1:i+26]
        for j, wl in enumerate(window):
            tm = term_re.search(wl)
            if tm and tm.group(2) == var:
                results.append((os.path.relpath(fp, root), i+1, var, m.group(2), rest.strip(), i+2+j, wl.strip()))
                break

with open(os.path.join(out, "sweep1_results.txt"), "w") as f:
    for r in results:
        f.write(f"{r[0]}:{r[1]} clamp {r[2]} = min*({r[3]}, {r[4]}) ; TERM at {r[5]}: {r[6]}\n")
print(f"total: {len(results)}")
for r in results:
    print(f"{r[0]}:{r[1]} {r[2]}={r[3]},{r[4]} -> line {r[5]}: {r[6]}")
