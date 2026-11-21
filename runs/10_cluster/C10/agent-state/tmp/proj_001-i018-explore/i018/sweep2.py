import re, os

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s01"
out = os.path.join(os.environ.get("TMPDIR","/tmp"), "i018")
os.makedirs(out, exist_ok=True)

files = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in (".git","tools","Documentation","samples","scripts","rust")]
    for fn in filenames:
        if fn.endswith((".c",".h")):
            files.append(os.path.join(dirpath, fn))

# Terminator write: NAME[idx] = 0 or '\0'; idx is an identifier (not constant)
term_re = re.compile(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(?:0|\'\\0\'|\'\\n\'|0x00)\s*;')
# Clamp or check assigning/limiting idx
clamp_re = re.compile(r'(\w+)\s*=\s*(?:min_t\s*\(\s*\w+\s*,\s*|min\s*\()')
# check pattern: if (count > N) reject  /  if (count >= N) reject
check_re = re.compile(r'if\s*\(\s*(\w+)\s*(>=|>|<=|<)\s*')

results = []
for fp in files:
    try:
        with open(fp, errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        continue
    for i, line in enumerate(lines):
        for tm in term_re.finditer(line):
            idx = tm.group(2)
            if idx in ("0","1"): continue
            base = tm.group(1)
            # find how idx was computed in previous 30 lines
            origin = None
            for j in range(i-1, max(i-31, -1), -1):
                l2 = lines[j]
                m2 = re.search(r'\b' + re.escape(idx) + r'\s*=\s*(.{0,80})', l2)
                if m2:
                    origin = (j+1, m2.group(1).strip()[:90])
                    break
                # also check-form constraints on idx
                m3 = re.search(r'if\s*\(\s*' + re.escape(idx) + r'\s*(>=|>|<|<=)\s*([^)]{1,60})\)', l2)
                if m3:
                    origin = (j+1, "CHECK " + m3.group(0).strip()[:90])
                    break
            results.append((os.path.relpath(fp, root), i+1, tm.group(0).strip()[:70], origin))

with open(os.path.join(out, "sweep2_results.txt"), "w") as f:
    for r in results:
        f.write(f"{r[0]}:{r[1]} TERM {r[2]}")
        if r[3]:
            f.write(f" || idx-origin line {r[3][0]}: {r[3][1]}")
        f.write("\n")
print(f"total terminator writes with variable index: {len(results)}")
