import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
SCAN_DIRS = ["drivers", "net"]

napi_re = re.compile(r"netif_napi_add(?:_weight)?\s*\(")
tasklet_re = re.compile(r"tasklet_(?:hi_)?schedule\s*\(|tasklet_init\s*\(|tasklet_setup\s*\(")
bh_lock_re = re.compile(r"spin_lock_bh\s*\(")

results = []
for scan_dir in SCAN_DIRS:
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, scan_dir)):
        for fn in filenames:
            if not fn.endswith(".c"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", errors="replace") as f:
                    text = f.read()
            except Exception:
                continue
            if not (napi_re.search(text) or tasklet_re.search(text)):
                continue
            lines = text.split("\n")
            plain_lines = []
            for i, ln in enumerate(lines):
                for m in re.finditer(r"spin_lock(?:_nested)?\s*\(\s*([^)&]+)", ln):
                    lockname = m.group(1).strip()
                    if lockname.startswith("&"):
                        lockname = lockname[1:]
                    plain_lines.append((i+1, lockname))
            n_plain = len(plain_lines)
            n_bh = len(bh_lock_re.findall(text))
            if n_plain > 0:
                rel = os.path.relpath(path, ROOT)
                locknames = {}
                for (ln_num, lockname) in plain_lines:
                    locknames.setdefault(lockname, []).append(ln_num)
                results.append((rel, n_plain, n_bh, locknames))

results.sort(key=lambda x: -x[1])
for rel, n_plain, n_bh, locknames in results[:70]:
    print(f"{rel}: plain={n_plain} bh={n_bh}")
    for k, v in sorted(locknames.items(), key=lambda kv: -len(kv[1]))[:6]:
        print(f"    {k}: {v[:14]}")
