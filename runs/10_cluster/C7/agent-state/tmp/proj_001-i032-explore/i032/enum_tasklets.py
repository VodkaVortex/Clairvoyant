import os, re, subprocess

root = "."
# 1. Find tasklet callback names from tasklet_setup / tasklet_init
tasklet_cbs = {}   # name -> (file, line of registration)
napi_polls = {}    # name -> (file, line of registration via netif_napi_add)

pat_tsetup = re.compile(r'tasklet_setup\(\s*&?[\w\->.\[\]]+,\s*(\w+)\s*\)')
pat_tinit  = re.compile(r'tasklet_init\(\s*&?[\w\->.\[\]]+,\s*(\w+)\s*,')
pat_napi   = re.compile(r'netif_napi_add(?:_weight)?\(\s*[^;]*?,\s*(\w+)\s*,')

scan_dirs = ["drivers", "net"]
for d in scan_dirs:
    for dirpath, dirs, files in os.walk(d):
        for f in files:
            if not f.endswith((".c", ".h")):
                continue
            p = os.path.join(dirpath, f)
            try:
                with open(p, errors="ignore") as fh:
                    for i, line in enumerate(fh, 1):
                        for m in pat_tsetup.finditer(line):
                            tasklet_cbs.setdefault(m.group(1), []).append((p, i, "tasklet_setup"))
                        for m in pat_tinit.finditer(line):
                            tasklet_cbs.setdefault(m.group(1), []).append((p, i, "tasklet_init"))
                        for m in pat_napi.finditer(line):
                            napi_polls.setdefault(m.group(1), []).append((p, i, "netif_napi_add"))
            except OSError:
                pass

# Also .ndo_start_xmit exclusion isn't needed here; and function bodies of tasklet cbs / napi polls
def body_of(name):
    # find definition via rg
    try:
        out = subprocess.run(["rg", "-n", "--no-heading", r"^(?:static\s+)?(?:inline\s+)?(?:\w[\w\s\*]*?)\b" + re.escape(name) + r"\s*\(", "drivers", "net"],
                             capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return None
    return out

print("=== TASKLET CANDIDATES (callback containing plain spin_lock) ===")
for name in sorted(tasklet_cbs):
    regs = tasklet_cbs[name]
    defs = subprocess.run(["rg", "-n", "--no-heading", "-A", "80", r"^[a-zA-Z_][\w\s\*]*\b" + re.escape(name) + r"\s*\([^;]*$", "drivers", "net"], capture_output=True, text=True).stdout
    # crude: check for spin_lock( without _bh/_irqsave within the chunk
    if "spin_lock(" in defs or "spin_lock_nested" in defs:
        has_bh = ("spin_lock_bh" in defs) or ("local_bh_disable" in defs)
        print(f"--- {name} registered at {regs[:3]}")
        print(f"    plain_spin_lock=yes bh_in_chunk={has_bh}")
print()
print("=== NAPI POLL CANDIDATES ===")
for name in sorted(napi_polls):
    regs = napi_polls[name]
    defs = subprocess.run(["rg", "-n", "--no-heading", "-A", "120", r"^[a-zA-Z_][\w\s\*]*\b" + re.escape(name) + r"\s*\([^;]*$", "drivers", "net"], capture_output=True, text=True).stdout
    if "spin_lock(" in defs or "spin_lock_nested" in defs:
        has_bh = ("spin_lock_bh" in defs) or ("local_bh_disable" in defs)
        print(f"--- {name} registered at {regs[:3]}")
        print(f"    plain_spin_lock=yes bh_in_chunk={has_bh}")
