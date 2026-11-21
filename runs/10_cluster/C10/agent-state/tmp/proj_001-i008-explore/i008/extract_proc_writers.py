import re, os, subprocess, json

S02 = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"

# files declaring struct proc_ops
files = [l.strip().lstrip('./') for l in open('procops_files.txt') if l.strip()]

result = {}
for f in files:
    p = os.path.join(S02, f)
    try:
        src = open(p, errors='replace').read()
    except Exception:
        continue
    # find proc_ops struct names and .proc_write = fn
    for m in re.finditer(r'\.proc_write\s*=\s*(\w+)', src):
        fn = m.group(1)
        result.setdefault(f, []).append(fn)

# also find proc_create / proc_mkdir style with file_operations .write (legacy proc fops)
legacy = {}
grep = subprocess.run(['grep', '-rn', '--include=*.c', '-E', r'proc_create(_data)?\(', S02], capture_output=True, text=True)
for line in grep.stdout.splitlines():
    parts = line.split(':', 3)
    if len(parts) < 4: continue
    f = os.path.relpath(parts[0], S02)
    legacy.setdefault(f, []).append(parts[3].strip()[:120])

json.dump({'procops_writers': result, 'proc_create_sites': {k: v[:8] for k, v in legacy.items()}}, open('proc_writers.json', 'w'), indent=1)
print("files with .proc_write:", len(result))
total = sum(len(v) for v in result.values())
print("total .proc_write handlers:", total)
for f, fns in sorted(result.items()):
    print(f, fns)
