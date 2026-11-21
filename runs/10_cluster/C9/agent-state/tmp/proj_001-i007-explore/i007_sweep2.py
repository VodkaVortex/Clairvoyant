import subprocess, re, os
S = "snapshots/s02"
pat = re.compile(r'copy_from_user\s*\(\s*&?[^,]*(num|count|nr_|_n$|^n$|entries|segs|bufs|len)', re.I)
pat2 = re.compile(r'(\w+)\s*=\s*nla_get_(?:u16|u32|u64|s32)\s*\(', re.I)
files = subprocess.run(["find", S, "-name", "*.c"], capture_output=True, text=True).stdout.split()
hits = []
for f in files:
    try:
        with open(f, errors='ignore') as fh:
            for i, line in enumerate(fh, 1):
                if pat.search(line):
                    hits.append((f, i, "CFU " + line.rstrip()))
                else:
                    m = pat2.search(line)
                    if m and re.search(r'(num|count|nr|entries|segs|bufs)', m.group(1), re.I):
                        hits.append((f, i, "NLA " + line.rstrip()))
    except Exception:
        pass
print("TOTAL", len(hits))
for h in hits:
    print(f"{h[0]}:{h[1]}: {h[2][:180]}")
