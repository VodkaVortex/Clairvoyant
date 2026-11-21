import subprocess, re, os
S = "snapshots/s02"
pat = re.compile(r'(\w+)\s*=\s*(?:__)?(?:le16_to_cpu|be16_to_cpu|le32_to_cpu|be32_to_cpu|le64_to_cpu|be64_to_cpu|ntohs|ntohl|ntohll)\s*\(', re.I)
dirs = ["drivers","net","fs","kernel","mm","block","ipc","security","sound","crypto","virt"]
files = subprocess.run(["find"]+[os.path.join(S,d) for d in dirs]+["-name","*.c","-o","-name","*.h"],
                       capture_output=True, text=True).stdout.split()
hits = []
for f in files:
    try:
        with open(f, errors='ignore') as fh:
            for i, line in enumerate(fh, 1):
                m = pat.search(line)
                if m:
                    var = m.group(1)
                    if re.search(r'(num|count|nr|^n_|_n$|^n$|entries|segs|bufs|desc|frames|packets|reports|ops|blocks|chunks|vecs|iters|rows|cols|bits|slots|pins|queues|rates|tcs|elems)', var, re.I):
                        hits.append((f, i, line.rstrip()))
    except Exception:
        pass
print("TOTAL", len(hits))
for h in hits:
    print(f"{h[0]}:{h[1]}: {h[2][:170]}")
