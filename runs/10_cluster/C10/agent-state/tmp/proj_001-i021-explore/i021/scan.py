import subprocess, re, os, json

hits = {}
for line in open(os.path.join(os.environ["T"], "hits.txt")):
    line = line.strip()
    if not line: continue
    f, ln = line.rsplit(":", 1)
    hits.setdefault(f, []).append(int(ln))

results = []
for f, lns in hits.items():
    try:
        with open(f, "r", errors="replace") as fh:
            src = fh.readlines()
    except OSError:
        continue
    for ln in lns:
        # context window: 25 lines before, 3 after
        lo = max(0, ln - 26); hi = min(len(src), ln + 3)
        ctx = "".join(src[lo:hi])
        # must contain a usercopy or write-buffer helper in the window
        if not re.search(r"copy_from_user|__copy_from_user|simple_write_to_buffer|proc_dostring|copy_from_iter|memcpy\(.*,\s*buf\b", ctx):
            continue
        # find clamp or bound-check lines and the buffer decl
        clamp = re.findall(r"(min_t\([^;]*?\)|min\([^;]*?\))", ctx)
        decl = re.findall(r"(\w+\s+\w+\[\s*(\w+)\s*(\*\s*\d+)?\s*\])", ctx)
        results.append({"file": f, "line": ln, "clamps": clamp[:3], "decls": [d[0] for d in decl[:3]]})

with open(os.path.join(os.environ["T"], "scan.json"), "w") as out:
    json.dump(results, out, indent=1)
print(len(results))
