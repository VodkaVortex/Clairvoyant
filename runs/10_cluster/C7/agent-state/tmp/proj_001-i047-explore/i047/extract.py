#!/usr/bin/env python3
"""Extract request_irq registration sites and their handler names from C sources.
Then for each handler, find plain spin_lock acquisitions inside the handler function
body, and cross-index with plain spin_lock acquisitions elsewhere in the same file.
"""
import re, os, sys, json, subprocess
from collections import defaultdict

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
T = os.environ.get("TMPDIR", "/tmp") + "/i047"

# 1) Parse irq registration sites: file:line:content
sites = []
with open(T + "/irq_sites.txt") as f:
    for line in f:
        m = re.match(r"(.+?):(\d+):(.*)", line.rstrip("\n"))
        if not m:
            continue
        path, ln, content = m.group(1), int(m.group(2)), m.group(3)
        # find handler arg. For request_irq(irq, handler, flags, name, dev)
        # for request_threaded_irq(irq, handler, thread_fn, flags, name, dev)
        # Capture the function args region (may span lines; here handle single line + continue below)
        sites.append((path, ln, content))

# Build per-file line arrays to join multiline calls
files_lines = {}
def get_lines(path):
    if path not in files_lines:
        try:
            with open(os.path.join(ROOT, path), errors="replace") as f:
                files_lines[path] = f.readlines()
        except OSError:
            files_lines[path] = []
    return files_lines[path]

handlers = []  # (file, regline, handlername, kind)
for path, ln, content in sites:
    lines = get_lines(path)
    idx = ln - 1
    if idx >= len(lines):
        continue
    # join up to 8 lines from the call start
    blob = "".join(lines[idx:idx+8])
    # remove comments
    blob = re.sub(r"/\*.*?\*/", " ", blob, flags=re.S)
    # normalize
    blob = blob.replace("\n", " ")
    m = re.search(r"request_threaded_irq\s*\(", blob)
    kind = None
    if m:
        kind = "threaded"
        start = m.end()
    else:
        m = re.search(r"(?:devm_)?request_irq\s*\(", blob)
        if m:
            kind = "plain"
            start = m.end()
        else:
            continue
    # take balanced parens content
    depth = 1
    i = start
    args = []
    cur = []
    while i < len(blob) and depth > 0:
        c = blob[i]
        if c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                break
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if len(args) < 2:
        continue
    if kind == "plain":
        handler = args[1].strip()
    else:
        handler = args[1].strip()
    # strip casts
    handler = re.sub(r"^\(.*?\)\s*", "", handler).strip()
    handler = handler.split()[-1] if handler else ""
    # clean trailing chars
    handler = handler.strip("&()").strip()
    if not handler:
        continue
    handlers.append((path, ln, handler, kind))

print("parsed handler registrations:", len(handlers))
with open(T + "/handlers.txt", "w") as f:
    for path, ln, h, kind in handlers:
        f.write(f"{path}\t{ln}\t{h}\t{kind}\n")

# distinct handler names
names = defaultdict(set)
for path, ln, h, kind in handlers:
    names[h].add(path)
print("distinct handler identifiers:", len(names))
