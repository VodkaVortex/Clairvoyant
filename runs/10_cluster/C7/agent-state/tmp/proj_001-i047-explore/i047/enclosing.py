#!/usr/bin/env python3
"""For each candidate file, print the enclosing function of each OTHER plain lock site."""
import re, os
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
T = os.environ.get("TMPDIR", "/tmp") + "/i047"

def enclosing(path, lineno):
    try:
        with open(os.path.join(ROOT, path), errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None
    # scan backwards from lineno for a line that looks like a function def start
    pat = re.compile(r"^[A-Za-z_][\w\s\*,\(\)]*?\b\w+\s*\([^;]*$")
    i = lineno - 1
    depth = 0
    # walk backwards counting braces to find function start
    for j in range(i, -1, -1):
        l = lines[j]
        # crude: find first '{' scanning back from target within same nesting
        if "{" in l:
            # check that this looks like a function opener: next non-empty after
            # find 'funcname(' on this or previous lines joined
            k = j
            blob = ""
            while k >= 0 and len(blob) < 400:
                blob = lines[k] + blob
                m = re.search(r"(\w+)\s*\([^;{}]*$", blob)
                if m:
                    name = m.group(1)
                    if name in ("if", "for", "while", "switch", "return", "sizeof", "else", "do"):
                        k -= 1
                        continue
                    return name
                k -= 1
            return "?"
    return "?"

# parse cross.tsv entries
entries = []
with open(T + "/cross.tsv") as f:
    cur = None
    for line in f:
        if not line.startswith(" "):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4:
                cur = {"path": parts[0], "lock": parts[1], "hp": parts[2], "op": parts[3], "os": parts[4], "others": [], "handlers": []}
                entries.append(cur)
        elif cur is not None:
            if line.startswith("  HANDLER"):
                cur["handlers"].append(line.strip())
            elif line.startswith("  OTHER"):
                m = re.match(r"\s+OTHER (\d+): (.*)", line)
                if m:
                    cur["others"].append((int(m.group(1)), m.group(2)))

with open(T + "/cross_enclosing.txt", "w") as f:
    for e in entries:
        f.write(f"== {e['path']}  lock={e['lock']}  {e['hp']} {e['op']} {e['os']}\n")
        for h in e["handlers"]:
            f.write(f"   {h}\n")
        for (ln, content) in e["others"]:
            fn = enclosing(e["path"], ln)
            f.write(f"   OTHER {ln} in {fn}(): {content}\n")
        f.write("\n")
print("done")
