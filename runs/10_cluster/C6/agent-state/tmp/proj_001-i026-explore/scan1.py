#!/usr/bin/env python3
# Interprocedural callee-pull caller-stale scan for s05:
# For each .c file in net/ and drivers/, find functions that contain a
# head-relocating call (pskb_may_pull etc.) but which are *called* by other
# functions. Too broad; instead: find all functions containing a relocating
# call whose name suggests validator/helper, then list their callers.
import os, re, sys

ROOT = "."
RELOC = re.compile(r"\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|ip_mc_may_pull|ipv6_mc_may_pull)\s*\(")

files = []
for base in ("net", "drivers"):
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, base)):
        for f in filenames:
            if f.endswith(".c"):
                files.append(os.path.join(dirpath, f))

func_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$")

def functions(text):
    """Yield (name, start, end) of top-level function bodies by brace matching."""
    lines = text.split("\n")
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        # find function definition start: line ending with '{' or next line '{'
        sig = line
        j = i
        while j < n and "{" not in lines[j] and ";" not in lines[j] and j - i < 6:
            j += 1
        if j < n and "{" in lines[j]:
            # candidate definition; extract name from first identifier before '('
            m2 = re.match(r"^[\t ]*(?:static\s+|inline\s+|const\s+|unsigned\s+|struct\s+[A-Za-z0-9_]+\s*\*?\s*)*([A-Za-z_][A-Za-z0-9_]*)\s*\(", sig)
            name = None
            mm = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", sig)
            # filter keywords
            kws = {"if","for","while","switch","return","sizeof","else","do","case"}
            cands = [x for x in mm if x not in kws]
            if cands:
                name = cands[-1] if len(cands)==1 or cands[-1] not in kws else cands[0]
            # brace match from j
            depth = 0
            k = j
            started = False
            while k < n:
                for ch in lines[k]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                        if started and depth == 0:
                            yield (name, i, k)
                            i = k + 1
                            break
                else:
                    k += 1
                    continue
                break
            else:
                i = j + 1
                continue
            continue
        i = max(j, i + 1)

results = []
for path in files:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    lines = text.split("\n")
    for (name, s, e) in functions(text):
        body = "\n".join(lines[s:e+1])
        if name and RELOC.search(body):
            results.append((path, name, s+1, e+1))

print(len(results), "functions with relocating calls")
# save
with open(sys.argv[1] if len(sys.argv)>1 else "funcs.txt","w") as fh:
    for r in results:
        fh.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\n")
