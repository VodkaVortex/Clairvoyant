import re, os, json, sys

TMP = os.environ.get("TMPDIR", "/tmp")
cbs = json.load(open(TMP + "/tasklet_cbs.json"))

results = []
for f, funcs in cbs.items():
    if not f.endswith(".c"):
        continue
    try:
        src = open(f, errors="ignore").read()
    except Exception:
        continue
    lines = src.split("\n")
    for fn in funcs:
        # find function definition (best effort)
        for i, l in enumerate(lines):
            m = re.match(r"^(?:static\s+)?(?:void|int|irqreturn_t|unsigned long|long)\s+" + re.escape(fn) + r"\s*\(", l)
            if m:
                # capture function body with brace matching
                depth = 0; started = False; body = []
                for j in range(i, min(i+400, len(lines))):
                    body.append((j+1, lines[j]))
                    depth += lines[j].count("{") - lines[j].count("}")
                    if "{" in lines[j]:
                        started = True
                    if started and depth == 0:
                        break
                # locks taken in tasklet body
                locks = set()
                for ln, bl in body:
                    for mm in re.finditer(r"spin_lock(?:_irqsave|_irq|_bh)?\s*\(\s*&?([A-Za-z_0-9>\.\-]+)", bl):
                        locks.add((mm.group(1), mm.group(0)))
                if locks:
                    results.append({"file": f, "cb": fn, "def_line": i+1, "locks": sorted(locks)})
                break

json.dump(results, open(TMP + "/tasklet_locks.json", "w"), indent=1)
print(len(results), "tasklet callbacks taking spinlocks")
for r in results[:200]:
    print(r["file"], r["cb"], "line", r["def_line"], [x[0] for x in r["locks"]])
