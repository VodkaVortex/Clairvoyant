import re, os, sys
root = "."
tasklet_files = []
for dirpath, dirs, files in os.walk(root):
    if "/.git" in dirpath: continue
    for f in files:
        if f.endswith((".c",".h")):
            p = os.path.join(dirpath, f)
            try: t = open(p, errors="ignore").read()
            except: continue
            if re.search(r"tasklet_schedule|tasklet_hi_schedule|tasklet_init", t):
                tasklet_files.append(p)
sys.stderr.write("files with tasklets: %d\n" % len(tasklet_files))
results = []
for p in tasklet_files:
    t = open(p, errors="ignore").read()
    lines = t.split("\n")
    # find tasklet_init calls: tasklet_init(&x->t, func, data) or DECLARE_TASKLET / DECLARE_TASKLET_OLD
    pairs = []
    for i, ln in enumerate(lines):
        m = re.search(r"tasklet_init\s*\(\s*&?[^,]+,\s*([A-Za-z_0-9]+)\s*,", ln)
        if m: pairs.append((m.group(1), i+1, "tasklet_init"))
        m = re.search(r"DECLARE_TASKLET(_OLD)?\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)\s*,", ln)
        if m: pairs.append((m.group(2), i+1, "DECLARE_TASKLET"))
        m = re.search(r"tasklet_setup\s*\(\s*&?[^,]+,\s*([A-Za-z_0-9]+)\s*\)", ln)
        if m: pairs.append((m.group(1), i+1, "tasklet_setup"))
    if not pairs: continue
    for fn, ln, kind in pairs:
        # find function def
        m = re.search(r"(?:^|\n)((?:[A-Za-z_0-9 \t\*]+\n)+[ \t]*%s\s*\()" % re.escape(fn), t)
        if not m:
            m = re.search(r"(?:^|\n)[A-Za-z_0-9 \t\*]*\b%s\s*\(" % re.escape(fn), t)
            if not m: continue
        start = t.find(m.group(0)) + len(m.group(0))
        # naive body capture: to matching close brace from first '{' after start
        b = t.find("{", start)
        if b < 0: continue
        depth = 0
        for j in range(b, len(t)):
            c = t[j]
            if c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: break
        body = t[b:j+1]
        nl = t[:b].count("\n")
        plain = re.findall(r"spin_lock\s*\(\s*&?([A-Za-z_0-9\.\->\[\]]+)", body)
        if plain:
            # line numbers of plain spin_lock in body
            plines = []
            bl = body.split("\n")
            for k, ln2 in enumerate(bl):
                if re.search(r"spin_lock\s*\(", ln2):
                    plines.append(nl + k + 1)
            results.append((p, fn, ln, plain, plines, len(body.split("\n"))))
for r in sorted(results):
    print("%s | tasklet fn %s (reg at %d) | plain spin_lock on %s at %s | body %d lines" % (r[0], r[1], r[2], ",".join(r[3][:6]), ",".join(map(str, r[4][:8])), r[5]))
