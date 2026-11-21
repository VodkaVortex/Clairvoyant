#!/usr/bin/env python3
import re, json, os, sys

rep = json.load(open(os.path.join(os.environ["TMPDIR"], "hardirq_report.json")))
out = []
for e in rep:
    f = e["file"]
    try:
        lines = open(f, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        continue
    # find handler def and body range
    sig = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:irqreturn_t\s+)?[A-Za-z_][\w\s\*]*?\b' + re.escape(e["handler"]) + r'\s*\(')
    defidx = None
    for i, l in enumerate(lines):
        if sig.match(l):
            defidx = i; break
    if defidx is None: continue
    depth = 0; started=False; end = defidx
    j = defidx
    while j < len(lines) and j < defidx + 400:
        l = lines[j]
        depth += l.count("{") - l.count("}")
        if "{" in l: started = True
        if started and depth <= 0:
            end = j; break
        j += 1
    body = set(range(defidx, end+1))
    other = [ln for ln in e["plain_sites_same_file"] if (ln-1) not in body]
    if not other: continue
    # classify enclosing function for each other site
    func_starts = []
    fsig = re.compile(r'^(?:static\s+|inline\s+)*(?:const\s+)?[A-Za-z_][\w\s\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    for i, l in enumerate(lines):
        m = fsig.match(l)
        if m and not l.strip().endswith(";") and not l.strip().startswith("#"):
            func_starts.append((i, m.group(1)))
    def encl(ln):
        name = "?"
        for (i, n) in func_starts:
            if i < ln-1: name = n
            else: break
        return name
    out.append({"file": f, "handler": e["handler"], "lock": e["key"],
                "handler_lock_line": e["handler_lock_line"],
                "other_plain": [(ln, encl(ln)) for ln in other],
                "reg": e["register_sites"][:2]})
json.dump(out, open(os.path.join(os.environ["TMPDIR"], "refined.json"), "w"), indent=1)
print(len(out))
for e in out:
    if e["file"].startswith("./drivers/net") or e["file"].startswith("./drivers/usb") or e["file"].startswith("./drivers/staging") or e["file"].startswith("./drivers/tty"):
        print(e["file"], e["handler"], e["lock"], "hdl@", e["handler_lock_line"], "others:", e["other_plain"], e["reg"][:1])
