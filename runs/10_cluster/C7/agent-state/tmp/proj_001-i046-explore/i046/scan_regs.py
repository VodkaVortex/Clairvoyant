import sys
Tree = sys.argv[1]
import os, re, glob
exts = (".c",".h")
files = [os.path.join(dp,f) for dp,_,fs in os.walk(Tree) for f in fs if f.endswith(exts)]
# whitelist of top-level dirs that contain devices with hardirq handlers
pref = ("drivers/","sound/","net/","fs/","kernel/","mm/","block/","crypto/","lib/","arch/","ipc/","security/")
regs = {}
for fp in files:
    rel = os.path.relpath(fp, Tree)
    if not rel.startswith(pref): continue
    try: src = open(fp, encoding="utf-8", errors="replace").read()
    except: continue
    for m in re.finditer(r"\b(?:devm_)?request(?:_threaded|_any|_percpu|_noprobe|_pirq)?_irq(?:_exclusive|_arrays|_resources|_free)?\s*\(", src):
        regs.setdefault(rel, 0)
        regs[rel] += 1
out = open("irq_files.txt","w")
for k,v in sorted(regs.items(), key=lambda x:-x[1]): out.write(f"{v}\t{k}\n")
out.close()
print(len(regs), "files with irq requests")
