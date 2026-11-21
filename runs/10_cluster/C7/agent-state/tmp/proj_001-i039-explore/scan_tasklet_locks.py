import re, subprocess, sys, os, json

res = subprocess.run(["grep", "-rln", "tasklet_init\\|tasklet_setup\\|DECLARE_TASKLET", "drivers/", "net/"], capture_output=True, text=True)
files = res.stdout.strip().split("\n")
out = {}
for f in files:
    if not f.endswith(".c") and not f.endswith(".h"):
        continue
    src = open(f, errors="ignore").read()
    # find tasklet callback definitions: tasklet_init(&X, fn,...) or tasklet_setup(&X, fn) or DECLARE_TASKLET(name, fn)
    cb = set()
    for m in re.finditer(r"tasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)", src):
        cb.add(m.group(1))
    for m in re.finditer(r"tasklet_setup\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)", src):
        cb.add(m.group(1))
    for m in re.finditer(r"DECLARE_TASKLET[A-Z_]*\s*\(\s*[A-Za-z_0-9]+\s*,\s*([A-Za-z_0-9]+)", src):
        cb.add(m.group(1))
    if cb:
        out[f] = sorted(cb)
json.dump(out, open(os.environ.get("TMPDIR","/tmp") + "/tasklet_cbs.json", "w"), indent=1)
print(len(out), "files with tasklet callbacks")
