import re, os, json

TMP = os.environ.get("TMPDIR", "/tmp")
cbs = json.load(open(TMP + "/tasklet_cbs.json"))
tlock = json.load(open(TMP + "/tasklet_locks.json"))

# Build map: for each tasklet callback lock, check whether the same lock expression
# is acquired with plain spin_lock( elsewhere in the same file
report = []
for r in tlock:
    f = r["file"]
    src = open(f, errors="ignore").read()
    for lk, full in r["locks"]:
        # plain spin_lock( with this lock
        pat = re.compile(r"spin_lock\s*\(\s*&?" + re.escape(lk))
        plain_sites = [src.count("\n", 0, m.start())+1 for m in pat.finditer(src)]
        # exclude sites inside tasklet body
        body_start = r["def_line"]
        # filter: keep only lines NOT between def_line and def_line+60
        plain_out = [p for p in plain_sites if not (body_start <= p <= body_start+80)]
        if plain_out:
            report.append({"file": f, "cb": r["cb"], "lock": lk, "plain_sites": plain_out[:10], "n": len(plain_out)})

json.dump(report, open(TMP + "/tasklet_plain_share.json", "w"), indent=1)
print(len(report), "shared-lock candidates")
for r in report:
    print(f'{r["file"]:70s} {r["cb"]:35s} {r["lock"]:30s} plain@{r["plain_sites"]} ({r["n"]})')
