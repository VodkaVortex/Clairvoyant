import re, json, subprocess
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"

hl = json.load(open("handler_locks.json"))
ps = json.load(open("plain_sites.json"))

rows=[]
for path, hs in hl.items():
    if path not in ps: continue
    plain = ps[path]["plain"]
    for h in hs:
        for (l, expr) in h["locks"]:
            # count plain sites in file with same canonical expr
            same = [(pl, pe) for (pl,pe) in plain if pe == expr]
            # count irqsave variants of same expr in file via rg later
            rows.append({
                "path": path.replace(ROOT+"/",""),
                "handler": h["handler"], "handler_line": h["handler_line"],
                "reg_line": h["reg_line"], "reg_fn": h["reg_fn"],
                "lock": expr, "lock_line": l,
                "plain_sites": [s[0] for s in same],
            })
rows.sort(key=lambda r: -(len(r["plain_sites"])))
json.dump(rows, open("rows.json","w"))
for r in rows[:60]:
    print(f'{r["path"]}:{r["handler"]}(L{r["handler_line"]},reg {r["reg_fn"]}:{r["reg_line"]}) lock={r["lock"]}@{r["lock_line"]} plain_sites={r["plain_sites"][:14]}')
