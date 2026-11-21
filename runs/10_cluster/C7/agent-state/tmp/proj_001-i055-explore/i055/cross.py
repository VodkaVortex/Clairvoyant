import json, os, collections, re
d=json.load(open("scan.json"))
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11"
hl=d["handler_locks"]; plain=d["plain_locks"]; allL=d["all_locks"]

def base(lock):
    return lock.strip().lstrip("&").split(".")[-1].split("->")[-1].strip()

# plain handler locks grouped by (file, lockbase)
hplain=collections.defaultdict(list)
for rel,handler,ln,kind,lock,sites in hl:
    if kind in ("spin_lock","raw_spin_lock"):
        hplain[(rel,base(lock))].append((ln,handler,lock))

rows=[]
for (rel,lb),hsites in hplain.items():
    # non-handler plain acquisitions in same file with same base
    others=[(ln,lock) for ln,lock in plain.get(rel,[]) if not any(ln==h[0] for h in hsites)]
    # exclude plain sites inside handler bodies of the same handlers
    same=[o for o in others]
    irqcnt=len(hsites)
    if same:
        rows.append((len(same), rel, lb, hsites, same))
rows.sort(key=lambda r:-r[0])
print("candidate (file, lock) pairs with handler-plain + other-plain:", len(rows))
for n,rel,lb,hs,os_ in rows[:60]:
    print(f"{rel} lock~{lb} handler_sites={[(l,h) for l,h,_ in hs]} other_plain={len(os_)}")
json.dump([{"file":r[1],"lock":r[2],"handler_sites":r[3],"other_plain":r[4]} for r in rows], open("cross.json","w"))
