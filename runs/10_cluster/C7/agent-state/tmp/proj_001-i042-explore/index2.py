import os, re, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"
T = os.environ.get("TMPDIR","/tmp")
data = json.load(open(os.path.join(T, "softirq_cbs.json")))
funcdefs = json.load(open(os.path.join(T, "funcdefs.json")))
# funcdefs may be missing bodies that open with macros; check which tasklet cbs / napi polls have no definition found
missing_tl = [n for n in data["tasklet_cbs"] if n not in funcdefs]
missing_np = [n for n in data["napi_polls"] if n not in funcdefs]
print("tasklet cbs without parsed definition:", len(missing_tl))
print(missing_tl)
print("napi polls without parsed definition:", len(missing_np))
print(missing_np)
