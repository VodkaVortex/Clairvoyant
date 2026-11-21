import json, os
ckpt = {
  "intent_id": "i019",
  "branch": "kind-callback-tb-gaps",
  "snapshot": "s03",
  "status": "in_progress",
  "phase": "pre-search checkpoint; about to enumerate per-kind callback surfaces (vxlan_nl2conf, .changelink implementations, net/sched init/change, ndo_fdb, dcbnl, nft expr init)",
  "candidates": [],
  "notes": [
    "Priority surfaces from prior s03 artifact f008: vxlan_nl2conf (drivers/net/vxlan.c), 22 remaining .changelink implementations, ndo_fdb_add/del bodies, net/sched per-kind init/change, dcbnl per-table handlers, nf_tables expr init callbacks",
    "mac802154_hwsim.c already reported for s03; must not re-report"
  ]
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/checkpoints/i019.json"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(tmp, path)
print("written", path)
