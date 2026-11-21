import json, os, sys
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/checkpoints/i021.json"
data = {
  "intent_id": "i021",
  "branch": "gro-frag-stale-ptr",
  "snapshot": "s05",
  "status": sys.argv[1] if len(sys.argv)>1 else "in_progress",
  "note": sys.argv[2] if len(sys.argv)>2 else "starting GRO/GSO/frag-list stale-pointer search in s05",
  "updated_at": "2026-11-14"
}
with open(path, "w") as f:
    json.dump(data, f, indent=2)
print("wrote", path, data["status"])
