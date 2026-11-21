import json, os
ckpt = {
  "intent_id": "i014",
  "branch": "helper-param-null-deref",
  "snapshot": "s01",
  "status": "in_progress",
  "note": "Initial checkpoint before first search; assigned snapshot s01 only. TMPDIR writable.",
  "candidates": []
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/checkpoints/i014.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(tmp, path)
print("wrote", path)
