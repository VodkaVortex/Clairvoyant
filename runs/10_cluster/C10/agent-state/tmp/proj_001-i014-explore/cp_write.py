import json, os
cp = {
  "intent_id": "i014",
  "branch": "debugfs-write-memdup-sscanf",
  "snapshot": "s04",
  "status": "started",
  "timestamp": "2026-11-12",
  "note": "Initial checkpoint before searching snapshots/s04 for debugfs .write handlers that memdup_user attacker-sized buffers and pass to C-string parsers without NUL termination.",
  "candidates": []
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/agent-state/checkpoints/i014.json"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cp, f, indent=2)
os.replace(tmp, path)
print("wrote", path)
