import json, sys, os
cp_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i032.json"
data = {
  "version": 1,
  "intent_id": "i032",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s03",
  "status": sys.argv[1] if len(sys.argv) > 1 else "initial",
  "updated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
  "progress_notes": sys.argv[2] if len(sys.argv) > 2 else "initial checkpoint before first search",
  "candidates": []
}
if len(sys.argv) > 3:
    try:
        data["candidates"] = json.loads(sys.argv[3])
    except Exception as e:
        data["candidates_error"] = str(e)
tmp = cp_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, cp_path)
print("checkpoint written:", cp_path, "status:", data["status"])
