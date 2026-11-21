import json, os, sys
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i055.json"
data = {
  "intent_id": "i055",
  "branch": "hci-completed-length-trust",
  "snapshot": "s10",
  "status": "in_progress",
  "step": sys.argv[1] if len(sys.argv) > 1 else "initial",
  "note": sys.argv[2] if len(sys.argv) > 2 else "",
  "candidates": json.loads(sys.argv[3]) if len(sys.argv) > 3 else [],
  "next": sys.argv[4:] if len(sys.argv) > 4 else []
}
tmp = p + ".tmp"
with open(tmp, "w") as f: json.dump(data, f, indent=2)
os.replace(tmp, p)
print("checkpoint updated:", data["step"])
