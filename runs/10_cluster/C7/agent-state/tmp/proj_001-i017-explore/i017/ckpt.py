import json, os, sys
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i017.json"
data = json.load(open(p)) if os.path.exists(p) else {"intent_id": "i017"}
data.update(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {})
with open(p + ".tmp", "w") as f:
    json.dump(data, f, indent=2)
os.replace(p + ".tmp", p)
print("checkpoint ok")
