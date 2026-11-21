import json, os, sys
ckpt_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i039.json"
data = json.load(open(sys.argv[1]))
tmp = ckpt_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, ckpt_path)
print("checkpoint written:", ckpt_path)
