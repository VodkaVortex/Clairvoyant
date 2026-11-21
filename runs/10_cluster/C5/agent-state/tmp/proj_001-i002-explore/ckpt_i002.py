import json, os, time
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/agent-state/checkpoints/i002.json"
data = {
  "intent_id": "i002",
  "branch": "xsk-umem-rereads",
  "snapshot": "s01",
  "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
  "status": "in_progress",
  "step": "initial checkpoint; s01 net/xdp/xsk.c appears to contain the pre-fix double-read of meta->request.csum_start/csum_offset (seed mechanism) at lines 765-795; need to read full function and confirm whether it matches the seed (excluded) or is a distinct variant",
  "candidates": []
}
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, path)
print("checkpoint written:", path)
