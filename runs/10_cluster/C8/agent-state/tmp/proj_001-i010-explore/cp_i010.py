import json
cp = {
  "intent_id": "i010",
  "branch": "media-epidx",
  "snapshot": "s03",
  "status": "in_progress",
  "updated_at": "start",
  "candidates": [],
  "notes": "Seed: cx231xx-cards NULL-deref at probe - indexing altsetting[i].endpoint[k].desc.* without checking altsetting[i].desc.bNumEndpoints > k. Search drivers/media/usb/** in snapshots/s03 only."
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i010.json"
with open(path, "w") as f:
    json.dump(cp, f, indent=2)
print("wrote", path)
