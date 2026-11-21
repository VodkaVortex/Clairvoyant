import json
ckpt = {
  "intent_id": "i026",
  "branch": "media-epidx",
  "snapshot": "s07",
  "status": "in_progress",
  "phase": "initial",
  "notes": "Starting search of snapshots/s07 drivers/media/usb/** for fixed/assumed-index altsetting[i].endpoint[k].desc reads without bNumEndpoints > k check (seed: cx231xx bNumEndpoints validation fix). Exclude cx231xx files (seed demo) and interface/altsetting-count gaps (if-alt-count branch).",
  "candidates": [],
  "queries_done": []
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i026.json"
with open(path, "w") as f:
    json.dump(ckpt, f, indent=2)
print("wrote", path)
