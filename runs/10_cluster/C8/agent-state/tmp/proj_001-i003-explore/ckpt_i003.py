import json, os
ckpt = {
  "intent_id": "i003",
  "branch": "net-epidx",
  "snapshot": "s01",
  "status": "in_progress",
  "phase": "initial_checkpoint_before_search",
  "candidates": [],
  "notes": "Starting search of snapshots/s01 drivers/net/usb/** plus drivers/net/wireless and drivers/net/wwan USB NICs for endpoint[k] descriptor reads without bNumEndpoints validation."
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i003.json"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(tmp, path)
print("checkpoint written:", path)
