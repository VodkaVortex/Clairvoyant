import json, os
ckpt = {
  "version": 1,
  "intent_id": "i031",
  "branch": "net-epidx",
  "status": "in_progress",
  "snapshot": "s08",
  "note": "Initial checkpoint before search. Intent: find missing bNumEndpoints>k validation before altsetting endpoint[k] fixed-index reads in USB networking drivers (drivers/net/usb, drivers/net/wireless, drivers/net/wwan).",
  "candidates": [],
  "queries_planned": [
    "rg endpoint\\[[0-9]+\\] drivers/net/usb",
    "rg endpoint\\[[0-9]+\\] drivers/net/wireless drivers/net/wwan",
    "rg bNumEndpoints drivers/net/usb drivers/net/wireless drivers/net/wwan",
    "rg altsetting.*endpoint / cur_altsetting->endpoint",
    "rg usb_set_interface + endpoint re-read",
    "rg usb_rcvbulkpipe/usb_sndbulkpipe near descriptor reads"
  ]
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i031.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(ckpt, f, indent=2)
print("wrote", path)
