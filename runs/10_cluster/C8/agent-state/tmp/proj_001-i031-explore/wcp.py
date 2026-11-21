import json, os
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i031.json"
data = {
  "version": 1,
  "intent_id": "i031",
  "branch": "net-epidx",
  "phase": "initial",
  "snapshot": "s08",
  "note": "Initial checkpoint before searching s08 for USB net driver endpoint-array bounds (seed cx231xx mechanism).",
  "candidates": [],
  "queries_planned": [
    "rg 'endpoint\\[' drivers/net/usb drivers/net/wireless drivers/net/wwan",
    "rg 'bNumEndpoints' drivers/net/usb drivers/net/wireless drivers/net/wwan",
    "rg 'altsetting' drivers/net/usb drivers/net/wireless drivers/net/wwan"
  ]
}
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=1)
os.replace(tmp, path)
print("written", path)
