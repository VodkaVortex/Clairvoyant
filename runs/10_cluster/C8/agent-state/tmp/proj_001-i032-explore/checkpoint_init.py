import json, os
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i032.json"
data = {
  "version": 1,
  "intent_id": "i032",
  "branch": "fixed-epidx-rest",
  "status": "in_progress",
  "snapshot": "s08",
  "note": "Initial checkpoint before search. Plan: (1) grep all .endpoint[ accesses in drivers/usb outside gadget/host/core, sound/usb, drivers/hid/usbhid, drivers/input, drivers/staging; (2) examine each candidate for missing bNumEndpoints bounds check at probe/bind/init; (3) triage strongest, classify reported/safe/unresolved; (4) write final artifact.",
  "candidates": []
}
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=1)
os.replace(tmp, path)
print("written", path)
