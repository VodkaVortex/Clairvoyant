import json, os
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i033.json"
d = {
  "version": 1,
  "intent_id": "i033",
  "branch": "hci-completed-length-trust",
  "phase": "initial",
  "note": "Pre-search checkpoint. Plan: (1) deep-read primary target drivers/greybus/es2.c cport_in_callback ~813-854 and trace urb->actual_length into greybus_data_rcvd -> gb_connection_recv -> recv_request/recv_response memcpy; determine whether actual_length is bounded anywhere vs ES2_GBUF_MSG_SIZE_MAX before the memcpy. (2) sweep snapshot s03 for other URB/request completion handlers using urb->actual_length / actual / resid as copy length or loop bound without cross-check against locally-requested size.",
  "searches_done": [],
  "candidates": []
}
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(d, f, indent=1)
os.replace(tmp, path)
print("wrote", path)
