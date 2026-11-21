import json, os
ckpt = {
  "version": 1,
  "intent_id": "i033",
  "branch": "hci-completed-length-trust",
  "execution_status": "in_progress",
  "assigned_snapshot": "s03",
  "primary_target": "drivers/greybus/es2.c ~line 844: greybus_data_rcvd(hd, cport_id, urb->transfer_buffer, urb->actual_length) -> gb_connection_recv memcpy",
  "steps_done": ["initial checkpoint written before any search"],
  "candidates": [],
  "notes": "Investigating completion handlers consuming device/HCI-set actual_length/actual/resid as copy length without bounds check."
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i033.json"
with open(path + ".tmp", "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(path + ".tmp", path)
print("written", path)
