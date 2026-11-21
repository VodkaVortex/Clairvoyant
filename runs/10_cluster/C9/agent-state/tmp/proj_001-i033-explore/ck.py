import json, os
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i033.json"
os.makedirs(os.path.dirname(p), exist_ok=True)
state = {
  "version": 1,
  "intent_id": "i033",
  "branch": "hci-completed-length-trust",
  "snapshot": "s03",
  "status": "in_progress",
  "progress": [
    "Wrote initial checkpoint. Plan: (1) deep-read drivers/greybus/es2.c cport_in_callback bulk-in path and trace urb->actual_length through gb_connection_recv -> gb_connection_recv_request/recv_response memcpy; (2) verify whether es2-side URB buffers are sized by es2 itself (ES2_GBUF_MSG_SIZE_MAX) and whether HCI contract bounds actual_length <= transfer_buffer_length; (3) sweep completion handlers in s03 using actual_length/actual/resid as copy/loop/subtraction operands (usb serial, usb core/misc/media/net, scsi resid, usbip excluded-by-rule); (4) classify candidates and finalize."
  ],
  "candidates": []
}
with open(p, "w") as f:
    json.dump(state, f, indent=2)
print("wrote", p)
