import json, os, sys
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i054.json"
d = {
  "intent_id": "i054",
  "branch": "peer-trusted-transport",
  "snapshot": "s13",
  "status": "in_progress",
  "phase": "initial",
  "priority": [
    "greybus gb-beagleplay hdlc_rx_greybus_frame hdr.size",
    "greybus es2.c bulk-in greybus_data_rcvd actual_length",
    "hv_balloon balloon_down range_count",
    "qcom_glink chunk_size/left_size",
    "9p trans_fd/virtio/rdma/xen reply handlers",
    "nbd reply, virtio/vhost ring, ceph/cifs replies"
  ],
  "candidates": [],
  "notes": "Initial checkpoint before searching s13."
}
tmp = p + ".tmp"
with open(tmp, "w") as f: json.dump(d, f, indent=1)
os.replace(tmp, p)
print("wrote", p)
