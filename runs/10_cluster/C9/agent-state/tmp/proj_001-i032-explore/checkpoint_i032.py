import json, os
cp_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i032.json"
cp = {
  "version": 1,
  "intent_id": "i032",
  "branch": "error-unwind-poisoned-count",
  "snapshot": "s08",
  "status": "finalize",
  "progress": [
    {"step": "seed-check", "detail": "s08 carries unpatched usbip seed chain (usbip_common.c:473 store, 664-665 int multiply, 640-715 recv_iso, vhci_rx.c goto error -> giveback): excluded by seed rule, recorded as candidate."},
    {"step": "qaic", "detail": "decode_message stores device count unclamped at qaic_control.c:974; every -EINVAL return (968/971/989/990/1001...) leaves user_msg->count poisoned; qaic_manage_ioctl copies msg->count back to userspace on -ECANCELED at 1345; no kernel OOB from count alone; low-confidence finding recorded."},
    {"step": "dm-era", "detail": "disk nr_bits/nr_blocks stored (372/603) but digest clamps d->nr_bits = min(writeset.nr_bits, md->nr_blocks) at 782; ws_inc/ws_dec driven by kernel-computed btree walker count; safe."},
    {"step": "dm-zoned", "detail": "sb counts stored 1079-1083 after nr_chunks<=nr_data_zones check at 1072; but nr_map_blocks has NO validation vs nr_chunks: load_mapping while(chunk<nr_chunks) fetches mblocks i+1 and stores map_mblk[i] into kcalloc(nr_map_blocks) array -> heap OOB write when nr_map_blocks < nr_chunks/DMZ_MAP_ENTRIES; error return -EIO at 1709/1730 leaves nr_map_blocks stored, cleanup loop 2784 iterates it; reported (medium)."},
    {"step": "usb iso consumers", "detail": "au0828-video.c:533-542 and cx231xx-video.c:291-303 clamp per-packet actual_length against max_pkt_size before use; safe."},
    {"step": "gve/ixgbe_e610/bnxt/ubi", "detail": "gve_adminq.c:1081/1425 count stores located; error paths not deep-read before finalize directive; recorded unresolved."}
  ],
  "findings": [
    {"path": "drivers/md/dm-zoned-metadata.c", "line": 1689, "confidence": "medium"}
  ],
  "candidates": [
    {"path": "drivers/usb/usbip/usbip_common.c", "line": 473, "status": "unresolved"},
    {"path": "drivers/accel/qaic/qaic_control.c", "line": 974, "status": "reported"},
    {"path": "drivers/md/dm-zoned-metadata.c", "line": 1689, "status": "reported"},
    {"path": "drivers/md/dm-era-target.c", "line": 372, "status": "safe"},
    {"path": "drivers/media/usb/au0828/au0828-video.c", "line": 533, "status": "safe"},
    {"path": "drivers/media/usb/cx231xx/cx231xx-video.c", "line": 291, "status": "safe"},
    {"path": "drivers/net/ethernet/google/gve/gve_adminq.c", "line": 1425, "status": "unresolved"}
  ]
}
os.makedirs(os.path.dirname(cp_path), exist_ok=True)
with open(cp_path, "w") as f:
    json.dump(cp, f, indent=2)
print("checkpoint written")
