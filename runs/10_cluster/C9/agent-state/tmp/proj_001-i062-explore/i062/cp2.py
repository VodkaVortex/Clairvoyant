import json
cp = {
  "version": 1,
  "intent_id": "i062",
  "branch": "hci-completed-length-trust",
  "status": "in_progress",
  "snapshot": "s08",
  "note": "Checkpoint 2. opticon.c:75-76 and kl5kusb105.c:357-360 both have the missing check FIXED (short-return guards present) -> safe. es2.c greybus bounds actual_length < sizeof(header) at 834 -> safe. Candidate chain cx231xx-417.c cx231xx_bulk_copy:1348 kmalloc(buffer_size=urb->actual_length) then memcpy(buffer+3,p_buffer,buffer_size-3) with no >=3 check; cx231xx_isoc_copy:1332 consumes iso actual_length with no max_pkt_size clamp and buffer_copy spills left_data into fixed EP5_BUF_SIZE=4096 p_left_data. Swept safe: ucan (pos checks), esd_usb (pos check), etas_es58x (cmd buf size check), pwc (frame_total_size check), uvc (decode_data clamps maxlen), au0828/em28xx isoc (max_pkt_size checks), mctp-usb (hdr->len checks), ipheth (align+NCM dg checks), dln2 (size==actual_length), ir-usb/imon/gnss (guards), ldusb (urb->actual_length bounded by interrupt_in_urb transfer_buffer_length = interrupt_in_endpoint_size slot).",
  "candidates": [
    {"path": "drivers/media/usb/cx231xx/cx231xx-417.c", "line": 1348, "status": "pending", "reason": "cx231xx_bulk_copy uses urb->actual_length (u32 buffer_size) with no >=3 check: kmalloc(buffer_size) then memcpy(buffer+3, p_buffer, buffer_size-3) and memcpy(ps_head, p_buffer+buffer_size-3, 3); buffer_size in {0,1,2} => kmalloc(0..2), 4GB-wrapped copy. Also no clamp vs ts1 max_pkt_size."},
    {"path": "drivers/media/usb/cx231xx/cx231xx-417.c", "line": 1332, "status": "pending", "reason": "cx231xx_isoc_copy: iso_frame_desc[i].actual_length consumed with no max_pkt_size clamp (cx231xx-video.c sibling clamps); buffer_copy spills len-tail_data into fixed 4096-byte p_left_data."}
  ]
}
json.dump(cp, open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i062.json","w"), indent=1)
print("ok")
