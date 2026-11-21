import json

artifact = {
  "version": 1,
  "intent_id": "i062",
  "branch": "hci-completed-length-trust",
  "execution_status": "complete",
  "snapshots_checked": ["s08"],
  "findings": [
    {
      "snapshot": "s08",
      "path": "drivers/media/usb/cx231xx/cx231xx-417.c",
      "start": 1341,
      "end": 1359,
      "quote": "buffer_size = urb->actual_length;\n\n\tbuffer = kmalloc(buffer_size, GFP_ATOMIC);\n\tif (!buffer)\n\t\treturn -ENOMEM;\n\n\tmemcpy(buffer, dma_q->ps_head, 3);\n\tmemcpy(buffer+3, p_buffer, buffer_size-3);\n\tmemcpy(dma_q->ps_head, p_buffer+buffer_size-3, 3);",
      "confidence": "medium",
      "reason": "Untrusted source: urb->actual_length is the controller/HCD-completed bulk transfer length for the cx231xx TS1 endpoint, i.e., metadata written at completion time by the host controller from a short or malicious device transfer, not a parse-time wire count. Missing guarantee: cx231xx_bulk_copy (dispatched from cx231xx_bulk_irq_callback in cx231xx-core.c for the MPEG encoder device) never checks buffer_size >= 3 and never clamps it against the locally known bulk transfer size sb_size = max_packets * ts1 max_pkt_size (320 * max_pkt_size, cx231xx_init_bulk in cx231xx-core.c:1118+). Unsafe use: buffer_size (u32) is used directly as kmalloc size; with a short completion of 0, 1, or 2 bytes, kmalloc(0..2) succeeds (kmalloc(0) returns a minimal object), then memcpy(buffer+3, p_buffer, buffer_size-3) computes (u32)(buffer_size-3) = 0xFFFFFFFD..0xFFFFFFFF, which as memcpy's size_t argument is ~4GB, causing an immediate kernel heap OOB read and write on kmalloc-8/16; memcpy(dma_q->ps_head, p_buffer+buffer_size-3, 3) also reads OOB before the transfer buffer start. buffer_filled then passes the poisoned size on. Consequence: device-triggerable heap overflow/OOB read-write and kernel crash. Counterevidence checked: usb core guarantees actual_length <= transfer_buffer_length for a normal HCD (so the large-value direction requires a short completion and the wrap, which the >=3 check absence enables); sibling cx231xx-video.c:295-298 clamps actual_length against max_pkt_size on its isoc path, showing the asymmetric-validation shape; sibling audits (f056 s02, f057 s05) independently flagged this same function family as unpatched, consistent with this tree's state. Uncertainty (why medium not high): this is the analog/417 encoder device path started via start_streaming -> cx231xx_init_bulk(dev, 320, 5, max_pkt_size, cx231xx_bulk_copy) (cx231xx-417.c:1417-1419); the minimum real completion length was reasoned statically (a device can legally send a 0-2 byte short bulk packet) rather than empirically reproduced, and I did not build/run the driver.",
      "conclusion": "cx231xx_bulk_copy consumes controller-completed urb->actual_length with no >=3 or max clamp: kmalloc(buffer_size) then memcpy(buffer+3, p_buffer, buffer_size-3) wraps to ~4GB on a 0-2 byte short bulk completion, giving a device-triggered heap OOB read/write."
    },
    {
      "snapshot": "s08",
      "path": "drivers/media/usb/cx231xx/cx231xx-417.c",
      "start": 1315,
      "end": 1335,
      "quote": "buffer_size = urb->iso_frame_desc[i].actual_length;\n\n\t\tif (buffer_size > 0)\n\t\t\tbuffer_copy(dev, p_buffer, buffer_size, urb, dma_q);",
      "confidence": "medium",
      "reason": "Untrusted source: urb->iso_frame_desc[i].actual_length is per-packet completion metadata set by the host controller at isoc completion time. Missing guarantee: cx231xx_isoc_copy consumes it with only a >0 check and no clamp against dev->ts1_mode.max_pkt_size, whereas the sibling isoc handler for the same chip (cx231xx-video.c:295-298) explicitly rejects packets with actual_length > max_pkt_size ('packet bigger than packet size') and cx231xx-dvb.c passes max_pkt_size into init as well — an asymmetric-validation mirror inside one driver family. Unsafe use: buffer_size (u32) feeds buffer_copy (cx231xx-417.c:1237-1293): the memcpy(vbuf+mpeg_buffer_completed, data, len) into the vb2 plane is bounded by mpeglines*mpeglinesize (128*512), but the else-branch tail path computes tail_data = mpeglines*mpeglinesize - mpeg_buffer_completed and then memcpy(dma_q->p_left_data, p_data, len - tail_data) (lines 1286-1291) where p_left_data is a fixed kzalloc(EP5_BUF_SIZE=4096) buffer (cx231xx-core.c:996, cx231xx.h:123); a controller-reported packet larger than max_pkt_size/4096 with the right mpeg_buffer_completed spills past the end of p_left_data on the next iteration's replay (cx231xx-417.c:1323-1327). Consequence: heap OOB write in the 4096-byte p_left_data allocation plus OOB read of the isoc packet slot. Counterevidence checked: the vb2 destination itself is length-guarded by the mpeglines*mpeglinesize test, so only the p_left_data spill path is affected; no clamp on actual_length exists anywhere on the 417 isoc path in this tree.",
      "conclusion": "cx231xx_isoc_copy consumes iso_frame_desc actual_length with no max_pkt_size clamp (cx231xx-video.c sibling enforces it) and buffer_copy spills len-tail_data into the fixed 4096-byte p_left_data, enabling heap overflow from oversized controller-reported packets."
    }
  ],
  "candidates": [
    {
      "snapshot": "s08",
      "path": "drivers/usb/serial/opticon.c",
      "line": 76,
      "status": "safe",
      "reason": "The seed-family shape is patched in this tree: 'size_t data_len = urb->actual_length - 2;' at line 76 is now preceded-in-effect by an explicit 'if (urb->actual_length <= 2) return;' guard at lines 74-80, so no size_t underflow reaches tty_insert_flip_string.",
      "conclusion": "opticon.c is patched: short-packet guard (actual_length <= 2) exists before the -2 subtraction, so no underflow."
    },
    {
      "snapshot": "s08",
      "path": "drivers/usb/serial/kl5kusb105.c",
      "line": 360,
      "status": "safe",
      "reason": "klsi_105_process_read_urb first checks 'if (!urb->actual_length) return;' then 'if (urb->actual_length <= KLSI_HDR_LEN) return;' (lines 354-360) before any subtraction; additionally the wire length from the header is clamped with 'if (len > urb->actual_length - KLSI_HDR_LEN) len = urb->actual_length - KLSI_HDR_LEN;'. No underflow path.",
      "conclusion": "kl5kusb105.c is patched: actual_length <= KLSI_HDR_LEN early return plus len clamp prevent any underflow or over-copy."
    },
    {
      "snapshot": "s08",
      "path": "drivers/greybus/es2.c",
      "line": 834,
      "status": "safe",
      "reason": "cport_in_callback checks 'if (urb->actual_length < sizeof(*header)) goto exit;' before greybus_data_rcvd(hd, cport_id, urb->transfer_buffer, urb->actual_length) at lines 843-845; the length handed downstream equals the completion length of a buffer the host itself allocated for the cport in-URB, and the known es2 short-message underflow is guarded in this tree.",
      "conclusion": "es2.c bulk-in completion is guarded: actual_length < sizeof(header) is rejected before greybus_data_rcvd, so no short-completion under-copy."
    },
    {
      "snapshot": "s08",
      "path": "drivers/media/usb/cx231xx/cx231xx-dvb.c",
      "line": 207,
      "status": "unresolved",
      "reason": "dvb_isoc_copy (line 207) and dvb_bulk_copy (line 257) hand iso_frame_desc[].actual_length / urb->actual_length straight into dvb_dmx_swfilter(&dev->dvb->demux, urb->transfer_buffer + offset, actual_length) with no max_pkt_size clamp (unlike cx231xx-video.c:295-298); whether this over-reads the per-packet transfer-buffer slot depends on dvb_dmx_swfilter internals in drivers/media/dvb-core/dvb_demux.c, which were not read in this session.",
      "conclusion": "Follow up: read dvb_dmx_swfilter/dvb_dmx_swfilter_packet in drivers/media/dvb-core to confirm whether cx231xx-dvb.c's unclamped completion actual_length can over-read the per-packet transfer-buffer slot, and report if unclamped like the -417 sibling."
    },
    {
      "snapshot": "s08",
      "path": "drivers/net/can/usb/esd_usb.c",
      "line": 503,
      "status": "safe",
      "reason": "esd_usb_read_bulk_callback's message walk is bounded: pos advances by msg->hdr.len*sizeof(u32) and each loop iteration re-checks 'if (pos > urb->actual_length) break;' (lines 530-533); the read of msg->hdr at the straddled tail can touch stale bytes but is within the ESD_USB_RX_BUFFER_SIZE coherent buffer, and this is a parse-time wire-count concern for the unclamped-wire-count branch, not a completion-length copy bound.",
      "conclusion": "esd_usb completion walk is bounded by the pos > actual_length re-check each iteration; any stale-tail parse issue belongs to the unclamped-wire-count branch, not this one."
    },
    {
      "snapshot": "s08",
      "path": "drivers/net/can/usb/etas_es58x/es58x_core.c",
      "line": 1222,
      "status": "safe",
      "reason": "es58x_copy_to_cmd_buf explicitly bounds the accumulated command buffer: 'if (es58x_dev->rx_cmd_buf_len + raw_cmd_len > es58x_dev->param->rx_urb_cmd_max_len) return -EMSGSIZE;' before its memcpy (lines 1222-1232), and es58x_split_urb's raw_cmd_len walk is driven by the same completion length; the previously suspected unbounded copy is guarded in this tree.",
      "conclusion": "etas_es58x rx_cmd_buf accumulation is explicitly size-checked against rx_urb_cmd_max_len before memcpy, so the completion-length cmd-buffer copy is bounded."
    },
    {
      "snapshot": "s08",
      "path": "drivers/media/usb/siano/smsusb.c",
      "line": 101,
      "status": "safe",
      "reason": "smsusb_onresponse requires urb->actual_length >= phdr->msg_length before using msg_length, and the split-msg offset path re-checks '((int)phdr->msg_length + surb->cb->offset) > urb->actual_length' before the header memcpy (lines 101-123); completion length is cross-checked against the header-declared size.",
      "conclusion": "smsusb cross-checks msg_length against actual_length (including the split-msg offset case), so no unbounded completion copy."
    },
    {
      "snapshot": "s08",
      "path": "drivers/net/usb/ipheth.c",
      "line": 215,
      "status": "safe",
      "reason": "ipheth_rcvbulk_callback_legacy rejects 'urb->actual_length <= IPHETH_IP_ALIGN' before subtracting, and the NCM callback checks actual_length >= IPHETH_NCM_HEADER_SIZE and per-datagram 'dg_idx + dg_len > urb->actual_length - dg_idx' style bounds before consuming; the read URB buffer is host-allocated at the fixed IPHETH_BUF_SIZE.",
      "conclusion": "ipheth guards both the legacy align-subtraction and the NCM datagram indices against actual_length, so short completions are rejected."
    },
    {
      "snapshot": "s08",
      "path": "drivers/media/usb/hdpvr/hdpvr-video.c",
      "line": 487,
      "status": "safe",
      "reason": "'rem = urb->actual_length - buf->pos;' occurs only after the buffer was produced by the bulk-in completion with pos initialized to 0 and advanced by cnt = min(rem, count); pos <= actual_length is maintained by construction, so no underflow; copy_to_user uses cnt clamped by count.",
      "conclusion": "hdpvr read path keeps buf->pos <= actual_length by construction and clamps the user copy, so the subtraction cannot underflow."
    },
    {
      "snapshot": "s08",
      "path": "drivers/media/usb/gspca/gspca.c",
      "line": 283,
      "status": "safe",
      "reason": "Generic isoc handler passes len = iso_frame_desc[i].actual_length to the subdriver pkt_scan; per-packet subdriver handling was not all deep-read, but the generic layer reads only within urb->transfer_buffer + offset for the controller-reported length and individual subdrivers (e.g. pwc) bound their frame copies; kept as swept-safe at the generic layer with subdriver depth out of scope for this pass.",
      "conclusion": "gspca generic isoc dispatch stays within the per-packet slot for the reported length; individual pkt_scan subdrivers were not exhaustively deep-read."
    },
    {
      "snapshot": "s08",
      "path": "drivers/media/rc/imon.c",
      "line": 1576,
      "status": "safe",
      "reason": "imon_incoming_packet uses len = urb->actual_length only for an 'if (len == 8 && buf[7] == 0xee)' equality test; the be32/be64 reads are of a fixed 8-byte interrupt buffer the host sized from the endpoint descriptor, and no length-derived copy occurs.",
      "conclusion": "imon only equality-tests the completion length against 8 and reads a fixed-size interrupt buffer, so no length-derived copy bound is violated."
    },
    {
      "snapshot": "s08",
      "path": "drivers/usb/usbip/usbip_common.c",
      "line": 453,
      "status": "safe",
      "reason": "Excluded by rule: usbip code (ret_submit/number_of_packets unpack and use) is present in this tree and matches the seed demonstration mechanism, but the seed path itself must never be reported as the finding; it is recorded here only as excluded-by-rule, and branch-relevant search continued elsewhere (result: the cx231xx-417 findings above).",
      "conclusion": "usbip seed path present but excluded-by-rule (seed is demonstration-only); not reported, search continued to other completion handlers."
    }
  ],
  "coverage_gaps": [
    "dvb_dmx_swfilter/dvb_dmx_swfilter_packet internal clamping in drivers/media/dvb-core was not read, so the cx231xx-dvb.c unchecked completion actual_length feeds (dvb_isoc_copy/dvb_bulk_copy) remain unresolved rather than reported.",
    "HCI-side setters of urb->actual_length and iso_frame_desc[].actual_length (ehci/uhci/xhci, fotg210, isp1760, musb, dwc2, c67x00, max3421, dummy_hcd, renesas_usbhs) were inspected only via grep hits, not per-site, so a controller double-count setting actual_length > transfer_buffer_length cannot be fully excluded from this pass.",
    "SCSI resid consumers (aacraid/aachba.c:3572 scsi_set_resid from err->residual_count, advansys, be2iscsi, aic7xxx) and drivers/usb/storage plus drivers/staging/gpib sync-URB actual_length consumers were grep-listed but not deep-read under this branch.",
    "Individual gspca pkt_scan subdrivers, hso packetizeRx, and non-USB completion analogues (spi/i2c msg->actual_length, serdev rx callbacks, tty hardware FIFO counts) were only spot-checked because the intent scoped to USB-controller completion metadata."
  ],
  "limitations": [
    "The two reported cx231xx-417 findings were verified by static reading only; no kernel build or device-emulation reproducer was run (read-only snapshot, no hardware), so the exact heap-object overlap of the ~4GB wrapped memcpy (bulk) and the p_left_data spill (isoc) is reasoned, not observed.",
    "The bulk-path minimum completion length (0-2 byte short bulk packet from the encoder device) is assumed to be attainable per USB semantics; the real device's firmware behavior was not characterized, hence medium rather than high confidence.",
    "The dvb-core demux clamp question and HCI-side actual_length setters were bounded by grep-level triage as documented in coverage_gaps."
  ]
}

with open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/findings/i062.json", "w") as f:
    json.dump(artifact, f, indent=1)
print("artifact written")

# update checkpoint to complete
cp = json.load(open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i062.json"))
cp["status"] = "complete"
cp["note"] = "Finalized: findings = cx231xx-417.c cx231xx_bulk_copy (1341-1359, medium) and cx231xx_isoc_copy (1315-1335, medium); opticon/kl5kusb105/es2/es58x/esd_usb/smsusb/ipheth/hdpvr safe; cx231xx-dvb dvb_isoc_copy unresolved (dvb-core clamp not read); usbip excluded-by-rule."
json.dump(cp, open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C9/agent-state/checkpoints/i062.json", "w"), indent=1)
print("checkpoint updated")
