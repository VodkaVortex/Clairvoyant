import json

ckpt = {
  "intent_id": "i026",
  "branch": "media-epidx",
  "snapshot": "s07",
  "status": "complete",
  "phase": "finalized",
  "notes": "Swept drivers/media/usb/** in s07: fixed-index endpoint[N] grep, endpoint+N, variable-index endpoint[i] with preceding loop, intf_cache/altsetting[1] pattern (f002), ->endpoint non-indexed, ep_in[] array. Seed cx231xx excluded. Strongest: stv06xx/xirlink_cit isoc_init/isoc_nego (intf_cache[0]->altsetting[1].endpoint[0] read+write, zero guards), usbvision per-alt loop endpoint[1] (bNumEndpoints check applied only to the initially chosen interface, not interface[0] per-alt), konica endpoint[0]/[1] sizing URB buffers, dib0700 rc_ep=1, flexcop cur_altsetting->endpoint[0]. ov519/pb0100/cit_get_packet_size boundary cases kept unresolved/safe per core alt_xfer guarantee. usbtv/uvc safe (explicit guards).",
  "candidates": [
    {"file": "gspca/stv06xx/stv06xx.c", "line": 320, "status": "reported"},
    {"file": "gspca/xirlink_cit.c", "line": 2653, "status": "reported"},
    {"file": "usbvision/usbvision-video.c", "line": 1504, "status": "reported"},
    {"file": "gspca/konica.c", "line": 203, "status": "reported"},
    {"file": "dvb-usb/dib0700_core.c", "line": 829, "status": "reported"},
    {"file": "b2c2/flexcop-usb.c", "line": 430, "status": "reported"},
    {"file": "gspca/ov519.c", "line": 3471, "status": "unresolved"},
    {"file": "gspca/stv06xx/stv06xx_pb0100.c", "line": 197, "status": "unresolved"},
    {"file": "gspca/xirlink_cit.c", "line": 1454, "status": "unresolved"},
    {"file": "usbtv/usbtv-core.c", "line": 82, "status": "safe"},
    {"file": "uvc/uvc_driver.c", "line": 1281, "status": "safe"},
    {"file": "siano/smsusb.c", "line": 439, "status": "safe"}
  ],
  "queries_done": [
    "grep fixed-index endpoint[0-9] in media/usb (excluding cx231xx)",
    "grep endpoint+ / endpoint[ident] variable index",
    "grep intf_cache / altsetting[1] (f002 pattern)",
    "grep non-indexed ->endpoint and ep_in[] array uses",
    "bNumEndpoints/num_altsetting guard-count per candidate file",
    "loop-header verification for all endpoint[i] hits (pwc, smsusb, hdpvr, s2255, zr364xx, stkwebcam, au0828, gspca core, tm6000, em28xx, stk1160, uvc)"
  ]
}
with open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i026.json", "w") as f:
    json.dump(ckpt, f, indent=2)

artifact = {
  "version": 1,
  "intent_id": "i026",
  "branch": "media-epidx",
  "execution_status": "complete",
  "snapshots_checked": ["s07"],
  "findings": [
    {
      "snapshot": "s07",
      "path": "drivers/media/usb/gspca/stv06xx/stv06xx.c",
      "start": 313,
      "end": 348,
      "quote": "alt = &gspca_dev->dev->actconfig->intf_cache[0]->altsetting[1];\n\talt->endpoint[0].desc.wMaxPacketSize =",
      "confidence": "high",
      "reason": "UNTRUSTED SOURCE: usb_interface_cache altsetting[] and its per-alt endpoint[] flex array are built solely from descriptors supplied at enumeration by a physically attacker-controlled USB gadget spoofing a stv06xx device_table ID (046d:0840/0850/0870/08f0/08f5/08f6); a gadget can present fewer than 2 altsettings or an altsetting[1] with 0 endpoints. MISSING GUARANTEE: stv06xx_isoc_init (lines 313-325, index at 320-322) and stv06xx_isoc_nego (lines 327-349, index at 333) take actconfig->intf_cache[0]->altsetting[1] with a literal 1 and then endpoint[0] with a literal 0; grep of the whole file shows ZERO bNumEndpoints and ZERO num_altsetting occurrences, so no code path validates num_altsetting >= 2 or altsetting[1].desc.bNumEndpoints >= 1. UNSAFE USE: isoc_init WRITES alt->endpoint[0].desc.wMaxPacketSize (321-322) and isoc_nego reads it (334) and writes it again (342) before usb_set_interface(gspca_dev->dev, gspca_dev->iface, 1) at 345; the hooks fire from gspca core at stream start (gspca.c isoc_init / isoc_nego on ENOSPC retry), i.e. first VIDIOC_STREAMON. An OOB write/read past the endpoint flex array of a 0-endpoint altsetting[1] (or past the altsetting array when num_altsetting == 1), consequences match the seed class. COUNTEREVIDENCE: the file's other alt access (stv06xx.c:292 via NULL-checked usb_altnum_to_altsetting) is a different, safe path; the gspca core (gspca.c:613 alt_xfer loops i < alt->desc.bNumEndpoints) is bounds-safe but runs only for its own alt selection, not for these subdriver hooks."
    },
    {
      "snapshot": "s07",
      "path": "drivers/media/usb/gspca/xirlink_cit.c",
      "start": 2634,
      "end": 2690,
      "quote": "alt = &gspca_dev->dev->actconfig->intf_cache[0]->altsetting[1];\n\talt->endpoint[0].desc.wMaxPacketSize = cpu_to_le16(max_packet_size);",
      "confidence": "high",
      "reason": "Same copied pattern as stv06xx. UNTRUSTED SOURCE: actconfig->intf_cache[0]->altsetting[1].endpoint[0] is descriptor-derived from an attacker-controlled gadget presenting a CIT/ibmcam device_table ID; num_altsetting and per-alt bNumEndpoints are device-chosen. MISSING GUARANTEE: sd_isoc_init (line 2634, index at 2653-2654) and sd_isoc_nego (line 2661, index at 2676) use literal altsetting[1] and literal endpoint[0]; grep of xirlink_cit.c shows ZERO bNumEndpoints and ZERO num_altsetting occurrences anywhere in the file, so neither count is ever validated. UNSAFE USE: isoc_init writes wMaxPacketSize at 2654, isoc_nego reads it at 2677 and writes at 2684 before usb_set_interface(gspca_dev->dev, gspca_dev->iface, 1) at 2687; reached from gspca core isoc_init/isoc_nego hooks at VIDIOC_STREAMON. OOB write/read past the endpoint flex array at stream start with a single-altsetting or endpointless-alt-1 gadget. COUNTEREVIDENCE: the sibling alt accessor cit_get_packet_size (line 1454) also reads endpoint[0] of a usb_altnum_to_altsetting result with only a NULL check (separate unresolved candidate), and no guard exists anywhere in the file; the file's safe paths do not protect these hooks."
    },
    {
      "snapshot": "s07",
      "path": "drivers/media/usb/usbvision/usbvision-video.c",
      "start": 1492,
      "end": 1508,
      "quote": "u16 tmp = le16_to_cpu(uif->altsetting[i].endpoint[1].desc.\n\t\t\t\t      wMaxPacketSize);",
      "confidence": "high",
      "reason": "UNTRUSTED SOURCE: usbvision_probe runs at device plug-in; uif = dev->actconfig->interface[0] (line 1492) whose altsetting[] entries each carry a device-declared bNumEndpoints that sizes a flex array (usbcore allocates only bNumEndpoints entries). MISSING GUARANTEE: the only bNumEndpoints check in the probe (line 1453, 'if (interface->desc.bNumEndpoints < 2) ... -ENODEV') validated the single 'interface' pointer selected at 1441-1447 -- a DIFFERENT usb_interface object than uif whenever the model-table branch (interface >= 0) or a different ifnum picks another interface -- and in any case that check covers only altsetting[0] of that interface; the loop at 1502-1508 iterates i over uif->num_altsetting (usbvision->num_alt) and reads uif->altsetting[i].endpoint[1] with literal index 1, never re-checking uif->altsetting[i].desc.bNumEndpoints > 1 per iteration. UNSAFE USE: the fixed-index endpoint[1].desc.wMaxPacketSize read (1504-1505) feeds usbvision->alt_max_pkt_size[i] (1506-1507), the per-altsetting max-packet-size array later used to size/limit isoc URB buffers -- exactly the seed cx231xx alt_max_pkt_size consequence. An altsetting of interface 0 declaring 0 or 1 endpoints yields an OOB read past the endpoint[] flex array (or NULL-deref when the zero-length array was left NULL) at probe from mere device plug-in. COUNTEREVIDENCE: no validation exists between 1492 and 1508; the checked interface at 1453 is only accidentally interface[0] for some models."
    },
    {
      "snapshot": "s07",
      "path": "drivers/media/usb/gspca/konica.c",
      "start": 186,
      "end": 214,
      "quote": "i = n & 1 ? 0 : 1;\n\t\tpacket_size =\n\t\t\tle16_to_cpu(alt->endpoint[i].desc.wMaxPacketSize);",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: gspca subdriver sd_start (line 171) re-fetches the negotiated altsetting via usb_ifnum_to_if/usb_altnum_to_altsetting (182-185, NULL-checked) from device-controlled descriptors at stream-on; each altsetting's bNumEndpoints is attacker-chosen. MISSING GUARANTEE: konica.c contains ZERO bNumEndpoints occurrences (grep); the URB-creation loop at 202-214 selects i = n & 1 ? 0 : 1 (line 203), so alt->endpoint[1] (i=1 on every even n) is read at line 205 with an assumed index k=1 justified only by the device-model assumption of two isoc endpoints (0x81/0x82); line 186 also reads endpoint[0]. The gspca core alt_xfer (gspca.c:613, loops i < alt->desc.bNumEndpoints) guarantees only that the SELECTED altsetting contains at least one isoc IN endpoint (bNumEndpoints >= 1), not two, so index 1 is unvalidated. UNSAFE USE: the (possibly OOB-read) wMaxPacketSize becomes packet_size which directly sizes usb_alloc_coherent(gspca_dev->dev, packet_size * SD_NPKT, ...) URB transfer buffers (lines 206-214) and urb->transfer_buffer_length -- the seed's wMaxPacketSize-derived buffer-sizing consequence. Trigger is VIDIOC_STREAMON with a single-isoc-endpoint gadget matching a konica device_table ID (vendor 04c8 product 0720), not mere plug-in, hence medium."
    },
    {
      "snapshot": "s07",
      "path": "drivers/media/usb/dvb-usb/dib0700_core.c",
      "start": 800,
      "end": 841,
      "quote": "e = &intf->altsetting[0].endpoint[rc_ep].desc;",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: dib0700_probe calls dib0700_rc_setup(dev, intf) at device plug-in for a gadget spoofing a dib0700 device-table ID; the device also controls the reported firmware version (dib0700_get_version) that gates entry -- the early-return at ~line 806 ('st->fw_version < 0x10200 || !intf') is attacker-satisfiable by reporting a newer fw version. MISSING GUARANTEE: rc_ep is a literal 1 (int rc_ep = 1, line ~804) and dib0700_core.c contains ZERO bNumEndpoints occurrences (grep), so nothing validates altsetting[0].desc.bNumEndpoints > 1 before the fixed-index fetch e = &intf->altsetting[0].endpoint[rc_ep].desc at line 829. UNSAFE USE: e is immediately dereferenced at 830-833 via usb_endpoint_dir_in(e)/usb_endpoint_xfer_bulk(e)/usb_endpoint_xfer_int(e) -- reading descriptor bytes OOB when altsetting[0] declares fewer than 2 endpoints -- and the read attributes program usb_rcvbulkpipe/usb_rcvintpipe pipes (832, 839) for a URB submitted at probe. COUNTEREVIDENCE: pipe stays 0 (error path ~845) only if the OOB-read fields happen not to look dir-in, which does not remove the OOB read itself; impact is OOB read of descriptor data feeding a pipe, not a write primitive."
    },
    {
      "snapshot": "s07",
      "path": "drivers/media/usb/b2c2/flexcop-usb.c",
      "start": 427,
      "end": 432,
      "quote": "fc_usb->uintf->cur_altsetting->endpoint[0].desc.wMaxPacketSize);",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: flexcop_usb_probe -> flexcop_usb_transfer_init (line 427) reads the currently selected altsetting whose endpoint[] length is solely device-declared; a legal altsetting may declare bNumEndpoints == 0, leaving endpoint a zero-length/NULL flex array. MISSING GUARANTEE: fixed index 0 into cur_altsetting->endpoint[] with ZERO bNumEndpoints occurrences anywhere in flexcop-usb.c (grep); note the usb_set_interface(fc_usb->udev, 0, 1) at line 506 in flexcop_usb_init runs BEFORE transfer_init and switches cur_altsetting to altsetting 1, whose endpoint count is never checked either -- the seed's 'validated one altsetting, indexed another' shape would apply if any check existed at all, but here none does. UNSAFE USE: the (possibly OOB-read) wMaxPacketSize becomes frame_size (429-430) which computes bufsize = B2C2_USB_NUM_ISO_URB * B2C2_USB_FRAMES_PER_ISO * frame_size (431-432) for usb_alloc_coherent and per-URB iso_frame_desc lengths -- the seed's wMaxPacketSize-derived buffer-sizing consequence. Trigger requires a gadget spoofing the 0af7 TechnoTrend IDs. COUNTEREVIDENCE: whether a 0-length endpoint array reads adjacent heap or faults depends on usbcore allocation details (config.c allocates alt->endpoint only when num_ep > 0), so the exact fault is uncertain while the missing-validation direction is certain."
    }
  ],
  "candidates": [
    {"snapshot": "s07", "path": "drivers/media/usb/gspca/stv06xx/stv06xx.c", "line": 320, "status": "reported", "reason": "stv06xx_isoc_init/isoc_nego index actconfig->intf_cache[0]->altsetting[1].endpoint[0] with zero bNumEndpoints/num_altsetting occurrences in the file; wMaxPacketSize written at 321 and 342, read at 334; OOB write/read at VIDIOC_STREAMON."},
    {"snapshot": "s07", "path": "drivers/media/usb/gspca/xirlink_cit.c", "line": 2653, "status": "reported", "reason": "sd_isoc_init/sd_isoc_nego copy the same intf_cache[0]->altsetting[1].endpoint[0] pattern with zero guards in the file; wMaxPacketSize written at 2654/2684, read at 2677."},
    {"snapshot": "s07", "path": "drivers/media/usb/usbvision/usbvision-video.c", "line": 1504, "status": "reported", "reason": "Per-altsetting loop over uif=actconfig->interface[0] reads altsetting[i].endpoint[1].desc.wMaxPacketSize with literal index 1; the bNumEndpoints<2 check at 1453 covers only altsetting[0] of a possibly different interface object; feeds alt_max_pkt_size[] at 1506-1507."},
    {"snapshot": "s07", "path": "drivers/media/usb/gspca/konica.c", "line": 203, "status": "reported", "reason": "sd_start URB loop uses i = n&1 ? 0 : 1 to read alt->endpoint[0]/[1].desc.wMaxPacketSize; zero bNumEndpoints in file; core alt_xfer guarantees only >=1 isoc IN endpoint; packet_size sizes usb_alloc_coherent buffers."},
    {"snapshot": "s07", "path": "drivers/media/usb/dvb-usb/dib0700_core.c", "line": 829, "status": "reported", "reason": "dib0700_rc_setup takes altsetting[0].endpoint[rc_ep=1].desc at probe with zero bNumEndpoints occurrences in the file; OOB-read attributes program usb_rcvbulkpipe/usb_rcvintpipe."},
    {"snapshot": "s07", "path": "drivers/media/usb/b2c2/flexcop-usb.c", "line": 430, "status": "reported", "reason": "flexcop_usb_transfer_init reads cur_altsetting->endpoint[0].desc.wMaxPacketSize with zero bNumEndpoints occurrences in the file; frame_size sizes the usb_alloc_coherent iso buffer; usb_set_interface(0,1) at line 506 switched altsetting without any count check."},
    {"snapshot": "s07", "path": "drivers/media/usb/gspca/ov519.c", "line": 3471, "status": "unresolved", "reason": "ov511_mode_init_regs (and ov518_mode_init_regs at 3596) reads alt->endpoint[0].desc.wMaxPacketSize where alt comes from NULL-checked usb_altnum_to_altsetting of the altsetting the gspca core selected; core alt_xfer guarantees at least one isoc IN endpoint (bNumEndpoints >= 1) in that altsetting, which covers index 0, but a full call-path audit of every mode-init entry was not completed, so it stays unresolved rather than safe."},
    {"snapshot": "s07", "path": "drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c", "line": 197, "status": "unresolved", "reason": "pb0100_start reads alt->endpoint[0].desc.wMaxPacketSize via NULL-checked usb_altnum_to_altsetting of the core-selected altsetting; index 0 is covered by the core's >=1 isoc-IN guarantee, and the value only picks a sensor register write, but the guarantee was not independently re-proven for every path in this snapshot."},
    {"snapshot": "s07", "path": "drivers/media/usb/gspca/xirlink_cit.c", "line": 1454, "status": "unresolved", "reason": "cit_get_packet_size reads alt->endpoint[0].desc.wMaxPacketSize; the usb_altnum_to_altsetting result IS NULL-checked (lines 1450-1453 verified), but no bNumEndpoints >= 1 check exists and the altsetting is the one the gspca core selected (alt_xfer guarantees >=1 isoc IN endpoint); left unresolved pending a full call-path audit."},
    {"snapshot": "s07", "path": "drivers/media/usb/usbtv/usbtv-core.c", "line": 82, "status": "safe", "reason": "Probe rejects intf->num_altsetting != 2 (line 77) and intf->altsetting[1].desc.bNumEndpoints != 4 (line 79) before ep = &intf->altsetting[1].endpoint[0] at line 82; canonical correct validation before use."},
    {"snapshot": "s07", "path": "drivers/media/usb/uvc/uvc_driver.c", "line": 1281, "status": "safe", "reason": "&alts->endpoint[0] at 1281 is guarded by the preceding 'if (alts->desc.bNumEndpoints == 1 && ...)' at 1279; other uvc endpoint uses (204, 675, 684-685) are loops bounded by alts->desc.bNumEndpoints."},
    {"snapshot": "s07", "path": "drivers/media/usb/siano/smsusb.c", "line": 439, "status": "safe", "reason": "Endpoint scan loops 'for (i = 0; i < intf->cur_altsetting->desc.bNumEndpoints; i++)' before every endpoint[i] access (lines 439-443, 534-543, 606-608); the separate udev->ep_in[1] read at line 431 is the device-maintained endpoint array, not the descriptor flex array, and was excluded as out of this branch's invariant."}
  ],
  "limitations": [
    "No compilation or dynamic reproducer was run: the snapshot is read-only and builds would go under $TMPDIR only; all findings rest on structural source evidence (fixed-index endpoint[] fetch with grep-verified absence of any bNumEndpoints/num_altsetting guard in the file) matching the seed mechanism, expressed as hypotheses.",
    "Trigger paths were source-traced (usbvision/dib0700/flexcop at probe; gspca isoc_init/isoc_nego and konica sd_start at VIDIOC_STREAMON) but not exercised with a USB gadget; whether a given kernel config enables each subdriver (CONFIG_USB_GSPCA_STV06XX, CONFIG_USB_GSPCA_CIT, CONFIG_USB_GSPCA_KONICA, CONFIG_VIDEO_USBVISION, CONFIG_DVB_USB_DIB0700, CONFIG_DVB_B2C2_FLEXCOP_USB) is environment-dependent.",
    "The stv06xx and xirlink_cit findings conflate two gaps in one statement (unvalidated altsetting[1] index owned by the if-alt-count branch, and unvalidated endpoint[0] count owned by this branch); they are reported here for the endpoint half and will overlap with the s07 if-alt-count intent (i029) -- dedupe at merge time.",
    "The OOB memory target for zero-endpoint altsettings depends on usbcore allocation details (drivers/usb/core/config.c allocates alt->endpoint only when num_ep > 0), so the consequence is heap-adjacent read/write vs NULL-deref depending on the case; the direction of the missing validation is certain, the exact fault is not.",
    "gspca subdrivers were audited for literal/loop endpoint[] descriptor reads; subdrivers deriving endpoint addresses via other means (indirect pointer arithmetic, cached pointers) were not exhaustively enumerated; ov519.c (3471/3596), stv06xx_pb0100.c (197), and cit_get_packet_size (1454) remain unresolved pending a full call-path audit of the gspca core alt-selection guarantee.",
    "dib0700 reachability requires the device-reported firmware version >= 0x10200 (dib0700_get_version control transfer), which is attacker-satisfiable but adds one gate; runtime behavior was not verified."
  ]
}
with open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/findings/i026.json", "w") as f:
    json.dump(artifact, f, indent=2)
print("wrote artifact and checkpoint")
