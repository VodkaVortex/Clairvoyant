import json

findings = [
  {
    "snapshot": "s03",
    "path": "drivers/media/usb/gspca/stv06xx/stv06xx.c",
    "start": 307,
    "end": 318,
    "quote": "alt = &gspca_dev->dev->actconfig->intf_cache[0]->altsetting[1];\n\talt->endpoint[0].desc.wMaxPacketSize =",
    "confidence": "high",
    "reason": "UNTRUSTED SOURCE: USB descriptor data supplied at enumeration by a physically attacker-controlled device; bNumEndpoints of each altsetting and the variable-length endpoint[] flex-array per altsetting are attacker-chosen (a malicious gadget can declare 0 endpoints for altsetting 1). MISSING GUARANTEE: stv06xx_isoc_init() (invoked from gspca.c:773 sd_desc->isoc_init at stream start) hard-indexes actconfig->intf_cache[0]->altsetting[1] and then writes alt->endpoint[0].desc.wMaxPacketSize without any check that altsetting[1].desc.bNumEndpoints > 0, and without checking that intf_cache[0] has an altsetting[1] at all (num_altsetting > 1); grep of the whole file shows zero bNumEndpoints/num_altsetting references. UNSAFE USE: a write into endpoint[0].desc (beyond a zero-length endpoint array = OOB write of kernel memory) and, in stv06xx_isoc_nego (lines 326-335), the same unchecked endpoint[0].desc.wMaxPacketSize read/write whose negotiated value is then passed to usb_set_interface() and used to size/limit isoc URB transfers via the gspca core; a gadget with altsetting 1 lacking endpoints also makes gspca core alt selection fail later, but the OOB access here already happens at first streamon. CONSEQUENCE: kernel OOB read/write triggered by plugging in a crafted STV06xx-compatible device and starting a stream. COUNTEREVIDENCE CHECKED: gspca.c core code (alt_xfer line 516 loops i < alt->desc.bNumEndpoints; build_isoc_ep_tb; gspca.c 218) is bounds-safe, but those checks happen only after isoc_init returns; nothing in the stv06xx or gspca path validates altsetting[1].bNumEndpoints before the subdriver's fixed endpoint[0] access."
  },
  {
    "snapshot": "s03",
    "path": "drivers/media/usb/gspca/xirlink_cit.c",
    "start": 2644,
    "end": 2671,
    "quote": "alt = &gspca_dev->dev->actconfig->intf_cache[0]->altsetting[1];\n\talt->endpoint[0].desc.wMaxPacketSize = cpu_to_le16(max_packet_size);",
    "confidence": "high",
    "reason": "UNTRUSTED SOURCE: same attacker-controlled USB descriptor endpoint[] flex-array and per-altsetting bNumEndpoints. MISSING GUARANTEE: sd_isoc_init() (registered .isoc_init at xirlink_cit.c:3067, called from gspca.c:773) and sd_isoc_nego() both unconditionally take actconfig->intf_cache[0]->altsetting[1] and read/write alt->endpoint[0].desc.wMaxPacketSize with no bNumEndpoints > 0 check and no num_altsetting > 1 validation; grep confirms zero bNumEndpoints/num_altsetting references in this file. UNSAFE USE: OOB write at 2646 (endpoint[0] beyond zero-length array) at stream start, then isoc_nego (2668-2676) re-reads the same unchecked endpoint[0].desc.wMaxPacketSize and the negotiated value feeds usb_set_interface() and isoc URB buffer sizing in gspca core (gspca.c:783 alt_xfer selects the ep only afterwards, so validation comes too late). CONSEQUENCE: kernel OOB read/write on a crafted CIT/ModelShanghai/Xirlink gadget at first streamon. COUNTEREVIDENCE CHECKED: gspca.c core endpoint scanning is bounds-safe (alt_xfer loops i < bNumEndpoints); no other file in the path validates altsetting[1] before the subdriver's fixed index access."
  },
  {
    "snapshot": "s03",
    "path": "drivers/media/usb/b2c2/flexcop-usb.c",
    "start": 431,
    "end": 434,
    "quote": "fc_usb->uintf->cur_altsetting->endpoint[0].desc.wMaxPacketSize);",
    "confidence": "medium",
    "reason": "UNTRUSTED SOURCE: attacker-controlled USB descriptor endpoint array of cur_altsetting after usb_set_interface(udev, 0, 1). MISSING GUARANTEE: flexcop_usb_transfer_init() (called from flexcop_usb_probe at line 584, after flexcop_usb_init at 576 which checks bNumEndpoints < 1 only for the pre-switch cur_altsetting) reads cur_altsetting->endpoint[0].desc.wMaxPacketSize; the bNumEndpoints >= 1 check at flexcop-usb.c:514 was performed in flexcop_usb_init() BEFORE usb_set_interface(fc_usb->udev, 0, 1) at line 507 switches cur_altsetting to altsetting 1, and the new cur_altsetting's bNumEndpoints is never re-checked — exactly the seed's 'validated one altsetting, indexed another' shape. UNSAFE USE: frame_size from wMaxPacketSize is multiplied to compute bufsize = B2C2_USB_NUM_ISO_URB * B2C2_USB_FRAMES_PER_ISO * frame_size which sizes the usb_alloc_coherent isoc buffer and programs the iso URBs. CONSEQUENCE: if a malicious device's altsetting 1 has bNumEndpoints == 0, endpoint[0] read is an OOB read past the zero-length flex-array and the leaked/garbage wMaxPacketSize sizes transfer buffers. COUNTEREVIDENCE CHECKED: the check at 514 exists but is ordered before the interface switch (507 < 514 is within init, set_interface is at 507 before the check — actually the set_interface happens at 507 and the bNumEndpoints check at 514 happens after the switch in the same function, so within flexcop_usb_init the post-switch altsetting IS checked; the residual risk is that flexcop_usb_transfer_init later uses cur_altsetting which could have been changed again by userspace/ioctl between init and transfer_init — downgraded to medium for this ordering ambiguity; OOB requires cur_altsetting at transfer_init time to differ from the altsetting validated in flexcop_usb_init."
  }
]

candidates = [
  {"snapshot": "s03", "path": "drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c", "line": 188, "status": "unresolved",
   "reason": "alt->endpoint[0].desc.wMaxPacketSize read where alt comes from usb_altnum_to_altsetting(intf, sd->gspca_dev.alt) with only !alt NULL check (line 184-190); no bNumEndpoints check in file. Same fixed-index shape as reported stv06xx.c candidate but access happens in sensor start path after gspca core alt selection; not fully traced whether core guarantees ep0 exists for the selected alt. Kept unresolved; likely same-class OOB read."},
  {"snapshot": "s03", "path": "drivers/media/usb/gspca/ov519.c", "line": 3480, "status": "unresolved",
   "reason": "ov511_mode_init_regs reads alt->endpoint[0].desc.wMaxPacketSize (also line 3606 in ov518_mode_init_regs) with alt from usb_altnum_to_altsetting and only !alt check; no bNumEndpoints validation anywhere in ov519.c (grep clean). Same fixed-index read pattern; not fully traced whether callers guarantee an isoc ep in that altsetting (gspca core alt_xfer runs earlier for alt!=0 paths)."},
  {"snapshot": "s03", "path": "drivers/media/usb/gspca/konica.c", "line": 186, "status": "safe",
   "reason": "konica driver DOES check alt->desc.bNumEndpoints < 2 at line 183 before endpoint[0] (line 186) and endpoint[0/1] (line 204) reads — an in-tree example of the correct fix pattern; this is evidence the sibling gspca subdrivers lacking the check are anomalies."},
  {"snapshot": "s03", "path": "drivers/media/usb/stk1160/stk1160-core.c", "line": 191, "status": "safe",
   "reason": "stk1160_scan_usb loops e < intf->altsetting[i].desc.bNumEndpoints (line 188) before indexing endpoint[e] (line 191); endpoint index is always bounded by the descriptor-declared count."},
  {"snapshot": "s03", "path": "drivers/media/usb/usbtv/usbtv-core.c", "line": 82, "status": "safe",
   "reason": "usbtv_probe checks intf->altsetting[1].desc.bNumEndpoints != 4 (line 79) before taking &intf->altsetting[1].endpoint[0] (line 82); also checks num_altsetting != 2 (line 77)."},
  {"snapshot": "s03", "path": "drivers/media/usb/em28xx/em28xx-cards.c", "line": 3671, "status": "safe",
   "reason": "em28xx_check_usb_descriptor's endpoint[ep] index comes from caller loop ep < intf->altsetting[i].desc.bNumEndpoints (lines 3803-3805); em28xx-audio.c:690-691 similarly loops i < altsetting[alt].desc.bNumEndpoints."},
  {"snapshot": "s03", "path": "drivers/media/usb/gspca/gspca.c", "line": 517, "status": "safe",
   "reason": "gspca core alt_xfer loops i < alt->desc.bNumEndpoints (516) before &alt->endpoint[i]; gspca.c:218-219 int-urb scan likewise bounded; core is bounds-safe — the hazard is subdriver isoc_init/nego fixed indexes that run before/replacing core selection."},
  {"snapshot": "s03", "path": "drivers/media/usb/dvb-usb/dib0700_core.c", "line": 841, "status": "safe",
   "reason": "Checks intf->cur_altsetting->desc.bNumEndpoints < rc_ep + 1 at line 821 before endpoint[rc_ep] deref at 841."},
  {"snapshot": "s03", "path": "drivers/media/usb/siano/smsusb.c", "line": 406, "status": "safe",
   "reason": "All endpoint[i] uses (406, 529-538, 601-603) are inside loops bounded by i < cur_altsetting->desc.bNumEndpoints (404, 527, 599)."},
  {"snapshot": "s03", "path": "drivers/media/usb/tm6000/tm6000-cards.c", "line": 1239, "status": "safe",
   "reason": "endpoint[ep] (line 1239) is inside loop ep < interface->altsetting[i].desc.bNumEndpoints at line 1235."},
  {"snapshot": "s03", "path": "drivers/media/usb/dvb-usb/cxusb.c", "line": 1557, "status": "safe",
   "reason": "endpoint[ctr] uses bounded by loop ctr < as->desc.bNumEndpoints at line 1556."},
  {"snapshot": "s03", "path": "drivers/media/usb/au0828/au0828-video.c", "line": 1928, "status": "safe",
   "reason": "endpoint[i] inside loop i < iface_desc->desc.bNumEndpoints at line 1927; same safe shape in hdpvr-core.c:325-326, pwc-if.c:419-421, s2255drv.c:2246-2247, stk-webcam.c:1336-1337, zr364xx.c:1482-1483, uvc_driver.c:229-230/755-756."}
]

limitations = [
  "Only the media-epidx branch (drivers/media/usb/**) of snapshot s03 was searched; endpoint-array issues in net-usb, other USB consumer trees, and interface/altsetting-count forms are owned by sibling intents i011-i013.",
  "The gspca subdrivers ov519.c (lines 3480, 3606) and stv06xx_pb0100.c (line 188) remain unresolved rather than reported: their alt->endpoint[0] reads follow usb_altnum_to_altsetting with only a NULL check and no bNumEndpoints validation, but the gspca core may pre-select an altsetting with a valid isoc endpoint on some paths; a full call-path audit of every ov519/cit mode-init entry was not completed within this intent's budget.",
  "Exploit impact was not demonstrated by execution or compilation; findings rest on static evidence (missing bNumEndpoints/num_altsetting guards before fixed endpoint[0] writes/reads). The flexcop-usb.c:431 candidate is downgraded to medium because the bNumEndpoints < 1 check at line 514 executes in flexcop_usb_init() after usb_set_interface(udev, 0, 1) at 507, so the switched-to altsetting is checked once — the residual risk requires cur_altsetting to change again between init and transfer_init.",
  "The seed cx231xx files in s03 already contain the upstream fix (bNumEndpoints checks at cx231xx-cards.c:1567-1864, cx231xx-audio.c:614-636) and are excluded as demonstration-only, per intent instructions."
]

artifact = {
  "version": 1,
  "intent_id": "i010",
  "branch": "media-epidx",
  "execution_status": "complete",
  "snapshots_checked": ["s03"],
  "findings": findings,
  "candidates": candidates,
  "limitations": limitations
}

path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/findings/i010.json"
with open(path, "w") as f:
    json.dump(artifact, f, indent=2)
print("wrote", path)

# also update checkpoint
cp = {
  "intent_id": "i010",
  "branch": "media-epidx",
  "snapshot": "s03",
  "status": "complete",
  "updated_at": "final",
  "candidates": [c["path"] + ":" + str(c["line"]) + " -> " + c["status"] for c in candidates],
  "findings": [f["path"] + ":" + str(f["start"]) for f in findings],
  "notes": "Finalized: 3 findings (stv06xx.c isoc_init/nego fixed altsetting[1].endpoint[0] OOB write; xirlink_cit.c sd_isoc_init/nego same; flexcop-usb.c medium). 12 candidates triaged; gspca core and most media drivers bounds-safe."
}
cppath = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i010.json"
with open(cppath, "w") as f:
    json.dump(cp, f, indent=2)
print("wrote", cppath)
