import json, os
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i037.json"
doc = {
  "version": 1,
  "intent_id": "i037",
  "branch": "if-alt-count",
  "snapshot": "s09",
  "phase": "initial",
  "candidates": [],
  "notes": "Initial checkpoint before searching s09. Plan: (1) verify drivers/media/usb/usbvision and drivers/staging/media/usbvision presence (facts f002/f003 lineage); (2) deep-read sound/usb set_alt handlers and fixed altsetting[1] sites (pcm.c, quirks.c, mixer.c, mixer_quirks.c, misc/ua101.c) left unresolved by f002; (3) cdc_ncm/cdc MBIM alt switching; (4) qcserial/sierra num_altsetting==2 switch paths; (5) V4L2 VIDIOC_S_ALT handlers; (6) wacom_sys interface[1]/[2] fixed-index pattern (proven in s03/s05/s06/s07); (7) actconfig->interface[ifnum] without bNumInterfaces check sweep."
}
with open(path, "w") as f:
    json.dump(doc, f, indent=1)
print("wrote", path)
