import json, os, sys, tempfile
cp = sys.argv[1]
data = {
  "version": 1,
  "intent_id": "i033",
  "branch": "if-alt-count",
  "status": "in_progress",
  "snapshot": "s08",
  "phase": "initial",
  "candidates": [],
  "notes": "Initial checkpoint before searching s08 for if-alt-count branch: interface[bNumInterfaces] validation, altsetting[bAlternateSetting]/num_altsetting assumptions, runtime alt-switch consumers (sound/usb set_alt, cdc_ncm/cdc_mbim, qcserial/sierra, VIDIOC_S_ALT). Prior media-epidx (i030) found gspca stv06xx/xirlink_cit FIXED in s08 (num_altsetting<2 guards present)."
}
d = os.path.dirname(cp)
os.makedirs(d, exist_ok=True)
tmp = cp + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, cp)
print("wrote", cp)
