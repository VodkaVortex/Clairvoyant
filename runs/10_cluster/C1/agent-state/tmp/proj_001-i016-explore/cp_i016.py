import json, os
cp = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/agent-state/checkpoints/i016.json"
data = {
  "intent_id": "i016",
  "branch": "firmware-table-divisor",
  "snapshot": "s03",
  "status": "started",
  "progress": "Initial checkpoint before searching. Invariant: denominator = f(untrusted firmware/device value) where f applies unchecked fixed-width scaling/offset before '/' or '%' so the denominator can be zero (or overflow-derived) at division width while any validation checks f's input instead of f's output. Plan: rg queries over snapshots/s03 drivers for firmware-table parsing (VBIOS/powerplay, ACPI, SMBIOS, EDID, DT, EEPROM) feeding divisions; then deep-read strongest candidates.",
  "candidates": [],
  "updated_at": "2026-11-12"
}
with open(cp, "w") as f:
    json.dump(data, f, indent=2)
print("written", cp)
