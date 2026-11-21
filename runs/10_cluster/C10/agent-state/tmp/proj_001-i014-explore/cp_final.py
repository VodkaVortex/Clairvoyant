import json, os
cp = {
  "intent_id": "i014",
  "branch": "debugfs-write-memdup-sscanf",
  "snapshot": "s04",
  "status": "complete",
  "timestamp": "2026-11-12",
  "note": "Final state. Findings: bnad_debugfs.c:314-320 (memdup_user+sscanf, high) and cio_inject.c:98-102 (vmemdup_user+sscanf, high); regwr twin at bnad_debugfs.c:375 reported as candidate; netdevsim fib.c:1384 unresolved (stack buf, size==sizeof(buf) allowed); ice_debugfs 4 sites safe via count clamps; 10 other candidates safe via memdup_user_nul / +1 slot / explicit terminator. Artifact written to agent-state/findings/i014.json.",
  "candidates": [
    {"path": "drivers/net/ethernet/brocade/bna/bnad_debugfs.c", "line": 315, "status": "reported"},
    {"path": "drivers/net/ethernet/brocade/bna/bnad_debugfs.c", "line": 375, "status": "reported"},
    {"path": "drivers/s390/cio/cio_inject.c", "line": 98, "status": "reported"},
    {"path": "drivers/net/ethernet/intel/ice/ice_debugfs.c", "line": 174, "status": "safe"},
    {"path": "drivers/net/netdevsim/fib.c", "line": 1384, "status": "unresolved"},
    {"path": "drivers/net/ethernet/marvell/octeontx2/af/rvu_debugfs.c", "line": 994, "status": "safe"},
    {"path": "drivers/scsi/scsi_debug.c", "line": 1031, "status": "safe"},
    {"path": "drivers/crypto/hisilicon/debugfs.c", "line": 530, "status": "safe"},
    {"path": "drivers/scsi/qla2xxx/qla_dfs.c", "line": 594, "status": "safe"},
    {"path": "drivers/net/wireless/marvell/libertas/debugfs.c", "line": 464, "status": "safe"},
    {"path": "drivers/infiniband/hw/hfi1/debugfs.c", "line": 564, "status": "safe"},
    {"path": "drivers/net/wireless/ath/ath5k/debug.c", "line": 336, "status": "safe"},
    {"path": "drivers/ntb/test/ntb_tool.c", "line": 922, "status": "safe"},
    {"path": "drivers/net/wireless/ralink/rt2x00/rt2x00debug.c", "line": 466, "status": "safe"},
    {"path": "drivers/net/wireless/intel/iwlegacy/debug.c", "line": 246, "status": "safe"},
    {"path": "drivers/gpu/drm/amd/amdgpu/amdgpu_debugfs.c", "line": 2076, "status": "safe"}
  ]
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/agent-state/checkpoints/i014.json"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cp, f, indent=2)
os.replace(tmp, path)
print("wrote", path)
