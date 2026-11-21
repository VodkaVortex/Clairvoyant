import sys; sys.path.insert(0, '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore')
from upd import load, save, add, prog
d = load()
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/intel/ixgbe/ixgbe_main.c","line":2925,"status":"safe","reason":"ixgbe ISRs (ixgbe_msix_clean_rings, ixgbe_intr, ixgbe_msix_other) and their helpers (ixgbe_check_lsc/check_overtemp/check_sfp schedule service task; ixgbe_msg_task->ixgbe_rcv_msg_from_vf and set_vf_* in ixgbe_sriov.c) contain no spin_lock acquisition anywhere (grep over ixgbe_sriov.c/ixgbe_mbx.c/ixgbe_common.c returns none). No hardirq-side lock taker."})
prog(d, "ixgbe: safe - no ISR-side spinlock acquisition; service task scheduling only")
save(d); print("ok")
