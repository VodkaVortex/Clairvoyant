import sys; sys.path.insert(0, '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore')
from upd import load, save, add, prog
d = load()
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/cisco/enic/enic_main.c","line":231,"status":"safe","reason":"enic wq_lock taken plainly only in enic_wq_service (NAPI/softirq poll) and enic_hard_start_xmit (ndo_start_xmit, 659); no hardirq handler acquires any lock (enic_isr_legacy/msi/msix just napi_schedule/schedule_work, enic_log_q_error in hardirq touches no lock). No hardirq-shared lock."})
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/cisco/enic/enic_api.c","line":36,"status":"safe","reason":"enic_api_lock taken plainly in process contexts (workqueue reset workers enic_main.c:2152/2172, exported API proxy enic_api.c:36); no hardirq-side acquisition exists anywhere in the enic directory; not hardirq-shared."})
prog(d, "enic: safe - ISRs acquire no locks; wq_lock is softirq/xmit shared (branch1 shape, both plain), enic_api_lock/devcmd_lock have no hardirq taker")
save(d); print("ok")
