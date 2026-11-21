import sys; sys.path.insert(0, '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore')
from upd import load, save, add, prog
d = load()
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c","line":523,"status":"reported","reason":"fep->tx_lock plain spin_lock in fs_start_xmit ndo_start_xmit (523) and fs_enet_napi softirq poll (99); hardirq fs_enet_interrupt (request_irq:733) is the lock-relevant interrupt via ev_error; mac-*.c op files contain no lock usage"})
prog(d, "fs_enet: reportable - tx_lock plain in ndo_start_xmit (523) + NAPI poll (99); hardirq taker fs_enet_interrupt via ev_error")
save(d); print("ok")
