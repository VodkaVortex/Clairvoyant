import sys; sys.path.insert(0, '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore')
from upd import load, save, add, prog
d = load()
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/faraday/ftgmac100.c","line":715,"status":"safe","reason":"ftgmac100_interrupt (request_irq:1122) only does iowrite32+napi_schedule, takes no lock. tx_lock plain users are ftgmac100_tx_complete_packet (NAPI poll 1036->1074, softirq) and ftgmac100_xmit (ndo_start_xmit, 761) - no hardirq taker, branch3/1 shape only"})
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/faraday/ftmac100.c","line":621,"status":"safe","reason":"ftmac100_interrupt (request_irq:968) only disables ints + napi_schedule, takes no lock; tx_lock plain users are softirq poll and ndo_start_xmit paths only"})
prog(d, "ftgmac100/ftmac100: safe - interrupt handlers take no locks; tx_lock shared only between NAPI poll and xmit")
save(d); print("ok")
