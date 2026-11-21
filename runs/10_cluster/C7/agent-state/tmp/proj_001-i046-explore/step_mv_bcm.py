import sys; sys.path.insert(0, '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore')
from upd import load, save, add, prog
d = load()
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/marvell/mvneta.c","line":3497,"status":"safe","reason":"mvneta_isr (request_irq:3497) only masks interrupts + napi_schedule, takes no lock; pp->lock plain users are cpu hotplug callbacks, mvneta_stop and ethtool RSS config - no hardirq-side acquisition"})
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/broadcom/bcm63xx_enet.c","line":925,"status":"safe","reason":"bcm_enet_isr_mac (925) and bcm_enet_isr_dma (929/934, 2136/2142) only mask interrupts, napi_schedule or schedule_work; neither takes any spinlock, so no hardirq-shared lock"})
prog(d, "mvneta/bcm63xx_enet: safe - ISRs take no locks")
save(d); print("ok")
