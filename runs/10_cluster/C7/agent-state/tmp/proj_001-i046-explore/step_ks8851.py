import sys; sys.path.insert(0, '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore')
from upd import load, save, add, prog
d = load()
add(d, {"snapshot":"s03","path":"drivers/net/ethernet/micrel/ks8851.c","line":1544,"status":"safe","reason":"ks8851_irq registered with request_threaded_irq(handler=NULL, thread_fn) at 1544 so it runs in thread context, and it uses mutex_lock(&ks->lock) not a spinlock; no hardirq-side spinlock acquisition exists"})
prog(d, "ks8851: safe - threaded irq (NULL primary handler), thread context uses mutex")
save(d); print("ok")
