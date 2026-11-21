import json, sys
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i032.json"
d = json.load(open(p))
cands = [
 {"path":"drivers/net/ethernet/chelsio/cxgb4/sge.c","line":1411,"status":"safe","reason":"Tasklet-side restart_ctrlq(1440)/restart_ofldq(1736) take plain spin_lock(&q->sendq.lock), but ALL process-context entry points wrap in local_bh_disable(): t4_mgmt_tx:1497, t4_ofld_send:1802, t4_crypto_send:1835. Invariant satisfied.","conclusion":"cxgb4 sendq.lock tasklet sites are bh-protected at all process entries"},
 {"path":"drivers/net/ethernet/chelsio/cxgb3/sge.c","line":1440,"status":"safe","reason":"Same as cxgb4: restart_ctrlq/restart_offloadq plain spin_lock(q->lock), process entries t3_mgmt_tx:1515 local_bh_disable; t3_offload_tx:1764 (ofld/ctrl xmit) lacks bh-disable - deferred pending verification of its callers.","conclusion":"cxgb3 q->lock: t3_mgmt_tx bh-protected; t3_offload_tx callers need verification"},
 {"path":"drivers/net/ethernet/chelsio/cxgb/sge.c","line":1313,"status":"unresolved","reason":"restart_sched tasklet (tasklet_hi_schedule at 1452 from interrupt/softirq path) takes plain spin_lock(&q->lock) at 1313-1342 on cmdQ[0].lock; t1_sge_tx (1667-1722) takes same q->lock plain but runs under ndo_start_xmit (NET_TX softirq). Process-context plain holders not yet found; t1_sched_update_parms (295, from cxgb2.c:174 link-update path) touches sched state WITHOUT q->lock but not the lock itself. Needs deeper check.","conclusion":"Verify whether any process-context path takes cxgb cmdQ q->lock plainly vs the restart_sched tasklet"},
 {"path":"drivers/net/wireless/ath/ath5k/base.c","line":1551,"status":"unresolved","reason":"tasklets ath5k_tasklet_rx/beacon take plain spin_lock(&ah->rxbuflock)/(txq->lock); process-context ath5k_reset_wake/ath5k_stop_hw paths also touch txq->lock/rxbuflock (1741/1126). Under review.","conclusion":"Check ath5k lock usage between tasklet RX and reset/stop process paths"},
 {"path":"drivers/staging/ks7010/ks_hostif.c","line":2604,"status":"safe","reason":"Seed-adjacent only: hostif_sme_task tasklet body takes NO spinlock; the vulnerable tx_dev_lock shape is the xmit seed (excluded). No new tasklet-side lock invariant violated here.","conclusion":"ks7010 sme tasklet takes no locks; seed excluded"}
]
d["candidates"] = cands
d["progress"] = "Enumerated 275 tasklet callbacks tree-wide; 44 with plain spin_lock in body. Network candidates (cxgb4/cxgb3/cxgb/ath5k/sc92031/skge/solos/dwc_eth_qos) under triage. cxgb4 confirmed safe (local_bh_disable wrappers). Next: cxgb t1_sge_tx/restart_sched cmdQ lock, ath5k, then NAPI poll vs ioctl/workqueue scan, then tasklet_hi_schedule non-net."
d["status"] = "in_progress"
json.dump(d, open(p,"w"), indent=1)
print("ok")
