import json, os, tempfile

art = {
  "version": 1,
  "intent_id": "i032",
  "branch": "tasklet-napi-softirq-lock",
  "execution_status": "complete",
  "snapshots_checked": ["s03"],
  "findings": [
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/silan/sc92031.c",
      "start": 1096,
      "end": 1107,
      "quote": "\t/* Disable interrupts by clearing the interrupt mask.*/\n\tsc92031_disable_interrupts(dev);\n\n\tspin_lock(&priv->lock);\n\n\tpriv->tx_timeouts++;",
      "confidence": "high",
      "reason": "priv->lock is shared between softirq and process context with inconsistent BH discipline. Softirq side: sc92031_interrupt (hardirq) sets priv->intr_status and tasklet_schedule(&priv->tasklet) (sc92031.c:895); the tasklet body sc92031_tasklet (sc92031.c:834-876) takes spin_lock(&priv->lock) at sc92031.c:843 and runs _sc92031_tx_tasklet/_sc92031_rx_tasklet. Process side: nearly every other user of priv->lock correctly uses spin_lock_bh (get_stats:918, open/reset paths 1024/1059/1080/1134, multicast 1239, ethtool 1259/1286/1317/1364/1518/1544), but sc92031_tx_timeout (sc92031.c:1094-1113) takes the same lock with plain spin_lock() at line 1096 and holds it across _sc92031_reset(); sc92031_start_xmit (949) also uses plain spin_lock but is the xmit path excluded by branch scope. sc92031_tx_timeout runs from the netdev watchdog (process context) with BH enabled; if the RX/TX tasklet is scheduled on the same CPU it spins on priv->lock forever while the holder can never resume until it finishes - a softirq self-deadlock window exactly of the seed shape, and the surrounding spin_lock_bh users show the missing bottom-half-disable is the defect. Trigger: sustained TX to provoke the watchdog timeout plus inbound traffic that schedules the tasklet. Counterevidence checked: the driver comment at sc92031.c:258 says 'the interrupt and the tasklet never run at the same time' but does not address tasklet-vs-timeout; no irqsave or BH-disable wrapper surrounds the tx_timeout site; no runtime reproducer was built.",
      "conclusion": "sc92031_tx_timeout takes priv->lock with plain spin_lock while the ISR-scheduled RX/TX tasklet takes the same lock in softirq context; the missing spin_lock_bh lets the tasklet spin forever against the preempted timeout holder on one CPU, a high-confidence tasklet-softirq variant of the seed invariant (soft-lockup/DoS)."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/wireless/ath/ath5k/base.c",
      "start": 2200,
      "end": 2211,
      "quote": "\t} else {\n\t\tspin_lock(&ah->block);\n\t\tath5k_beacon_send(ah);\n\t\tspin_unlock(&ah->block);\n\t}",
      "confidence": "medium",
      "reason": "ah->block is the ath5k beacon lock shared across softirq and process contexts. Softirq side: ath5k_irq sees AR5K_INT_SWBA and calls tasklet_hi_schedule(&ah->beacontq) (base.c:2333); the tasklet body ath5k_tasklet_beacon (base.c:2186) takes ah->block with plain spin_lock() at base.c:2204 and calls ath5k_beacon_send(). The driver's own comment above ath5k_beacon_send (base.c:1924-1927) states it 'is called from software irq context (beacontq tasklets) or user context from ath5k_beacon_config', proving the lock is expected to be shared. Process side: ath5k_beacon_config (base.c:2151-2178) and ath5k_bss_info_changed (mac80211-ops.c:303-305) both correctly use spin_lock_bh(&ah->block), so every process-context site disables bottom halves while only the tasklet side uses plain spin_lock(). Because the process side already uses _bh, the residual hazard is the reverse pairing: the tasklet holds ah->block with plain spin_lock and a hardirq (ath5k_irq) can preempt it (branch4 overlap), and any current/future process-context site taking ah->block with plain spin_lock would deadlock the SWBA tasklet on that CPU. Counterevidence: no plain process-context acquirer of ah->block exists in this tree, and a tasklet cannot be preempted by another tasklet on the same CPU, so a livelock is not demonstrated; this is reported as a medium-confidence invariant-discipline hypothesis, not a proven deadlock.",
      "conclusion": "ath5k's SWBA beacontq tasklet takes ah->block with plain spin_lock (base.c:2204) while all process-context users of the same lock use spin_lock_bh; the inconsistent missing-BH-disable pairing is a medium-confidence variant of the seed invariant whose deadlock needs the tasklet preempted by hardirq or a plain process-side acquirer."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/usb/rtl8150.c",
      "start": 435,
      "end": 437,
      "quote": "\tspin_lock(&dev->rx_pool_lock);\n\tskb = pull_skb(dev);\n\tspin_unlock(&dev->rx_pool_lock);",
      "confidence": "low",
      "reason": "rx_pool_lock is used with inconsistent variants: read_bulk_callback (USB URB completion, softirq context) takes it with plain spin_lock at rtl8150.c:435 and reschedules the rx tasklet at rtl8150.c:457; the tasklet body rx_fixup (rtl8150.c:597, tasklet_init at 892) is scheduled from both the completion and interrupt paths; the other lock sites (rtl8150.c:603/609) use spin_lock_irq. Because the plain acquirer and the tasklet both run in softirq context on the same CPU they cannot deadlock each other, and the _irq sites only raise a hardirq-level (branch4) requirement with no hardirq acquirer identified; so this is a lock-discipline inconsistency, not the branch's softirq-vs-holder deadlock. Reported at low confidence for completeness of the candidate record.",
      "conclusion": "rtl8150 read_bulk_callback (softirq) takes rx_pool_lock with plain spin_lock while sibling sites use spin_lock_irq, but both sides are softirq-context on one CPU so no seed-shape deadlock follows; low-confidence discipline inconsistency only."
    }
  ],
  "candidates": [
    {
      "snapshot": "s03",
      "path": "drivers/net/usb/hso.c",
      "line": 1034,
      "status": "unresolved",
      "reason": "serial->serial_lock is taken with plain spin_lock in USB completion callbacks (read_bulk_callback ~1218, intr_callback ~1885, write/ctrl callbacks 1933/1982) which run in softirq context, and with spin_lock_irqsave/_irq in process-context paths (hso_serial_write:1356, tiocmget/tiocmset 1660/1687, kick_transmit 1733). hso_unthrottle_tasklet (1232) uses irqsave. No plain process-context acquirer of serial_lock was found, and the tasklet plus URB completions are all softirq-context peers on the same CPU.",
      "conclusion": "Follow up: search hso.c (and lio/mainprobe paths) for any process-context plain spin_lock on serial->serial_lock; the softirq-side plain users alone do not create this branch's softirq-vs-holder deadlock."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/wireless/marvell/mwl8k.c",
      "line": 3817,
      "status": "unresolved",
      "reason": "stream_lock is taken with plain spin_lock in the mwl8k_watchdog_ba_events workqueue worker (mwl8k.c:3817), in mwl8k_txq_xmit's tx path (1977/2041/2114), and in mwl8k_ampdu_action (5440+, mac80211 MLME process context). The poll_tx_task/poll_rx_task tasklets take tx_lock with spin_lock_bh and never touch stream_lock; the softirq-side acquirer of stream_lock is mwl8k_tx (mac80211 .tx callback), which is the xmit-callback shape of branch1, not a tasklet/NAPI callback.",
      "conclusion": "Follow up: reassign to the xmit-softirq-lock branch - a workqueue worker holding stream_lock plainly can be preempted by a NET_TX softirq running mwl8k_txq_xmit, which is branch1's invariant, not this branch's tasklet shape."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/dlink/sundance.c",
      "line": 1272,
      "status": "safe",
      "reason": "The plain spin_lock(&np->lock) sites at 1272/1298 are inside the hardware interrupt handler where BH cannot run; the rx_poll/tx_poll tasklet bodies (1074/1333) take no np->lock at all; all process-context users (1008/1534/1670/1680/1824) use irqsave/irq variants.",
      "conclusion": "No unsafe pairing: sundance's plain spin_lock appears only in the hardirq handler and its tasklets take no lock."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/micrel/ksz884x.c",
      "line": 5253,
      "status": "safe",
      "reason": "The plain spin_lock(&hw_priv->hwlock) at 5253 is inside the netdev_intr hardirq handler; the rx_proc_task/tx_proc_task tasklet bodies use spin_lock_irq (5195/5214) and netdev_tx uses spin_lock_irq (4867), so every softirq-vs-process pairing on hwlock already carries irq (hence BH) disabling.",
      "conclusion": "Safe: ksz884x hwlock's tasklet and process users all use irq variants; the only plain use is inside the hardirq handler."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/micrel/ks8842.c",
      "line": 400,
      "status": "safe",
      "reason": "All adapter->lock sites (400/746/794/1056/1097) use spin_lock_irqsave, including the ks8842_tasklet and ks8842_rx_frame_dma_tasklet paths; no plain process-context site exists to pair with the tasklets.",
      "conclusion": "Safe: ks8842 uses irqsave on adapter->lock uniformly across tasklet and process contexts."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/chelsio/cxgb/sge.c",
      "line": 1667,
      "status": "safe",
      "reason": "q->lock is taken plainly in t1_sge_tx (1667), whose own comment says 'This runs with softirqs disabled' (xmit path), and in restart_sched (1313), the sched_tsk tasklet body scheduled from update_tx_info (1452). Both plain users are softirq-context; tasklet/softirq peers cannot deadlock each other on the same CPU, and the process-context timer caller of t1_sge_tx (espibug timer) belongs to the timer branch.",
      "conclusion": "Safe for this branch: cxgb's q->lock plain users are both softirq-context; residual hazard maps to the xmit/timer branches."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/cavium/liquidio/lio_main.c",
      "line": 3215,
      "status": "safe",
      "reason": "glist_lock is taken plainly in liquidio_xmit (3215) and in free_netsgbuf/free_netsgbuf_with_resp (1891/1940). The free callbacks run from lio_process_iq_request_list under octeon_flush_iq's spin_lock_bh(&iq->lock) (request_manager.c:467), reached from liquidio_napi_poll (NAPI softirq) and __check_db_timeout (workqueue); the outer _bh already disables bottom halves on that CPU, so the inner plain glist_lock cannot be preempted by the NAPI/tasklet softirq. droq->lock's tasklet users (octeon_droq.c:753) are balanced by spin_lock_bh (octeon_device.c:1361) and irqsave setup paths, and no process-context plain holder of droq->lock was found.",
      "conclusion": "Safe: liquidio's plain glist_lock free callbacks execute under a spin_lock_bh outer lock and the NAPI/tasklet peers are themselves softirq, so no missing-BH pairing was established."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/wireless/intel/ipw2x00/ipw2200.c",
      "line": 10531,
      "status": "safe",
      "reason": "The only plain spin_lock(&priv->irq_lock) is inside ipw_isr (hardirq, 10531); ipw_irq_tasklet (1977) and all other irq_lock users (604/613) use irqsave, so no tasklet-vs-process softirq pairing exists on this lock.",
      "conclusion": "Safe for this branch: ipw2200's plain irq_lock user is the hardirq handler; the tasklet uses irqsave."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/wireless/intel/ipw2x00/ipw2100.c",
      "line": 3352,
      "status": "safe",
      "reason": "The plain spin_lock(&priv->low_lock) at 3352 is inside ipw2100_interrupt (hardirq); the irq_tasklet body (3229) and every other low_lock user use irqsave. Hardirq-context shape, not tasklet-vs-process.",
      "conclusion": "Safe for this branch: ipw2100's plain low_lock user is the hardirq handler; the tasklet uses irqsave."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/wireless/ralink/rt2x00/rt2800mmio.c",
      "line": 503,
      "status": "safe",
      "reason": "The plain spin_lock(&rt2x00dev->irqmask_lock) sites (rt2800mmio.c:503; rt61pci.c:2371; rt2500pci.c:1548; rt2400pci.c:1420) are all inside the hardirq interrupt handlers; the tasklet-side re-enable path rt2800mmio_enable_interrupt (333) and the config path rt2800mmio_toggle_irq (528) use spin_lock_irq/irqsave, so no process-context plain holder pairs with the tasklets.",
      "conclusion": "Safe: rt2x00 irqmask_lock plain uses are confined to hardirq handlers; tasklet and config paths use irq variants."
    },
    {
      "snapshot": "s03",
      "path": "drivers/staging/ks7010/ks7010_sdio.c",
      "line": 374,
      "status": "safe",
      "reason": "The ks7010 tx_dev_lock plain spin_lock at ks_wlan_hw_tx (374) is the demonstration seed and must never be reported, and its shape is the xmit branch anyway. For this branch specifically, the rx_bh_task tasklet (rx_event_task, 389) takes no lock at all, and rx_dev_lock is initialized (671) but never acquired anywhere in the file, so no tasklet-side lock sharing exists in this driver.",
      "conclusion": "Seed only: ks7010's tx_dev_lock issue is the demonstration pattern and its RX tasklet takes no lock; nothing new for this branch."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/ethernet/smsc/smc91x.c",
      "line": 1222,
      "status": "safe",
      "reason": "The plain spin_lock(&lp->lock) at 1222 is inside smc_interrupt (hardirq); the tx tasklet body smc_hardware_send_pkt (551, tasklet_init 1980) takes lp->lock through smc_special_lock, which expands to spin_lock_irqsave (line 540); process-context users likewise use the same irqsave macro. No missing-BH-disable pairing.",
      "conclusion": "Safe: smc91x's tasklet takes lp->lock with irqsave via smc_special_lock; the only plain use is in the hardirq handler."
    },
    {
      "snapshot": "s03",
      "path": "drivers/net/wireless/realtek/rtlwifi/pci.c",
      "line": 1086,
      "status": "safe",
      "reason": "The rtlwifi irq_tasklet and irq_prepare_bcn_tasklet are scheduled from the hardirq handler (pci.c:982/1086); their bodies (_rtl_pci_irq_tasklet:1094, _rtl_pci_prepare_bcn_tasklet:1099) delegate to mac80211/base helpers, and the rtlwifi locks that appear with plain spin_lock (rtl8192ce/rtl8192se phy.c rf_lock) are in PHY config helpers reached from workqueue/config paths, not from the tasklet bodies; the tasklet-path shared locks (irq_th_lock, h2c_lock) are used with irqsave elsewhere in this tree. No plain process-context holder paired against a tasklet softirq acquirer of the same lock was confirmed.",
      "conclusion": "Safe: rtlwifi tasklet bodies were not shown to take any lock that a process-context path holds with plain spin_lock; rf_lock plain users sit in unrelated PHY config paths."
    }
  ],
  "coverage_gaps": [
    "The tasklet_init inventory (about 200 tasklet callbacks across drivers/net, drivers/staging, sound, mmc, dma, crypto, scsi) was deep-read only for the network and staging drivers listed in candidates; sound/, drivers/dma/, drivers/crypto/, drivers/mmc/ and drivers/scsi/ tasklet bodies were not individually audited for a plain-spin_lock process-context partner.",
    "NAPI poll functions beyond cxgb3's ofld_poll/napi_rx_handler and liquidio's liquidio_napi_poll were not enumerated; only NAPI paths reached incidentally while tracing tasklets were checked.",
    "net/ core and protocol tasklet users (net/mac80211 util.c/status.c/rx.c, net/can/bcm.c, net/dccp/ccids/ccid2.c, net/ipv4/tcp_output.c, net/iucv, net/rds) were listed by grep but not deep-read for this branch."
  ],
  "limitations": [
    "Caller-context classification (worker vs ioctl vs softirq vs hardirq) was done by source reading and kernel idiom knowledge, not by runtime tracing or compilation, so a misclassified caller could flip a 'safe' classification into a finding.",
    "For the sc92031 high-confidence finding, the deadlock needs the RX/TX tasklet to be pending on the same CPU while sc92031_tx_timeout holds priv->lock across _sc92031_reset(); no reproducer was built to measure the window or confirm the watchdog's execution context in this exact kernel revision.",
    "For the ath5k medium-confidence finding, all current process-context users of ah->block already use spin_lock_bh, so exploitability depends on the tasklet being preempted by a hardirq while holding the lock (branch4 overlap) or on a plain process-context acquirer; it is a discipline-inconsistency hypothesis, not a demonstrated deadlock.",
    "The 'This runs with softirqs disabled' comment on cxgb t1_sge_tx was taken at face value without verifying every caller's context in this revision."
  ]
}

path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i032.json"
d = os.path.dirname(path)
os.makedirs(d, exist_ok=True)
tmp = tempfile.NamedTemporaryFile('w', dir=d, delete=False, suffix='.tmp')
json.dump(art, tmp, indent=1)
tmp.flush()
os.fsync(tmp.fileno())
tmp.close()
os.replace(tmp.name, path)
print("written", path, os.path.getsize(path))
