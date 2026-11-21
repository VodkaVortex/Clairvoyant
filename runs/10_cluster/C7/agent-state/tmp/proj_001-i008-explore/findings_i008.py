import json

artifact = {
  "version": 1,
  "intent_id": "i008",
  "branch": "xmit-softirq-lock",
  "execution_status": "complete",
  "snapshots_checked": ["s07"],
  "findings": [
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/marvell/mwl8k.c",
      "start": 1978,
      "end": 2033,
      "quote": "spin_lock(&priv->stream_lock);\n\t\tstream = mwl8k_lookup_stream(hw, sta->addr, tid);",
      "confidence": "medium",
      "reason": "Lock object priv->stream_lock (spinlock_t, mwl8k.c:209, spin_lock_init at 6132) is shared between a NET_TX-softirq-reachable xmit path and process/workqueue-context paths, with every acquisition in the file being plain spin_lock() and zero spin_lock_bh/local_bh_disable on this lock (14 plain sites at 1982, 2046, 2069, 2119, 3822, 3835, 4152, 4163, 5445, 5486, 5507, 5525, 5536, 5543; grep 'spin_lock_bh(&priv->stream_lock)' count = 0). UNTRUSTED TRIGGER (attacker-influenced concurrency, not data): any QoS data frame for an HT station (or BA-watchdog firmware interrupt) that runs the mac80211 TX machinery on the same CPU. SOFTIRQ SIDE: mwl8k_tx (ieee80211_ops .tx at mwl8k.c:5597, dispatched via drv_tx from net/mac80211/tx.c:1651 inside ieee80211_subif_start_xmit/ndo_start_xmit under NET_TX softirq) -> mwl8k_txq_xmit (called at 4690, defined at 1888) takes spin_lock(&priv->stream_lock) at 1982 (range 1978-2033, unlock 2033) and again at 2046/2069/2119 with no bottom-half disable; the very same function takes priv->tx_lock with spin_lock_bh at 2054 (also 1568/1581/1587/4634), proving this xmit code path is expected to run with bottom halves enabled. PROCESS/WORKQUEUE SIDE holding the same stream_lock plainly: (a) mwl8k_watchdog_ba_events worker (lines 3822/3835; INIT_WORK at 6110, queued from hardirq handler mwl8k_interrupt at 4605 via ieee80211_queue_work after MWL8K_A2H_INT_BA_WATCHDOG) - workqueue/process context; (b) mwl8k_cmd_set_new_stn_del (4152/4163) reached from mwl8k_sta_remove (5309->5316, .sta_remove at 5609) in cfg80211 process context; (c) mwl8k_ampdu_action (5445, 5486, 5507, 5525, 5536, 5543) from mac80211/cfg80211 process context, including re-acquire after msleep(1000) in the TX_START loop. DEADLOCK SHAPE: a worker or user task holding stream_lock acquired with plain spin_lock is preempted by a NET_TX softirq on the same CPU whose mwl8k_txq_xmit then spins on stream_lock forever while the preempted holder can never resume -> softirq/soft-lockup on one CPU, RCU stall, watchdog splats and TX stall (repeatable DoS), the exact seed mechanism (missing spin_lock_bh on a softirq-shared lock). COUNTEREVIDENCE CHECKED: no spin_lock_bh, spin_lock_irqsave or local_bh_disable on stream_lock anywhere in mwl8k.c; mac80211 .tx is also callable in process context (direct xmit), which narrows the window and is why confidence is medium, not high; static analysis only, no runtime reproducer (tree lacks .config/headers for standalone build)."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "start": 455,
      "end": 464,
      "quote": "static int tse_tx_complete(struct altera_tse_private *priv)\n{\n\tunsigned int txsize = priv->tx_ring_size;\n\tu32 ready;\n\tunsigned int entry;\n\tstruct tse_buffer *tx_buff;\n\tint txcomplete = 0;\n\n\tspin_lock(&priv->tx_lock);",
      "confidence": "low",
      "reason": "Lock object priv->tx_lock in altera_tse is shared between a NET_RX-softirq NAPI callback and process-context code with the process side missing bottom-half disable (both the NAPI-poll site and the shutdown site are plain, while the xmit site correctly uses _bh). SOFTIRQ SIDES: tse_poll (NAPI poll, altera_tse_main.c:503, reached via __napi_schedule at 554 from hardirq altera_isr at 532, request_irq'd) calls tse_tx_complete (510) which takes plain spin_lock(&priv->tx_lock) at 463 (range 455-464); tse_start_xmit (ndo_start_xmit, line 568) takes the same lock with spin_lock_bh at 579, proving the driver knows this lock needs BH disable in xmit context. PROCESS SIDE: tse_shutdown (net_device ndo_stop, line 1273) takes the SAME plain spin_lock(&priv->tx_lock) at 1298 in process context. MISSING GUARANTEE: no spin_lock_bh/irqsave at the 463 and 1298 sites (only spin_lock_init and the _bh at 579 exist for this lock). COUNTEREVIDENCE: tse_shutdown calls napi_disable(&priv->napi) at 1284 and free_irq at 1293-1294 BEFORE taking tx_lock at 1298, which waits for an in-flight NAPI poll to finish and removes the IRQ source, so the NAPI-vs-shutdown window is largely closed; the remaining risk is the xmit (spin_lock_bh at 579) vs NAPI-poll (plain at 463) softirq-vs-softirq pairing plus any residual in-flight poll, a narrower race than the seed's holder-can-never-resume shape. Classified low confidence, reported as a hypothesis: the violated lock-context invariant (lock shared with softirq must use _bh at every non-softirq site) is objectively present at line 1298, but runtime exploitability is not proven."
    }
  ],
  "candidates": [
    {
      "snapshot": "s07",
      "path": "drivers/staging/ks7010/ks7010_sdio.c",
      "line": 398,
      "status": "safe",
      "reason": "The literal seed bug is present unpatched in s07 (spin_lock(&priv->tx_dev.tx_dev_lock) at line 398 in ks_wlan_hw_tx); it is the seed demonstration itself and must never be reported per instructions; excluded from findings."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/marvell/mwl8k.c",
      "line": 1982,
      "status": "reported",
      "reason": "Reported as finding 1: mwl8k_txq_xmit plain spin_lock(&priv->stream_lock) at 1982/2046/2069/2119 on the softirq-reachable .tx chain (mwl8k_tx:4676 -> 4690) vs process/workqueue holders at 3822/3835 (watchdog_ba_events worker queued from hardirq at 4605), 4152/4163 (mwl8k_cmd_set_new_stn_del from sta_remove:5316) and 5445+ (mwl8k_ampdu_action); zero spin_lock_bh on this lock."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "line": 463,
      "status": "reported",
      "reason": "Reported as finding 2 (low confidence): tse_tx_complete plain spin_lock(&priv->tx_lock) at 463 called from NAPI poll tse_poll:510, paired with process-context plain spin_lock at 1298 in tse_shutdown; xmit side correctly uses spin_lock_bh at 579 but the other two sites violate the shared-lock BH-disable invariant; napi_disable/free_irq ordering before 1298 narrows the window."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/intersil/hostap/hostap_hw.c",
      "line": 1862,
      "status": "unresolved",
      "reason": "local->baplock is taken with plain spin_lock at 1862 (prism2_transmit path), 1953 (RX path), 2229 (TX-complete interrupt path), 2420 (info-frame interrupt path) but with spin_lock_bh at 829/902; local->txfidlock is plain at 1719/2115 vs irqsave at other sites, and local->lock plain at 2184. hostap is a softmac driver whose prism2_transmit is reachable from ndo_start_xmit (NET_TX softirq) while the interrupt-side sites 2229/2420 run in hardirq context (branch-4 shape rather than branch-1). The exact process-vs-softirq pairing for baplock was not fully traced before the finalize deadline."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/st/cw1200/wsm.c",
      "line": 1091,
      "status": "safe",
      "reason": "priv->wsm_cmd.lock has 11 plain spin_lock sites (938, 1091, 1094, 1118, 1133, 1152, 1328, 1405, 1519, 1679, 1771) but all command send/tx consumption is serialized by the wsm_cmd_mux mutex (wsm_cmd_lock macro at wsm.c:88 wraps mutex_lock) and the transmit loop wsm_get_tx (1679) and wsm_txed (1771) execute in the dedicated cw1200_bh kernel thread (bh.c:423 kthread, called at bh.c:55/376), i.e. process context on both sides; no NET_TX/NET_RX-softirq-reachable acquisition of these locks found. event_queue_lock (938) likewise pairs the cw1200_bh thread with workqueue workers. Same conclusion as sibling snapshots s01/s10/s14."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/quantenna/qtnfmac/trans.c",
      "line": 43,
      "status": "unresolved",
      "reason": "ctl_node->resp_lock has 4 plain spin_lock sites (43, 60, 100, 149) and zero _bh/_irqsave in the file; qtnfmac bus locks (tx_lock, tx_reclaim_lock, irq_lock) use spin_lock_irqsave. The RX side qtnf_trans_signal_cmdresp is reached via qtnf_shm_handle_new_data from qtnf_shm_ipc_irq_work (shm_ipc.c:60, queue_work at 76, INIT_WORK at 126), i.e. bus-workqueue process context, and the transmit path goes through the bus worker, so cmd/response paths appear process-context on both sides; however full softirq reachability of every resp_lock site was not conclusively traced before the finalize deadline (mirrors the unresolved candidate in sibling snapshots)."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/ath/ath9k/main.c",
      "line": 387,
      "status": "safe",
      "reason": "Plain spin_lock(&sc->sc_pcu_lock) at 387 is inside ath9k_tasklet (tasklet callback at 371, softirq side itself) and plain spin_lock(&sc->intr_lock) at 539 / sc_pm_lock at 575 are inside the ath9k hardirq primary handler; every process-context sc_pcu_lock site uses spin_lock_bh (295, 674, 845, 865, 2121). The dangerous direction for this branch is a plain process-context holder, which does not exist; the 539/575 sites are branch-4 (hardirq) shapes, out of scope here."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/ethernet/sun/cassini.c",
      "line": 1863,
      "status": "safe",
      "reason": "Highest plain-spin_lock density in drivers/net (29 sites), but per-lock analysis: the only plain tx_lock[ring] acquisition is cas_tx_ringN (1863) called from cas_tx (1928), invoked from cas_interrupt (hardirq, 2563, under spin_lock_irqsave(&cp->lock)) and cas_poll (NAPI, 2594, also under cp->lock irqsave); the xmit side cas_xmit_tx_ringN uses spin_lock_irqsave(&cp->tx_lock[ring]) at 2776, and cas_lock_tx (245, used only from process-context cas_reset at 4104/4201 after cas_mask_intr) takes spin_lock_nested at 250 after cp->lock with spin_lock_irq at 255. Because cp->lock is taken with irq-disable at every hardirq/NAPI/process site, the hardirq and NAPI TX-completion paths cannot preempt a tx_lock holder; no plain process-context acquisition shared with a softirq path exists for tx_lock. rx_inuse_lock/rx_spare_lock plain sites (514-1382) run in the NAPI RX softirq path and the workqueue cas_spare_recover (which is itself scheduled from RX softirq at 663/666); stat_lock sites are statistics counters. No seed-shape violation established."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/intel/iwlwifi/pcie/rx.c",
      "line": 1675,
      "status": "unresolved",
      "reason": "24 plain spin_lock sites (rxq->lock, rba->lock, trans_pcie->irq_lock at 1675/1889/1962/1988/2025) with zero spin_lock_bh in the file. The RX path runs under NAPI softirq and irq_lock is taken under explicit local_irq_save at other sites in the driver, but the per-site context pairing of every plain irq_lock/rxq->lock acquisition against process-context holders was not completed before the finalize deadline; this was the top-density remaining lead in the ranking."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/ethernet/intel/igb/igb_main.c",
      "line": 2470,
      "status": "unresolved",
      "reason": "10 plain spin_lock sites on adapter->nfc_lock (2470, 2702, 2749, 9655, 9670), stats64_lock (2211, 5417, 6245) and tmreg_lock (6502, 6517). nfc_lock sites are in ethtool RX-flow-hash config handlers (process context) and possibly an RX-path consumer; stats64_lock is taken from ndo_get_stats64 (process) and from NAPI/softirq TX completion; the per-lock softirq/process pairing was ranked but not traced before the finalize deadline."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/wireless/st/cw1200/wsm.c",
      "line": 1692,
      "status": "safe",
      "reason": "The only spin_lock_bh in cw1200 wsm.c is ps_state_lock at 1692; the bss_loss_lock plain site at 1519 (wsm_handle_tx_data) executes in the cw1200_bh kernel thread alongside its counterparts in cw1200_tx_confirm, both process context, not NET_TX softirq; same reasoning as the s01/s10/s14 verdicts."
    },
    {
      "snapshot": "s07",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "line": 543,
      "status": "unresolved",
      "reason": "priv->rxdma_irq_lock plain spin_lock sites 543/550 are inside the altera_isr hardirq handler itself while all non-hardirq sites use spin_lock_irqsave (522, 1237, 1287); this is the branch-4 hardirq shape taken from the interrupt side, which is consistent, but cross-verification against every process-context site was not completed; recorded as unresolved for the hardirq branch, out of scope for this xmit-softirq intent."
    }
  ],
  "limitations": [
    "Search bounded to snapshot s07 only, as required; candidate enumeration ranked drivers/net, drivers/net/wireless and drivers/staging by plain-spin_lock density (cassini 29, iwlwifi pcie/rx.c 24, mwl8k 14, hostap 13+11, cw1200 11, cxgb3/cxgb4 sge.c, igb, altera_tse, forcedeth, vxlan, qlcnic, mvneta, cpmac, tun, ppp) and deep reachability analysis was completed only for mwl8k, altera_tse, cassini, ath9k, cw1200 and ks7010.",
    "hostap baplock/txfidlock (plain at hostap_hw.c:1862/1953/2229/2420/1719/2115/2184) pairing between the prism2 ndo_start_xmit/NET_TX-softirq path and the hardirq-side plain acquisitions remains unresolved; the plain xmit-side baplock at 1862 may be the exact seed shape against the _bh sites at 829/902 but needs call-graph confirmation.",
    "iwlwifi pcie/rx.c (24 plain spin_lock sites on rxq->lock/rba->lock/irq_lock) and igb nfc_lock/stats64_lock were ranked but their process-vs-softirq lock-object pairing was not traced before the finalize deadline.",
    "qtnfmac trans.c resp_lock softirq reachability was not conclusively established (evidence points to bus-workqueue process context on both sides, mirroring the s05 verdict, but not proven for all four sites).",
    "Both findings are static hypotheses: no runtime reproducer, lockdep run, or compile was performed because the snapshot tree lacks a Makefile/.config/generated headers for standalone driver builds; the mwl8k window also depends on mac80211 .tx dispatch under NET_TX softirq (vs process-context direct xmit), and the altera_tse window is narrowed by napi_disable()/free_irq() ordering before the plain tx_lock acquisition at line 1298.",
    "Only branch=xmit-softirq-lock was searched in s07; timer/tasklet/hardirq analogues (branches 2-4 of the mechanism profile, e.g. cassini cas_tx_ringN plain tx_lock under hardirq/NAPI and altera_isr rxdma_irq_lock) were only incidentally noted and are out of scope for this intent."
  ]
}

with open('/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i008.json', 'w') as f:
    json.dump(artifact, f, indent=2)
print("artifact written")
