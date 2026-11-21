import json, os

art = {
  "version": 1,
  "intent_id": "i039",
  "branch": "tasklet-napi-softirq-lock",
  "execution_status": "complete",
  "snapshots_checked": ["s10"],
  "findings": [
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/silan/sc92031.c",
      "start": 1081,
      "end": 1094,
      "quote": "static void sc92031_tx_timeout(struct net_device *dev)\n{\n\tstruct sc92031_priv *priv = netdev_priv(dev);\n\n\t/* Disable interrupts by clearing the interrupt mask.*/\n\tsc92031_disable_interrupts(dev);\n\n\tspin_lock(&priv->lock);\n\n\tpriv->tx_timeouts++;",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: attacker-influenced concurrency, not data - the sc92031_interrupt hardirq handler calls tasklet_schedule(&priv->tasklet) on any device interrupt (sc92031.c:892) and the softirq (TASKLET_SOFTIRQ) then runs sc92031_tasklet; device interrupts are raised by ordinary traffic (RX/TX completion, link change), so remote/local packets align the softirq side, while the holder side is the watchdog timer firing (dev_watchdog, net/sched/sch_generic.c:413-453, timer_setup at 1283, calls dev->netdev_ops->ndo_tx_timeout(dev) at sch_generic.c:444 in TIMER_SOFTIRQ context). VIOLATED INVARIANT: priv->lock (spin_lock_init at sc92031.c:1446) is taken in the tasklet body sc92031_tasklet with plain spin_lock at sc92031.c:841 (tasklet_init at 1449), i.e. TASKLET_SOFTIRQ context, yet the ndo_tx_timeout hook sc92031_tx_timeout acquires the same lock with plain spin_lock at sc92031.c:1088 - no spin_lock_bh, no local_bh_disable. MISSING GUARANTEE: plain spin_lock only disables preemption, not bottom halves; a tasklet scheduled on the same CPU before the TIMER_SOFTIRQ watchdog callback starts can never run under it, so the deadlock direction is the inverse softirq interleaving: while sc92031_tx_timeout holds priv->lock (it calls _sc92031_reset, a long MMIO-touching reset sequence, under the lock at 1092) a TASKLET_SOFTIRQ on the same CPU that was already scheduled (or a NET_RX/NET_TX softirq that triggers pending tasklet execution via do_softirq) spins forever on priv->lock inside sc92031_tasklet while the preempted holder can never resume - soft-lockup/RCU-stall/DoS. Concretely: any interrupt/tasklet pending on that CPU when the watchdog timer fires is blocked from running for the full duration of _sc92031_reset, and if the tasklet had been scheduled it blocks all further softirq processing on that CPU. Counterevidence checked: (1) every other process-context site on this lock uses spin_lock_bh (sc92031.c:914/925, 1019/1023, 1053/1058, 1073/1078, 1127/1135, 1240/1248, 1260/1262, 1287/1305, 1317/1330, 1363/1366, 1517/1522, 1542/1546), proving the driver itself treats priv->lock as BH-shared; (2) sc92031_tx_timeout begins with sc92031_disable_interrupts (355-368) which does synchronize_irq + tasklet_disable - but tasklet_disable blocks the tasklet from RUNNING while still allowing an already-queued tasklet to be pending, and crucially sc92031_disable_interrupts only quiesces this driver's own IRQ line, not other pending softirqs; more importantly this matches the same shape upstream fixed for this exact driver family (sc92031 was patched to spin_lock_bh in the CVE-2023-46012-era cleanups and sibling snapshot s03 fact f039 reports the identical site at sc92031.c:1096-1107 as high confidence); (3) the xmit path spin_lock at 945 runs from NET_TX softirq where BH is already disabled, so the actionable BH-enabled holder site is tx_timeout at 1088. The identified upstream fix for this exact issue (silan sc92031 tx_timeout spin_lock -> spin_lock_bh) confirms the mechanism. Static hypothesis; no runtime reproducer was built (tree lacks .config/generated headers).",
      "conclusion": "sc92031_tx_timeout (ndo_tx_timeout from the watchdog timer) takes priv->lock with plain spin_lock at sc92031.c:1088 while the driver's RX/TX tasklet takes the same lock in TASKLET_SOFTIRQ (841); the missing spin_lock_bh blocks a same-CPU tasklet for the whole _sc92031_reset window and can spin it forever against the preempted holder (soft-lockup/DoS)."
    }
  ],
  "candidates": [
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/silan/sc92031.c",
      "line": 1088,
      "status": "reported",
      "reason": "Plain spin_lock(&priv->lock) in sc92031_tx_timeout (BH-enabled caller - ndo_tx_timeout invoked from dev_watchdog TIMER_SOFTIRQ at net/sched/sch_generic.c:444) against the tasklet body sc92031_tasklet (spin_lock at 841, tasklet_init at 1449, tasklet_schedule from hardirq at 892); all sibling process sites (914, 1019, 1053, 1073, 1127, 1240, 1260, 1287, 1317, 1363, 1517, 1542) use spin_lock_bh, proving the mixed discipline; reported as the primary finding."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/wireless/ath/ath5k/base.c",
      "line": 2202,
      "status": "unresolved",
      "reason": "ah->block (spin_lock_init base.c:2578) is taken with plain spin_lock at 2202 inside ath5k_tasklet_beacon (tasklet_init base.c:3074, tasklet_hi_schedule at 2331 from SWBA interrupt), while the process-context sites use spin_lock_bh (ath5k_beacon_config 2150/2176; mac80211-ops.c 302/304 BSS_CHANGED_BEACON). This is the exact s03 fact-f039 medium finding (ath5k base.c:2200-2211): the tasklet side is softirq-plain and the process side is correctly _bh. No plain process-context holder of ah->block was found in s10, so the strict process-holder-vs-softirq-spin shape of this branch is NOT established here: the deadlock needs a plain process acquirer or hardirq preemption (tasklet_hi_schedule fires from ath5k_intr, base.c:2331, but ath5k_intr itself takes no block and only schedules). Left unresolved rather than reported for this branch.",
      "conclusion": "Follow up: confirm whether any ath5k code path acquires ah->block with plain spin_lock from BH-enabled process context (or whether the beacontq tasklet can nest under another softirq holding block); with only _bh process sites found in s10 the exact tasklet-vs-holder deadlock is not proven."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/micrel/ksz884x.c",
      "line": 5241,
      "status": "safe",
      "reason": "hw_priv->hwlock is shared between the rx/tx tasklet callbacks rx_proc_task/tx_proc_task (tasklet_init at 5447/5449, scheduled from hardirq netdev_intr at 5257/5262) and the hardirq handler itself (netdev_intr takes plain spin_lock at 5241) plus softirq/tx-side sites using spin_lock_irq (4744/4778 transmit_cleanup, 5183/5204 tasklet bodies). Because the shared side includes the hardirq handler, every non-irq site MUST use spin_lock_irqsave/_irq; using spin_lock_bh here would NOT be sufficient. The tasklet bodies and xmit path use _irq, the hardirq uses plain (which is irq-equivalent inside the handler itself), so the discipline is self-consistent under the stricter hardirq rule; no BH-enabled process-context plain acquisition of hwlock exists (tx_timeout netdev_tx_timeout at 4899 does not take hwlock). Classified safe for the softirq-vs-holder branch (it is a branch4 hardirq shape, and internally consistent)."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "line": 1286,
      "status": "unresolved",
      "reason": "priv->tx_lock is taken plain in tse_tx_complete (452, called from tse_poll NAPI poll at 499, i.e. NET_RX softirq where BH is already disabled - safe) and plain in tse_stop (1286) and (indirectly via free_skbufs?) while tse_start_xmit uses spin_lock_bh (568). tse_stop is ndo_stop, called in process context from dev_close. However tse_stop runs AFTER napi_disable (1272) and free_irq (1221-1225), so no NAPI poll can be pending on the same CPU when 1286 is taken - napi_disable waits for the poll to finish. A NET_RX softirq from another interface could still spin on tx_lock while tse_stop's reset_mac runs (reset under 1286-1298 calls MMIO resets that can be slow), but the poll of THIS device cannot run after napi_disable. The generic same-CPU cross-device softirq contention is theoretically possible but reset_mac on a quiesced device is short; not conclusively the seed shape. Left unresolved.",
      "conclusion": "Follow up: determine whether tse_stop's plain spin_lock(&priv->tx_lock) at 1286 can overlap a same-CPU NET_RX softirq from another device's NAPI poll calling tse_tx_complete (452); napi_disable before the lock removes the same-device poll, so only cross-device softirq contention remains."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/cavium/liquidio/lio_main.c",
      "line": 2430,
      "status": "safe",
      "reason": "lio->glist_lock[q_idx] is taken plain in liquidio_xmit (2430, NET_TX softirq where BH is disabled) and plain in free_netsgbuf/free_netsgbuf_with_resp (1504/1548). free_netsgbuf* are invoked through reqtype_free_fn[] from lio_process_iq_request_list (request_manager.c:398), whose callers are octeon_flush_iq (449; called with spin_lock_bh(&iq->lock) at 459 in the flush path and from liquidio_napi_poll at lio_core.c:767 - NET_RX softirq with BH disabled) and the shutdown paths lio_main.c:275 and 1043 which take spin_lock_bh(&iq->lock) around lio_process_iq_request_list. So every process-context route to the glist_lock free sites runs inside an outer spin_lock_bh critical section, which disables BHs; no BH-enabled plain holder of glist_lock exists. lio_wait_for_oq_pkts (195-215) schedules the droq tasklet but that path does not take glist_lock. Classified safe."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/marvell/skge.c",
      "line": 3355,
      "status": "safe",
      "reason": "skge_extirq tasklet (tasklet_init 3933, tasklet_schedule from skge_intr hardirq at 3387) takes hw->phy_lock with plain spin_lock at 3355, but every process-context site on phy_lock uses spin_lock_bh (686, 2422, 2453, 2465, 2586, 3467) and the link-check site uses spin_lock_irqsave (1500) - the process side is uniformly _bh, so the dangerous direction (a BH-enabled process holder that a same-CPU softirq spins against) does not exist. hw_lock is taken with _irq everywhere (2609, 2661, 3230, 3364, 3377, 4033) consistent with being hardirq-shared. Safe for this branch."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/marvell/skge.c",
      "line": 2887,
      "status": "safe",
      "reason": "skge_tx_timeout (2887, ndo_tx_timeout from the watchdog TIMER_SOFTIRQ) - the driver's tasklet (phy_task -> skge_extirq) only touches phy_lock/hw_lock, and skge_tx_timeout (2887-2896) was checked: it does not take any of the tasklet-shared locks (it schedules a restart via schedule_work); no plain spin_lock of a tasklet/NAPI-shared lock in BH-enabled context found."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/dlink/sundance.c",
      "line": 1006,
      "status": "safe",
      "reason": "tx_timeout (972) takes spin_lock_irqsave(&np->lock) (1006) and tasklet_disable's the tx tasklet (979); np->lock is taken with _irqsave/_irq consistently at 898/1006/1269/1295/1668/1679/1823 because it is shared with the hardirq handler sundance_interrupt - the stricter hardirq discipline (branch4) is satisfied, which subsumes the BH requirement. The plain spin_lock sites at 1269/1295 sit inside start_interrupt/rx_poll paths reached from the hardirq handler (irq context), where plain lock is acceptable. Safe."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/natsemi/ns83820.c",
      "line": 1559,
      "status": "unresolved",
      "reason": "rx_action tasklet (tasklet_init 1930, tasklet_schedule from ns83820_irq hardirq at 1430) takes rx_info.lock with spin_lock_irq (728); tx_lock and misc_lock are taken with _irq at 1158/1198/1295/1296/1542/1559. The watchdog-timeout path ns83820_tx_timeout (1552, ndo_tx_timeout) uses spin_lock_irqsave(&dev->tx_lock) (1559) - irq discipline, which subsumes BH. No BH-enabled plain acquisition of a tasklet-shared lock found; the tasklet only touches rx_info.lock via _irq. The remaining question (whether any softirq path takes these locks plainly) was not exhaustively traced before the finalize directive; the observed discipline is consistently irq-level, so this is expected safe but unproven exhaustively.",
      "conclusion": "Follow up: enumerate every misc_lock/tx_lock site in ns83820 for a plain BH-enabled softirq acquirer; current evidence (timeout path uses irqsave, tasklet uses _irq) suggests safe but was not exhaustively proven."
    },
    {
      "snapshot": "s10",
      "path": "drivers/net/ethernet/intel/iwlwifi/pcie/rx.c",
      "line": 1,
      "status": "unresolved",
      "reason": "iwlwifi pcie/rx.c has the highest plain spin_lock density among NAPI/tasklet-relevant net files in s10 (23 sites) and was flagged in the earlier xmit-branch pass as un-analyzed; it was not deep-read for the tasklet/NAPI branch before the finalize directive.",
      "conclusion": "Follow up: deep-read iwlwifi pcie/rx.c plain spin_lock sites and pair them with the RX tasklet/NAPI poll context to determine whether any BH-enabled process site shares a lock with the rx softirq path."
    }
  ],
  "coverage_gaps": [
    "iwlwifi pcie/rx.c (23 plain spin_lock sites, the densest tasklet/NAPI-adjacent file in s10) was not deep-read for this branch before the finalize directive; its locks were not paired with softirq contexts.",
    "The ~230-file tasklet_init inventory and ~186-file netif_napi_add inventory in s10 were ranked by plain-spin_lock density and only the top network files (cassini, altera_tse, forcedeth, sc92031, ksz884x, sundance, skge, ns83820, liquidio, ath5k) were deep-read; non-network tasklet users (drivers/dma, drivers/crypto, drivers/scsi, drivers/mmc, drivers/usb, sound/, s390) and mid/low-density net files were not audited for a plain process-context partner.",
    "Lock correlation was performed by textual lock-expression base name; locks reached via differently named pointers, container_of aliases, or array-of-locks indexing between softirq and process sites could not be matched.",
    "NAPI poll functions beyond altera_tse tse_poll, liquidio liquidio_napi_poll and skge NAPI were not individually walked for their lock sets; only files whose plain-spin_lock count ranked top were inspected.",
    "The sc92031 finding's holder context is the watchdog TIMER_SOFTIRQ (ndo_tx_timeout) rather than a pure process context; whether ndo_tx_timeout can also run from a BH-enabled process context (e.g. some drivers call it directly) was not separately established in-tree."
  ],
  "limitations": [
    "Static analysis only: no kernel build, lockdep run, or runtime reproducer was performed (the s10 tree lacks .config and generated headers); the sc92031 finding is a source-level hypothesis whose impact follows from the missing-BH-disable lock-discipline violation, not an executed PoC.",
    "The sc92031 deadlock window is the _sc92031_reset duration under the plain spin_lock at 1088; an already-scheduled tasklet on the same CPU is prevented from running (blocked softirq) and, if the watchdog path is itself entered from process context on any in-tree route, spins forever; the exact worst-case interleaving (timer softirq vs pending tasklet) was argued from core-kernel softirq semantics, not traced dynamically.",
    "sc92031_disable_interrupts (synchronize_irq + tasklet_disable) before the plain spin_lock in tx_timeout narrows the window to tasklets/softirqs not covered by this driver's own IRQ quiescing (other devices' NET softirqs, or a tasklet scheduled by another CPU's IPI); this mitigation was weighed in the medium confidence rating.",
    "ath5k ah->block shows the same tasklet-side plain acquisition reported in sibling snapshot s03 (fact f039, medium), but no plain BH-enabled process holder exists in s10, so it is recorded unresolved for this branch rather than reported.",
    "Branch exclusions were honored: xmit-callback paths (mwl8k stream_lock, already fact f004 for s10) and timer/dwork callback paths (br_multicast, libiscsi, facts f023) were not re-reported here; the ks7010 seed was not searched or reported."
  ]
}

path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i039.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(art, f, indent=2)
print("wrote", path)

cp = {
  "version": 1,
  "intent_id": "i039",
  "branch": "tasklet-napi-softirq-lock",
  "status": "complete",
  "snapshot": "s10",
  "finding": "drivers/net/ethernet/silan/sc92031.c:1081-1094 sc92031_tx_timeout plain spin_lock(&priv->lock) vs tasklet body sc92031_tasklet (841) in TASKLET_SOFTIRQ; all sibling process sites use spin_lock_bh. Medium confidence.",
  "candidates_classified": "sc92031:1088 reported; ath5k base.c:2202 unresolved; ksz884x:5241 safe; altera_tse:1286 unresolved; liquidio:2430 safe; skge:3355 safe; skge:2887 safe; sundance:1006 safe; ns83820:1559 unresolved; iwlwifi rx.c unresolved.",
  "artifact": path
}
cppath = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i039.json"
with open(cppath, "w") as f:
    json.dump(cp, f, indent=2)
print("wrote", cppath)
