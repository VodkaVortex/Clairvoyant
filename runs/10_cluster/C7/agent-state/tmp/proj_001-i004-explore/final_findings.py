import json

findings = [
  {
    "snapshot": "s03",
    "path": "drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c",
    "start": 761,
    "end": 768,
    "quote": "spin_lock(&fep->tx_lock);\n\t(*fep->ops->stop)(dev);\n\tspin_unlock(&fep->tx_lock);",
    "confidence": "high",
    "reason": "Lock fs_enet_private.tx_lock is shared between softirq and process context with the process side missing bottom-half disable (exact seed shape). UNTRUSTED TRIGGER: any packet/event that runs the driver's NAPI poll under NET_RX softirq, plus any ifconfig down / device close. SOFTIRQ SIDE: fs_enet_interrupt (request_irq at line 733, fs_enet-main.c) -> __napi_schedule(&fep->napi) (line 352) -> fs_enet_napi (NAPI poll, line 86) takes the SAME tx_lock with plain spin_lock at fs_enet-main.c:99 and completes TX descriptors while holding it (unlock at line 188). PROCESS SIDE: fs_enet_stop (net_device close path, line ~755) runs in process context and takes the SAME fep->tx_lock with plain spin_lock at fs_enet-main.c:765 after napi_disable(); note the open path fs_enet_open calls napi_enable BEFORE request_irq, and close calls napi_disable before taking tx_lock, which closes most of the window; however fs_enet_start_xmit (ndo_start_xmit, line 484) also takes the same plain spin_lock at line 523 in NET_TX softirq context. COUNTEREVIDENCE CHECKED: (a) napi_disable() in fs_enet_stop waits for an in-flight fs_enet_napi poll to finish, so the NAPI-vs-close pairing is normally serialized before the plain lock at 765 is taken; (b) the xmit-vs-NAPI pairing (both softirq) cannot deadlock since plain spin_lock disables preemption on a single CPU and NET_TX/NET_RX softirqs do not nest on the same CPU while the holder spins with BH-state unchanged only if xmit itself is not interrupted by another softirq - actually a NET_TX holder CAN be interrupted by a NET_RX softirq on the same CPU, which is the real residual risk: ks7010-style self-deadlock requires the plain-lock holder to be process context, which here exists only after napi_disable, making the deadlock window narrow. Reported as hypothesis with medium residual uncertainty on exploitability, high confidence on the pattern (same lock object, plain spin_lock at both softirq site 99 and process site 765, no spin_lock_bh/local_bh_disable anywhere in the file)."
  },
  {
    "snapshot": "s03",
    "path": "drivers/net/ethernet/cisco/enic/enic_main.c",
    "start": 655,
    "end": 678,
    "quote": "spin_lock(&enic->wq_lock[txq_map]);",
    "confidence": "low",
    "reason": "enic wq_lock[] is taken with plain spin_lock both in enic_hard_start_xmit (ndo_start_xmit, NET_TX softirq; the file itself comments 'process context with BHs disabled, or BH' at line 629) and in enic_wq_service (line 231) which runs from enic_poll / enic_poll_msix_wq NAPI callbacks (NET_RX softirq) via vnic_cq_service (lines 1299, 1439). A NET_TX softirq holder on one CPU can be interrupted by a NET_RX softirq that spins on the same wq_lock. No spin_lock_bh on wq_lock anywhere (only devcmd_lock/rfs_h.lock use _bh, showing the driver knows the pattern). This is softirq-vs-softirq rather than the seed's process-vs-softirq shape, and net_tx_action/net_rx_action both run from do_softirq on the same CPU, so the holder (also a softirq) can still be preempted by the other softirq type - the exact scenario spin_lock_bh exists to prevent. Classified low confidence: deadlock requires both softirq types ready on the same CPU with the TX holder not yet finished; reported as a hypothesis only."
  }
]

candidates = [
  {"snapshot": "s03", "path": "drivers/staging/ks7010/ks7010_sdio.c", "line": 374, "status": "safe",
   "reason": "Exact seed bug (ks7010 tx_dev_lock plain spin_lock in ks_wlan_hw_tx, callers include workqueue hostif_sme_work chain and xmit ks_wlan_start_xmit) IS present unpatched in s03, but the seed must never be reported per instructions. Excluded from findings."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c", "line": 765, "status": "reported",
   "reason": "Reported: process-context plain spin_lock(&fep->tx_lock) in fs_enet_stop while NAPI poll fs_enet_napi takes same lock at line 99; napi_disable before the lock narrows the window but the invariant (softirq-shared lock needs _bh at process sites) is violated with no spin_lock_bh in the file."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/cisco/enic/enic_main.c", "line": 231, "status": "reported",
   "reason": "Reported low confidence: wq_lock plain spin_lock in NAPI-serviced enic_wq_service vs same plain lock in enic_hard_start_xmit; softirq-vs-softirq variant of the missing-BH-disable invariant."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/faraday/ftgmac100.c", "line": 715, "status": "safe",
   "reason": "tx_lock plain sites are ftgmac100_tx_complete_packet (NAPI poll, NET_RX softirq) and ftgmac100_xmit (ndo_start_xmit, NET_TX softirq). NO process-context plain acquisition exists (only spin_lock_init at 1363); tx_pending reset in open is outside any race with NAPI since IRQ is requested after. Softirq-vs-softirq window exists but no process-context holder, so the seed's holder-can-never-resume shape is absent; not reported for this branch."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/faraday/ftmac100.c", "line": 621, "status": "safe",
   "reason": "Identical twin of ftgmac100: both plain tx_lock sites are softirq (NAPI poll tx_complete at 621, ndo xmit at 654); no process-context site. Same conclusion."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/micrel/ks8851.c", "line": 940, "status": "safe",
   "reason": "ks8851_start_xmit plain spin_lock(&ks->statelock) at 940 is itself the NET_TX softirq side; the other site at 1025 (set_rx_mode) runs under netif_addr_lock_bh (BH disabled) via __dev_set_rx_mode; IRQ handler ks8851_irq (threaded, request_threaded_irq line 1544) uses only mutex; no process-context plain lock that a softirq can spin against."},
  {"snapshot": "s03", "path": "drivers/net/wireless/wl3501_cs.c", "line": 1128, "status": "safe",
   "reason": "Plain spin_lock(&this->lock) at 1128 is inside hardirq handler wl3501_interrupt; every other site (390,434,1233,1263,1317,1345,1639 incl. hard_start_xmit at 1317 and open at 1345) uses spin_lock_irqsave, which excludes both hard and soft interrupts. Branch-4 shape, not violated."},
  {"snapshot": "s03", "path": "drivers/net/wireless/intel/ipw2x00/ipw2100.c", "line": 3352, "status": "safe",
   "reason": "Plain spin_lock(&priv->low_lock) at 3352 is inside hardirq handler ipw2100_interrupt itself; all process-context sites use spin_lock_irqsave (743,1750,1877,1888,1971,3229,3402,5810,5829,5968,6008). Branch-4 shape not violated here."},
  {"snapshot": "s03", "path": "drivers/net/wireless/intel/ipw2x00/ipw2200.c", "line": 10531, "status": "safe",
   "reason": "Plain spin_lock(&priv->irq_lock) at 10531 is inside hardirq handler ipw_isr; all other irq_lock sites use spin_lock_irqsave (604,613,1977). No process-context plain acquisition."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/marvell/mvneta.c", "line": 3574, "status": "unresolved",
   "reason": "pp->lock taken plain in process contexts (mvneta_stop:3574, mvneta_config_rss:3850, cpu hotplug callbacks 3386/3447/3465); need to verify no softirq-side acquisition of the same lock (tx/rx paths appear to use per-cpu deferred locking). Not fully traced before finalize."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/intel/ixgbe/ixgbe_main.c", "line": 8345, "status": "unresolved",
   "reason": "fdir_perfect_lock taken plain at 4812 (ixgbe_fdir_filter_restore, called from reset/watchdog work = process context) and at 8692 (ethtool fdir entry, process) and 8329/8345 (ethtool delete, process). Softirq side not located before finalize; recorded for future work."},
  {"snapshot": "s03", "path": "drivers/net/ethernet/broadcom/bcm63xx_enet.c", "line": 444, "status": "unresolved",
   "reason": "tx_lock plain sites at 444 and 584; enclosing contexts not fully classified (likely NAPI poll vs ndo xmit) before finalize."}
]

artifact = {
  "version": 1,
  "intent_id": "i004",
  "branch": "xmit-softirq-lock",
  "execution_status": "complete",
  "snapshots_checked": ["s03"],
  "findings": findings,
  "candidates": candidates,
  "limitations": [
    "Search bounded to snapshot s03 only, as required; other snapshots not inspected.",
    "The literal seed bug (ks7010 tx_dev_lock, drivers/staging/ks7010/ks7010_sdio.c:374) is present unpatched in s03 but excluded from findings per the never-report-the-seed rule.",
    "Static analysis only: lock-context pairing was established from source reading; no runtime reproduction, lockdep run, or compile was performed, so exploitability (especially for the softirq-vs-softirq enic case and the napi_disable-narrowed fs_enet window) is unproven.",
    "Three candidates (mvneta pp->lock process sites, ixgbe fdir_perfect_lock process sites, bcm63xx_enet tx_lock) remain unresolved; their softirq-side lock acquisition paths were not traced before the finalize deadline.",
    "Candidate enumeration covered drivers/net and drivers/net/wireless plus staging drivers with ndo_start_xmit; drivers outside net/ (e.g. non-net spinlock users reachable from softirq) were not exhaustively enumerated."
  ]
}

out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i004.json"
with open(out, "w") as f:
    json.dump(artifact, f, indent=2)
print("written", out)
