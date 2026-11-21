import json, os

CKPT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i031.json"
FINAL = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i031.json"

ckpt = {
  "intent_id": "i031",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s02",
  "status": "finalized",
  "phase": "final artifact written per finalize directive",
  "verified_evidence": {
    "fs_enet": "fs_enet-main.c: NAPI poll fs_enet_napi def 84, plain spin_lock(&fep->tx_lock) at 97 (unlock 186), netif_napi_add_weight at 1016, scheduled from hardirq fs_enet_interrupt via napi_schedule_prep:340/__napi_schedule:348 (request_irq IRQF_SHARED at 741); process side fs_enet_close (.ndo_stop at 893, def 762) plain spin_lock(&fep->tx_lock) at 774 nested in spin_lock_irqsave(&fep->lock) at 773; zero spin_lock_bh/local_bh_disable in file (grep=0); napi_disable at 769, free_irq at 781",
    "altera_tse": "altera_tse_main.c: tse_poll (NAPI def 477, netif_napi_add at 1384, scheduled from altera_isr 523-528, request_irq 928/937) -> tse_tx_complete at 484 takes plain spin_lock(&priv->tx_lock) at 437; process side tse_shutdown (.ndo_stop at 1031, def 986) takes plain spin_lock(&priv->tx_lock) at 1009 after mac_cfg_lock at 1008, no irqsave/BH on the section (rxdma_irq_lock irqsave released at 1001); xmit uses spin_lock_bh at 553; napi_disable at 995 and free_irq at 1004/1005 precede the section",
    "cassini": "cassini.c: cas_poll (NAPI def 2530, scheduled from cas_interrupt hardirqs at 2408/2459/2515) takes cp->lock irqsave at 2538 and calls cas_tx at 2539 -> cas_tx_ringN (def 1810) plain spin_lock(&cp->tx_lock[ring]) at 1817; ALL process-context tx_lock[] acquisitions go through cas_lock_all_save (247: spin_lock_irqsave(&cp->lock)+cas_lock_tx plain nested at 236) at 3795/3971/4041/4194/4233/4267 or explicit spin_lock_irqsave(&cp->lock) at 4041; zero spin_lock_bh in file (grep=0). Local hard-IRQ disable during the hold precludes same-CPU softirq entry, so the NAPI-vs-process shape is absent; hardirq cas_interrupt->cas_tx at 2506-2508 vs NAPI holder is branch-4 scope",
    "mwl8k": "mwl8k.c: tasklet_setup(poll_tx_task,mwl8k_tx_poll) at 6132, tasklet_schedule at 4606/4611/4665/4683; mwl8k_tx_poll takes plain spin_lock(&priv->tx_lock) at 4649 (softirq side, acceptable) while every process-context tx_lock site uses spin_lock_bh at 1578/1591/1597/2064; stream_lock defect is xmit-branch scope (f005)"
  },
  "candidates": [
    "fs_enet tx_lock: reported (medium)",
    "altera_tse tx_lock: reported (low)",
    "cassini tx_lock[]: safe for this branch (branch-4 lead noted)",
    "mwl8k tx_lock tasklet: safe",
    "hostap_hw.c / cxgb4 sge.c / ath5k base.c / macb_main.c: unresolved (not traced this session)"
  ]
}
with open(CKPT, "w") as f:
    json.dump(ckpt, f, indent=2)

artifact = {
  "version": 1,
  "intent_id": "i031",
  "branch": "tasklet-napi-softirq-lock",
  "execution_status": "complete",
  "snapshots_checked": ["s02"],
  "findings": [
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c",
      "start": 762,
      "end": 777,
      "quote": "spin_lock(&fep->tx_lock);",
      "confidence": "medium",
      "reason": "TASKLET/NAPI-softirq analogue of the seed's missing-BH-disable invariant in snapshot s02. LOCK OBJECT: struct fs_enet_private.tx_lock, taken plainly at exactly three sites in the file (97, 520, 774) with zero spin_lock_bh/local_bh_disable anywhere (grep count 0). UNTRUSTED SOURCE: attacker-influenced concurrency, not data — any inbound packet or DMA event on the shared IRQ (request_irq(fs_enet_interrupt, IRQF_SHARED) at fs_enet-main.c:741) that makes fs_enet_interrupt call napi_schedule_prep (line 340) / __napi_schedule (line 348), plus any device close (ifconfig down / netlink). SOFTIRQ SIDE: fs_enet_napi (NAPI poll fn, def line 84, registered via netif_napi_add_weight at line 1016) takes the SAME fep->tx_lock with plain spin_lock at line 97 (unlock 186) and reaps TX descriptors, frees skbs and possibly restarts TX while looping up to budget — NET_RX softirq context with BH enabled. PROCESS SIDE (holder, missing BH disable): fs_enet_close (.ndo_stop at line 893, def line 762) runs in process context and acquires the SAME fep->tx_lock with plain spin_lock at line 774, nested inside spin_lock_irqsave(&fep->lock, flags) at line 773 — the outer irqsave on the unrelated fep->lock disables hard IRQs but expresses no BH-disable discipline for tx_lock; there is no spin_lock_bh on this lock in the entire file. MISSING GUARANTEE: a lock reachable from NAPI/NET_RX softirq must be acquired with spin_lock_bh()/local_bh_disable() at process-context sites (the exact invariant the seed ks7010 tx_dev_lock fix encodes); plain spin_lock nested under another lock's irqsave is the violation. IMPACT if the window is hit: a NET_RX softirq executing fs_enet_napi on the same CPU spins forever on tx_lock while the preempted close path can never resume — soft-lockup, RCU stall, DoS. COUNTEREVIDENCE CHECKED: napi_disable(&fep->napi) at line 769 runs before the lock section (waits out an in-flight poll and blocks new scheduling), free_irq only happens at line 781 after the section, and the outer spin_lock_irqsave(&fep->lock) at 773 keeps local hard IRQs disabled during the hold, which on non-RT kernels also blocks softirq entry on that CPU — so the exploitable window is narrow; reported at medium confidence as a verified lock-discipline violation with the same pairing already reported for sibling snapshots (s01 f029:777, s03 f003:765, s04 f033:780, s06 f013:765, s07 f031:774), not a demonstrated deadlock."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "start": 1007,
      "end": 1012,
      "quote": "spin_lock(&priv->tx_lock);",
      "confidence": "low",
      "reason": "Second instance of the tasklet/NAPI-softirq missing-BH invariant in s02. LOCK OBJECT: struct altera_tse_private.tx_lock (spin_lock_init at altera_tse_main.c:1387). UNTRUSTED SOURCE: any inbound packet or DMA completion firing hardirq altera_isr (request_irq with IRQF_SHARED at lines 928/937) which calls napi_schedule_prep (523) / __napi_schedule (528), plus any device close executing tse_shutdown. SOFTIRQ SIDE: tse_poll (NAPI poll, def line 477, registered netif_napi_add at line 1384) calls tse_tx_complete(priv) at line 484, which takes the SAME priv->tx_lock with plain spin_lock at line 437 (unlock 471) while freeing TX buffers and waking the queue — NET_RX softirq. PROCESS SIDE (holder): tse_shutdown (.ndo_stop at line 1031, def line 986) takes spin_lock(&priv->mac_cfg_lock) at line 1008 and then plain spin_lock(&priv->tx_lock) at line 1009 with NO irqsave and NO BH disable on this section (the earlier spin_lock_irqsave(&priv->rxdma_irq_lock) at 998 was already released at 1001), holding both across reset_mac (1011), reset_dma (1018) and free_skbufs (1019) until unlock at 1021/1022. MISSING GUARANTEE: the transmit path tse_start_xmit takes the SAME lock with spin_lock_bh at line 553, proving the driver knows this lock requires BH disable in BH-enabled context, yet the NAPI-side (437) and shutdown-side (1009) acquisitions are plain. IMPACT: a NET_RX softirq running tse_poll->tse_tx_complete on the same CPU while the shutdown path holds tx_lock spins forever against a holder that can never resume. COUNTEREVIDENCE CHECKED: tse_shutdown executes napi_disable(&priv->napi) at line 995 and free_irq at lines 1004/1005 BEFORE the plain tx_lock acquisition, which waits out in-flight NAPI polls and removes the interrupt source, so only a poll racing the shutdown sequence remains — reported at low confidence as a verified discipline violation (same shape as s04 f033:1239, s06 f035:1298, s07 f017:1298), not a demonstrated deadlock."
    }
  ],
  "candidates": [
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c",
      "line": 774,
      "status": "reported",
      "reason": "Process-context holder of finding 1: fs_enet_close (.ndo_stop at 893) plain spin_lock(&fep->tx_lock) at 774 nested inside spin_lock_irqsave(&fep->lock) at 773, after napi_disable (769), with free_irq only at 781; zero spin_lock_bh in the file."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c",
      "line": 97,
      "status": "reported",
      "reason": "NAPI-softirq side of finding 1: fs_enet_napi (def 84, netif_napi_add_weight at 1016, scheduled from hardirq fs_enet_interrupt via napi_schedule_prep:340/__napi_schedule:348, request_irq at 741) takes plain spin_lock(&fep->tx_lock) at 97 in NET_RX softirq."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "line": 1009,
      "status": "reported",
      "reason": "Process-context holder of finding 2: tse_shutdown (.ndo_stop at 1031) plain spin_lock(&priv->tx_lock) at 1009 (after mac_cfg_lock at 1008, no irqsave/BH) preceded by napi_disable (995) and free_irq (1004/1005); xmit side correctly uses spin_lock_bh at 553."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/altera/altera_tse_main.c",
      "line": 437,
      "status": "reported",
      "reason": "NAPI-softirq side of finding 2: tse_tx_complete (def 429) takes plain spin_lock(&priv->tx_lock) at 437, called from NAPI poll tse_poll at 484 (netif_napi_add at 1384, scheduled from hardirq altera_isr at 523-528, request_irq at 928/937)."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/sun/cassini.c",
      "line": 236,
      "status": "safe",
      "reason": "cas_lock_tx takes plain spin_lock_nested(&cp->tx_lock[i]) at 236, and the NAPI poll cas_poll (def 2530, napi_schedule from cas_interrupt hardirqs at 2408/2459/2515) reaches plain spin_lock(&cp->tx_lock[ring]) at 1817 via cas_tx (2539) -> cas_tx_ringN (def 1810). Safe for THIS branch because every process-context acquisition of tx_lock[] (cas_reset_task worker at 3971 via cas_lock_all_save, cas_reset at 3795, link reset 4194, cas_open 4233, cas_close 4267, and the 4041-4042 pair) happens while holding spin_lock_irqsave(&cp->lock) (macro at 247-252) — local hard-IRQ disable during the hold also blocks same-CPU softirq entry on non-RT kernels, so the holder-can-never-resume shape against a NET_RX softirq is absent (zero spin_lock_bh in the file, grep=0). The residual hardirq-vs-NAPI pairing (cas_interrupt takes cp->lock at 2506 and calls cas_tx at 2508 while cas_poll holds cp->lock at 2538 around cas_tx) is a hardirq-shared-lock shape out of scope for this branch — recorded as a priority lead for the s02 hardirq branch intent (i045)."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/wireless/marvell/mwl8k.c",
      "line": 4649,
      "status": "safe",
      "reason": "Tasklet side is disciplined: tasklet_setup(&priv->poll_tx_task, mwl8k_tx_poll) at 6132 (scheduled at 4606/4665) takes plain spin_lock(&priv->tx_lock) at 4649, but plain is acceptable on the softirq side and every process-context acquisition of the same tx_lock uses spin_lock_bh (1578, 1591, 1597, 2064); no BH-enabled process-context plain holder exists, so the tasklet/NAPI invariant holds. The separate mwl8k stream_lock defect in this snapshot is xmit-branch scope (fact f005) and is not re-reported here."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/wireless/intersil/hostap/hostap_hw.c",
      "line": 1,
      "status": "unresolved",
      "reason": "11 plain spin_lock sites in the highest-density tasklet-containing wireless file (baplock/txfidlock/local->lock, including tasklet-driven prism2 TX-completion and RX-tasklet paths); per-lock pairing of plain sites against BH-enabled process-context holders was not traced before the finalize directive. (Sibling s12 pass reported hostap txfidlock as a mixed-discipline defect at hostap_hw.c:1721.)"
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/chelsio/cxgb4/sge.c",
      "line": 1,
      "status": "unresolved",
      "reason": "14 plain spin_lock sites in a NAPI-containing file (adapters serviced by NAPI polls; ptp_lock/plain sites ranked by the s02 xmit pass fact f005 as unresolved); context attribution of each plain site versus NAPI softirq was not completed before the finalize directive."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/wireless/ath/ath5k/base.c",
      "line": 1,
      "status": "unresolved",
      "reason": "5 plain spin_lock sites (txq->lock/txbuflock) in a driver with tasklet and NAPI RX wiring; softirq-vs-process pairing not traced before the finalize directive (carried from sibling-snapshot rankings)."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/cadence/macb_main.c",
      "line": 1,
      "status": "unresolved",
      "reason": "6 plain spin_lock sites in a NAPI-containing Ethernet driver (ranked #6 by plain-spin_lock density among tasklet/NAPI files in s02); per-lock softirq/process attribution was not performed before the finalize directive."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c",
      "line": 520,
      "status": "safe",
      "reason": "fs_enet_start_xmit (.ndo_start_xmit) plain spin_lock(&fep->tx_lock) at 520 is the xmit-callback path excluded from this branch per intent scope (covered by the xmit-softirq-lock branch; ndo_start_xmit also runs with BH already disabled by __dev_queue_xmit); recorded only as same-lock-object evidence for finding 1."
    }
  ],
  "limitations": [
    "Bounded search halted by the finalize directive: deep lock-object pairing was completed only for fs_enet (reported), altera_tse (reported), cassini (safe for this branch, hardirq lead noted) and mwl8k tasklet tx_lock (safe); the systematic whole-tree enumeration of tasklet_schedule/tasklet_setup callback bodies and NAPI poll functions containing plain spin_lock was not executed for s02 in this session.",
    "Unresolved candidates left for follow-up in s02: hostap hostap_hw.c/hostap_ap.c (tasklet/TX-completion plain locks), cxgb4 sge.c (14 plain sites, NAPI-reachable), ath5k base.c txq->lock/txbuflock, macb_main.c, ath9k main.c, mac80211 rx.c/util.c, qtnfmac trans.c resp_lock (NAPI reachability never established, carried from fact f005), and the wider ~290 tasklet/NAPI trigger population ranked but not per-site attributed.",
    "Static source analysis only: no kernel build, lockdep run, or runtime reproducer was performed (the s02 snapshot tree lacks .config and generated headers); contexts were attributed from grep-visible wiring (request_irq, netif_napi_add/netif_napi_add_weight, .ndo_stop, tasklet_setup, INIT_WORK/schedule_work) rather than tracing.",
    "For finding 1 (fs_enet), the deadlock window is narrow: napi_disable at line 769 precedes the plain tx_lock acquisition, free_irq only happens at line 781, and the plain acquisition at 774 is nested inside spin_lock_irqsave(&fep->lock) at 773 — local hard-IRQ disable during the hold also blocks same-CPU softirq entry on non-RT kernels; the actionable defect is the verified missing-BH-disable lock discipline (zero spin_lock_bh in the file) on a NAPI-softirq-shared lock, reported as a hypothesis at medium confidence.",
    "For finding 2 (altera_tse), the window is further narrowed: napi_disable (995) and free_irq (1004/1005) run before the plain tx_lock section (1009-1022), so only a NAPI poll racing the shutdown sequence remains; reported at low confidence for the same reason the sibling snapshots s04/s06/s07 reported it low.",
    "The cassini hardirq-vs-NAPI cp->lock/tx_lock[] pairing (cas_interrupt at cassini.c:2506-2508 vs cas_poll at 2538-2539) was identified but is hardirq-shared-lock scope (branch 4, intent i045 for s02) and was deliberately not reported here.",
    "hrtimer callbacks and delayed_work expiry paths were not enumerated in this branch pass; only tasklet_list/tasklet_setup wiring and NAPI poll functions of the four deep-read drivers plus the density-ranked candidate files were considered.",
    "The staging ks7010 seed (tx_dev_lock) was not searched and must never be reported per instructions; the mwl8k stream_lock defect of this snapshot belongs to the xmit branch (fact f005) and is out of scope here."
  ]
}

os.makedirs(os.path.dirname(FINAL), exist_ok=True)
with open(FINAL, "w") as f:
    json.dump(artifact, f, indent=2)
print("checkpoint:", CKPT)
print("final:", FINAL)
print("findings:", len(artifact["findings"]), "candidates:", len(artifact["candidates"]))
