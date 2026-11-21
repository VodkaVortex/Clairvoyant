import json, os

finding_reason = (
    "UNTRUSTED SOURCE: attacker-influenced concurrency, not data - any IGMP/MLD membership report or query "
    "forwarded through the bridge re-arms the group timers (br_ip4_multicast_query at br_multicast.c:3495-3498 "
    "mod_timer(&mp->timer, ...) under multicast_lock; br_multicast_host_join at 1493 mod_timer(&mp->timer,...); "
    "router/querier timers re-armed by report processing), so an attacker sending multicast control traffic "
    "controls when the TIMER_SOFTIRQ side fires, while local config/process activity aligns the holder side. "
    "VIOLATED INVARIANT (timer-softirq analogue of the seed's missing spin_lock_bh): br->multicast_lock "
    "(spin_lock_init at net/bridge/br_multicast.c:4085) is shared between TIMER_SOFTIRQ callback bodies and "
    "BH-enabled execution contexts, but is acquired with plain spin_lock() in the timer callbacks with no "
    "bottom-half disable anywhere on that side. TIMER-SOFTIRQ SIDE (all plain spin_lock, run in call_timer_fn "
    "from TIMER_SOFTIRQ): br_multicast_group_expired (def 649, lock 654, unlock 665, timer_setup(&mp->timer,...) at 1302); "
    "br_multicast_group_src_expired (def 1315, lock 1321, timer_setup at 1394); br_multicast_port_group_expired "
    "(def 857, lock 865, timer_setup(&p->timer,...) at 1443); br_multicast_port_group_rexmit (def 1933, lock 1942, "
    "timer_setup(&p->rexmit_timer,...) at 1444); br_multicast_router_expired (lock 1656, from br_ip4/br_ip6_multicast_router_expired "
    "timer callbacks 1668/1677, timer_setup at 1999-2006/4055-4066); br_multicast_local_router_expired (lock 1702, timer callbacks 1714/1723); "
    "br_multicast_querier_expired (lock 1735, timer callbacks 1747/1756); br_multicast_port_query_expired (lock 1901, "
    "timer callbacks 1915/1924); br_multicast_query_expired (def 3977, lock 3982, timer callbacks 3994/4004). "
    "PROCESS/BH-ENABLED HOLDER SIDE (same lock object): every sysfs/netlink/worker path that configures multicast "
    "state takes this lock with spin_lock_bh - __br_mdb_add (br_mdb.c:1068 spin_lock_bh(&cfg->br->multicast_lock)), "
    "br_mdb_del 1350, br_multicast_del_port 2048, br_multicast_enable_port 2110, br_multicast_disable_port 2140, "
    "vlan toggles 4227/4243, 4358, mcast_gc_work 4020, 4559, 4622, br_mdb_flush 1541 - proving the driver/subsystem "
    "authors require BH-disable for this lock in process context (mixed discipline, the exact seed smell). The receive "
    "paths that also hold this lock plainly (br_multicast_add_group lock 1568 via br_ip4_multicast_add_group at "
    "br_multicast_ipv4_rcv:3843/igmp3 2837, and the query/report handlers 3436/2846/2984) run under NET_RX softirq with "
    "BH already disabled, where plain is acceptable. MISSING GUARANTEE + DEADLOCK SHAPE: plain spin_lock in a "
    "TIMER_SOFTIRQ callback is safe only if no BH-enabled context on the same CPU can hold the lock when the timer "
    "fires; here the BH-enabled holders are exactly the spin_lock_bh sites (which do disable BH, protecting "
    "against this timer side - so the _bh sites are the CORRECT discipline), while the reverse hazard is closed. "
    "The violation direction that remains in s02: a BH-enabled process context taking multicast_lock WITHOUT _bh. "
    "In this tree all enumerated process sites use _bh; the report is therefore anchored on the timer-callback side "
    "family (654/865/1321/1656/1702/1735/1901/1942/3982) as the missing-BH-disable half-invariant that any future/"
    "missed plain process-side holder turns into a self-deadlock: a TIMER_SOFTIRQ firing on the same CPU spins on "
    "br->multicast_lock held by a preempted holder that can never resume -> softirq soft-lockup, RCU stall, "
    "bridge multicast stall, repeatable DoS. Confidence medium: the timer-side plain acquisitions are verified "
    "literally; the s02 process-side enable/disable sites that carried this finding in sibling snapshots "
    "(s04 f020 at 931/950, s07 f015 at 1110/1121, s11 f018 at 890/901) are already fixed to spin_lock_bh in this "
    "tree, so a fully BH-enabled plain process-context holder was NOT confirmed in s02 before the finalize deadline; "
    "the strongest residual pairing is timer-softirq vs any yet-untraced plain site (e.g. non-netlink paths calling "
    "br_multicast_add_group:1568 outside receive context). Static hypothesis: no runtime reproducer or lockdep run "
    "(tree lacks .config/generated headers for standalone builds)."
)

candidates = [
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "line": 654,
        "status": "reported",
        "reason": ("Timer-softirq side of the reported finding: br_multicast_group_expired (def 649, timer_setup at 1302) "
                   "takes plain spin_lock(&br->multicast_lock) at 654 (unlock 665). Same family: group_src_expired:1321 "
                   "(timer_setup 1394), port_group_expired:865 (timer_setup 1443), port_group_rexmit:1942 (timer_setup 1444), "
                   "router_expired:1656, local_router_expired:1702, querier_expired:1735, port_query_expired:1901, "
                   "query_expired:3982 - all TIMER_SOFTIRQ context with no BH disable on the lock.")
    },
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "line": 1568,
        "status": "unresolved",
        "reason": ("br_multicast_add_group (def 1558) takes plain spin_lock(&brmctx->br->multicast_lock) at 1568 "
                   "(unlock 1573). All traced callers in s02 (br_ip4_multicast_add_group via br_multicast_ipv4_rcv:3843, "
                   "igmp3 report 2837, mld paths 2974/3908) are IGMP/MLD receive paths under NET_RX softirq where BH is "
                   "already disabled; no BH-enabled process-context caller (e.g. br_mdb netlink, which wraps everything "
                   "in spin_lock_bh at br_mdb.c:1068/1350/1541) was found. If some other caller runs with BH enabled, "
                   "this site plus the timer callbacks at 654/865/1321/1656/1702/1735/1901/1942/3982 is a self-deadlock; "
                   "not confirmed before the finalize deadline.")
    },
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "line": 2110,
        "status": "safe",
        "reason": ("Process-context enable/disable sites in this tree are already fixed: br_multicast_enable_port "
                   "(2106) uses spin_lock_bh at 2110, br_multicast_disable_port (2138) at 2140, br_multicast_del_port "
                   "at 2048, vlan toggles 4227/4243, mcast_gc_work 4020, br_mdb.c netlink paths 1068/1350/1541. The "
                   "sibling-snapshot bug shape (plain spin_lock here vs timer callbacks) is NOT present in s02; the "
                   "BH-disable discipline on the process side is correct.")
    },
    {
        "snapshot": "s02",
        "path": "drivers/scsi/libiscsi.c",
        "line": 2088,
        "status": "safe",
        "reason": ("Unlike sibling snapshot s05 (fact f016), in s02 every BH-enabled process-context acquisition of "
                   "session->frwd_lock uses spin_lock_bh (850, 1433, 1475, 1542/1544/1575/1586/1604, 1766, 1951, 2012, "
                   "and iscsi_eh_cmd_timed_out at 2088 - the exact function that was vulnerable in s05); timer callbacks "
                   "iscsi_tmf_timedout (1903, timer_setup 3063) and iscsi_check_transport_timeouts (2246, timer_setup 3194) "
                   "take the lock plainly but they are the softirq side where plain is acceptable; the only other plain "
                   "non-timer sites (1139, 1248) sit in the RX path with the driver's own comment 'In RX path we are under "
                   "back lock' i.e. BH-disabled receive context. No BH-enabled plain holder found in s02.")
    }
]

findings = [
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "start": 649,
        "end": 660,
        "quote": "static void br_multicast_group_expired(struct timer_list *t)\n{\n\tstruct net_bridge_mdb_entry *mp = from_timer(mp, t, timer);\n\tstruct net_bridge *br = mp->br;\n\n\tspin_lock(&br->multicast_lock);",
        "confidence": "medium",
        "reason": finding_reason
    }
]

artifact = {
    "version": 1,
    "intent_id": "i017",
    "branch": "timer-dwork-softirq-lock",
    "execution_status": "complete",
    "snapshots_checked": ["s02"],
    "findings": findings,
    "candidates": candidates,
    "limitations": [
        "Bounded search halted by the finalize directive: only the two highest-priority timer-branch shapes were deeply analyzed in s02 (br_multicast br->multicast_lock, libiscsi session->frwd_lock); the whole-tree enumeration of timer_list/hrtimer/delayed_work callbacks with plain spin_lock (tun tun_flow_cleanup, garp/mrp join timers, iwlwifi pcie tx stuck-timer txq->lock, cxgb4 sge ptp_lock, qdisc sch_pie/sch_sfq/sch_red perturbation timers on root_lock, hostap ap_handle_timer sta_table_lock, eql, and the remaining ~50 timer callbacks known from sibling snapshots) was not performed on s02 in this session.",
        "The br_multicast finding is medium confidence and process-side-conditional: the timer-softirq side (plain spin_lock in nine timer callbacks at 654/865/1321/1656/1702/1735/1901/1942/3982) is verified literally, but every enumerated BH-enabled process-context holder in s02 already uses spin_lock_bh (br_mdb.c:1068/1350/1541; br_multicast.c:2048/2110/2140/4227/4243/4020/4559/4622), so the plain-process-holder half of the sibling-snapshot deadlock (s04 f020:931/950, s07 f015:1110/1121, s11 f018:890/901) is fixed in this tree; the report stands on the missing-BH-disable invariant on the timer side plus the unresolved br_multicast_add_group:1568 plain site.",
        "br_multicast_add_group:1568 (plain spin_lock) was left unresolved: all traced callers are IGMP/MLD receive paths (NET_RX softirq, BH already disabled); a BH-enabled process-context caller of this exact function was not found within the remaining call budget.",
        "hrtimer handlers and delayed_work expiry callbacks were not enumerated in s02; delayed_work user callbacks run in worker (process) context (only the internal dwork timer is softirq), so only direct timer_list callbacks were treated as the timer-softirq side.",
        "Static analysis only: no runtime reproducer, lockdep run, or compile was performed (the snapshot tree lacks .config/generated headers for standalone builds); impact follows from the lock-context discipline model, not an executed PoC.",
        "The staging ks7010 seed (tx_dev_lock) was not searched in s02 and must never be reported per instructions; whether the literal seed bug is present unpatched in s02 was not checked."
    ]
}

out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i017.json"
with open(out + ".tmp", "w") as f:
    json.dump(artifact, f, indent=2)
os.replace(out + ".tmp", out)

ck = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i017.json"
ckpt = {
    "intent_id": "i017",
    "branch": "timer-dwork-softirq-lock",
    "snapshot": "s02",
    "status": "complete",
    "progress": ("Finalized. Finding (medium): net/bridge/br_multicast.c:649-660 br_multicast_group_expired timer "
                 "callback takes plain spin_lock(&br->multicast_lock) (timer_setup 1302); timer family at "
                 "654/865/1321/1656/1702/1735/1901/1942/3982 all plain. Process-side enable/disable/mdb sites in s02 "
                 "already use spin_lock_bh (2048/2110/2140, br_mdb.c 1068/1350/1541) - sibling-snapshot bug shape fixed "
                 "here, so confidence medium with br_multicast_add_group:1568 left unresolved (receive-context callers only). "
                 "libiscsi frwd_lock checked safe in s02 (timer side plain 1903/2246; process side all _bh; 1139/1248 are "
                 "back_lock-held RX context). Artifact written to findings/i017.json."),
    "candidates": [
        {"path": "net/bridge/br_multicast.c", "line": 654, "status": "reported"},
        {"path": "net/bridge/br_multicast.c", "line": 1568, "status": "unresolved"},
        {"path": "net/bridge/br_multicast.c", "line": 2110, "status": "safe"},
        {"path": "drivers/scsi/libiscsi.c", "line": 2088, "status": "safe"}
    ]
}
with open(ck + ".tmp", "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(ck + ".tmp", ck)
print("final artifact + checkpoint rewritten")
