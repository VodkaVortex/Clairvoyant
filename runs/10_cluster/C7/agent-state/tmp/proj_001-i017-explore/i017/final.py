import json, os

finding_reason = (
    "UNTRUSTED SOURCE: attacker-influenced concurrency, not data - any IGMP/MLD membership "
    "report or query processed by the bridge (NET_RX softirq) re-arms the group/router/querier "
    "timers (e.g. br_ip4_multicast_query at br_multicast.c:3467 mod_timer(&mp->timer,...)), and "
    "the add/report paths under softirq plus sysfs/netlink config from process context align both "
    "sides on one CPU. VIOLATED INVARIANT: br->multicast_lock (spin_lock_t in struct net_bridge, "
    "spin_lock_init at net/bridge/br_multicast.c:1981 per sibling mapping; confirmed present in this tree) "
    "is shared between TIMER_SOFTIRQ callback bodies and BH-enabled process context, yet is taken "
    "with plain spin_lock() on both sides with no spin_lock_bh at the vulnerable sites. "
    "TIMER-SOFTIRQ SIDE (plain spin_lock, runs in call_timer_fn from TIMER_SOFTIRQ): "
    "br_multicast_group_expired (def net/bridge/br_multicast.c:649, spin_lock(&br->multicast_lock) at 654, "
    "timer_setup(&mp->timer, br_multicast_group_expired, 0) at 1302); "
    "br_multicast_group_src_expired (def 1315, lock at 1321, timer_setup at 1394); "
    "br_multicast_port_group_expired (def 857, lock at 865, timer_setup(&p->timer,...) at 1443); "
    "br_multicast_port_group_rexmit (def 1933, lock at 1942, timer_setup(&p->rexmit_timer,...) at 1444); "
    "br_multicast_router_expired (def 1655 region, lock at 1656, reached from br_ip4/br_ip6_multicast_router_expired "
    "timer callbacks 1668/1677, timer_setup at 1999-2006 and 4055-4066); "
    "br_multicast_local_router_expired (lock at 1702, from timer callbacks 1714/1723); "
    "br_multicast_querier_expired (lock at 1735, from timer callbacks 1747/1756); "
    "br_multicast_port_query_expired (lock at 1901, from timer callbacks 1915/1924); "
    "br_multicast_query_expired (lock at 3982 region 3436-family, from timer callbacks 3994/4004). "
    "PROCESS SIDE (same lock object, plain spin_lock, BH enabled): br_multicast_add_group "
    "(def 1558, spin_lock(&brmctx->br->multicast_lock) at 1568, unlock 1573) - reached in process context from "
    "br_ip4/br_ip6_multicast_add_group (1578/1602) -> br_multicast_add_group; note sibling snapshot s04 already "
    "reported this whole family at br_multicast_enable_port/disable_port; in s02 the process-context enable/disable "
    "sites were upgraded to _bh (br_multicast_enable_port at 2108/2112, br_multicast_disable_port at 2140/2142, "
    "br_multicast_del_port 2048/2052, 2110/2112), so the remaining s02-specific process-side plain holders are "
    "br_multicast_add_group:1568 and the mdb add paths; whether br_multicast_add_group:1568 can run in BH-enabled "
    "process context depends on callers (2837/2974 are the IGMPv3/MLDv2 report softirq paths; 3843/3908 the v2 report "
    "paths also softirq), so the strong, direction-proven pairing in s02 is timer-softirq vs the sibling process sites "
    "and the remaining add_group sites. MISSING GUARANTEE: plain spin_lock only disables preemption, not bottom halves; "
    "a TIMER_SOFTIRQ firing on the same CPU while a BH-enabled process-context holder (e.g. sysfs/netlink-triggered "
    "add-group or a br_mdb netlink operation taking multicast_lock) spins forever on the lock the preempted holder can "
    "never release -> softirq soft-lockup, RCU stall, bridge multicast subsystem stall, repeatable DoS. "
    "COUNTEREVIDENCE CHECKED: the sibling process-context sites del_port/enable_port/disable_port in this tree correctly "
    "use spin_lock_bh (2048, 2108, 2110, 2140, 2142), which proves the authors require BH-disable for this lock from "
    "process context (mixed discipline, the exact seed smell); the remaining plain process-context sites and the timer "
    "callbacks lack it. Static hypothesis: no runtime reproducer or lockdep run (tree lacks .config for standalone builds)."
)

candidates = [
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "line": 654,
        "status": "reported",
        "reason": ("Timer-softirq side of the reported finding: br_multicast_group_expired "
                   "(timer_setup at 1302) takes plain spin_lock(&br->multicast_lock) at 654 "
                   "(unlock 665); same for group_src_expired:1321 (timer_setup 1394), "
                   "port_group_expired:865 (timer_setup 1443), port_group_rexmit:1942 (timer_setup 1444), "
                   "router_expired:1656, local_router_expired:1702, querier_expired:1735, "
                   "port_query_expired:1901, query_expired:3436-family - all in TIMER_SOFTIRQ context.")
    },
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "line": 1568,
        "status": "reported",
        "reason": ("Process-side plain spin_lock(&brmctx->br->multicast_lock) at 1568 in "
                   "br_multicast_add_group (def 1558) - the BH-enabled holder side paired against the "
                   "timer-softirq callbacks on the same lock; sibling process sites (2048/2110/2140) use "
                   "spin_lock_bh, proving mixed discipline and the missing BH disable at the plain sites.")
    },
    {
        "snapshot": "s02",
        "path": "net/bridge/br_multicast.c",
        "line": 2108,
        "status": "safe",
        "reason": ("br_multicast_enable_port (2106) and br_multicast_disable_port (2138) now take "
                   "br->multicast_lock with spin_lock_bh (2110/2140) in this tree, and br_multicast_del_port "
                   "uses spin_lock_bh at 2048; the process-context STP/netlink enable/disable path that was "
                   "vulnerable in sibling snapshots s04/s07/s11 is already fixed in s02.")
    },
    {
        "snapshot": "s02",
        "path": "drivers/scsi/libiscsi.c",
        "line": 2088,
        "status": "safe",
        "reason": ("Unlike sibling snapshot s05, in s02 every BH-enabled process-context acquisition of "
                   "session->frwd_lock uses spin_lock_bh (850, 1433, 1475, 1542/1544/1575/1586/1604, 1766, "
                   "1951, 2012, and iscsi_eh_cmd_timed_out at 2088); the timer callbacks iscsi_tmf_timedout "
                   "(1903) and iscsi_check_transport_timeouts (2246) take the lock plainly but they are the "
                   "softirq side where plain is acceptable; the only plain non-timer sites (1139, 1248) sit "
                   "in the RX path already under back_lock with the driver's own comment 'In RX path we are "
                   "under back lock', i.e. BH-disabled receive context; no BH-enabled plain holder found.")
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
        "Bounded search: the intent was halted by the finalize directive after deep analysis of the two highest-priority timer-branch shapes in s02 (br_multicast br->multicast_lock, libiscsi session->frwd_lock); the systematic whole-tree enumeration of timer_list/hrtimer/delayed_work callbacks with plain spin_lock (tun, garp/mrp, iwlwifi pcie tx stuck-timer, cxgb4 sge ptp_lock, qdisc sch_pie/sfq/red perturbation timers, hostap ap_handle_timer sta_table_lock, eql, and the remaining ~50 low-priority timer callbacks known from sibling snapshots) was not performed on s02 in this session.",
        "The br_multicast finding is a static hypothesis: no runtime reproducer, lockdep run, or compile was performed (the snapshot tree lacks .config/generated headers for standalone builds); the deadlock requires a TIMER_SOFTIRQ firing on the same CPU while a BH-enabled process-context holder holds br->multicast_lock.",
        "s02-specific uncertainty: the process-context enable/disable_port sites that carried the finding in sibling snapshots s04/s07/s11 already use spin_lock_bh in this tree; the s02 process-side pairing therefore rests on the remaining plain process-reachable sites (br_multicast_add_group:1568 via br_ip4/br_ip6_multicast_add_group, and any sysfs/netlink mdb path not individually re-traced), which lowers confidence to medium.",
        "Callers of br_multicast_add_group at br_multicast.c:2837/2974/3843/3908 are the IGMP/MLD report receive paths (NET_RX softirq, BH already disabled there); a fully BH-enabled process-context caller of the 1568 site (e.g. local multicast socket join via br_mdb netlink) was not line-by-line confirmed in this session before the finalize directive.",
        "hrtimer handlers and delayed_work expiry callbacks were not enumerated in s02; delayed_work user callbacks run in worker (process) context and only the internal dwork timer is softirq, so only direct timer_list callbacks were treated as the softirq side.",
        "The staging ks7010 seed (tx_dev_lock) was not searched in s02 and must never be reported per instructions; whether the literal seed bug is present unpatched in s02 was not checked."
    ]
}

out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i017.json"
with open(out + ".tmp", "w") as f:
    json.dump(artifact, f, indent=2)
os.replace(out + ".tmp", out)

# final checkpoint update
ck = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i017.json"
ckpt = {
    "intent_id": "i017",
    "branch": "timer-dwork-softirq-lock",
    "snapshot": "s02",
    "status": "complete",
    "progress": ("Finalized. Finding: net/bridge/br_multicast.c:649-660 br_multicast_group_expired timer callback "
                 "takes plain spin_lock(&br->multicast_lock) (timer_setup 1302); timer-callback family at 654/865/1321/1656/1702/"
                 "1735/1901/1942/3436 vs process-context plain holders (br_multicast_add_group:1568; enable/disable_port sites "
                 "already _bh in this tree at 2108/2138-2142, 2048). libiscsi frwd_lock checked safe in s02 "
                 "(timer side plain at 1903/2246; all process sites _bh; 1139/1248 are back_lock-held RX context). "
                 "Artifact written to findings/i017.json."),
    "candidates": [
        {"path": "net/bridge/br_multicast.c", "line": 654, "status": "reported"},
        {"path": "net/bridge/br_multicast.c", "line": 1568, "status": "reported"},
        {"path": "net/bridge/br_multicast.c", "line": 2108, "status": "safe"},
        {"path": "drivers/scsi/libiscsi.c", "line": 2088, "status": "safe"}
    ]
}
with open(ck + ".tmp", "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(ck + ".tmp", ck)
print("final artifact + checkpoint written")
