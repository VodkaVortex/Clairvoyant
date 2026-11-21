import json, os

# ---- checkpoint update ----
cp_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i022.json"
state = {
  "intent_id": "i022",
  "branch": "timer-dwork-softirq-lock",
  "snapshot": "s07",
  "status": "complete",
  "note": "Enumerated 70 timer-softirq callbacks containing plain spin_lock via scripted scan (timer_setup/setup_timer/DEFINE_TIMER/.function). Deep lock-object pairing completed for br_multicast br->multicast_lock (REPORTED, medium), tun tun->lock (safe), garp/mrp app->lock (safe), bcm63xx_enet rx_lock (safe). Unresolved: iwlwifi txq->lock stuck timer, cxgb4 ptp_lock, qdisc root_lock (pie/sfq/red), hostap sta_table_lock.",
  "candidates": [
    {"file": "net/bridge/br_multicast.c", "line": 1110, "status": "reported"},
    {"file": "drivers/net/tun.c", "line": 495, "status": "safe"},
    {"file": "net/802/garp.c", "line": 408, "status": "safe"},
    {"file": "net/802/mrp.c", "line": 593, "status": "safe"},
    {"file": "drivers/net/ethernet/broadcom/bcm63xx_enet.c", "line": 303, "status": "safe"},
    {"file": "drivers/net/wireless/intel/iwlwifi/pcie/tx.c", "line": 158, "status": "unresolved"},
    {"file": "drivers/net/ethernet/chelsio/cxgb4/sge.c", "line": 3306, "status": "unresolved"},
    {"file": "net/sched/sch_pie.c", "line": 433, "status": "unresolved"},
    {"file": "drivers/net/wireless/intersil/hostap/hostap_ap.c", "line": 215, "status": "unresolved"}
  ],
  "timestamp": "finalized"
}
os.makedirs(os.path.dirname(cp_path), exist_ok=True)
tmp = cp_path + ".tmp"
open(tmp, "w").write(json.dumps(state, indent=2))
os.replace(tmp, cp_path)

# ---- final artifact ----
quote = (
    "void br_multicast_disable_port(struct net_bridge_port *port)\n"
    "{\n"
    "\tstruct net_bridge *br = port->br;\n"
    "\tstruct net_bridge_port_group *pg;\n"
    "\tstruct hlist_node *n;\n"
    "\n"
    "\tspin_lock(&br->multicast_lock);"
)

finding = {
    "snapshot": "s07",
    "path": "net/bridge/br_multicast.c",
    "start": 1115,
    "end": 1121,
    "quote": quote,
    "confidence": "medium",
    "reason": (
        "Lock object br->multicast_lock (spinlock_t in struct net_bridge, spin_lock_init at net/bridge/br_multicast.c:1981) "
        "is shared between TIMER-softirq callbacks and process-context code with the process side missing the bottom-half disable (timer-softirq analogue of the seed's missing spin_lock_bh). "
        "TIMER SOFTIRQ SIDE (all plain spin_lock, no _bh): br_multicast_group_expired (def at 242, spin_lock(&br->multicast_lock) at 248, registered via timer_setup(&mp->timer, br_multicast_group_expired, 0) at 705), "
        "br_multicast_port_group_expired (def at 306, lock at 311, timer_setup at 732), br_multicast_router_expired (def at 848, lock at 854, timer_setup at 1982), br_multicast_local_router_expired (def at 878, lock at 882), "
        "br_multicast_port_query_expired (def at 998, lock at 1003, timer_setup for ip4/ip6_own_query at 1051/1054) and the querier-expired callbacks registered at 1984/1986/1989/1991 (plain lock at 896). "
        "These run in call_timer_fn from TIMER_SOFTIRQ. "
        "PROCESS SIDE (same lock object, plain spin_lock): br_multicast_enable_port (def at 1106, spin_lock(&br->multicast_lock) at 1110) and br_multicast_disable_port (def at 1115, plain lock at 1121, unlock at 1133) - reached from the STP port enable/disable paths (br_stp_enable_port/br_stp_disable_port: netlink port-state changes, bridge/port carrier handling, bridge stop), i.e. process context. "
        "UNSAFE USE: while a process-context holder holds br->multicast_lock acquired with plain spin_lock (preemption disabled but BHs enabled) at 1110/1121, a TIMER softirq firing on the same CPU executes br_multicast_group_expired/br_multicast_router_expired etc. and spins forever on the same lock at 248/311/854/882/1003; the holder can never resume because a softirq does not yield to process context -> soft lockup on one CPU, watchdog/RCU stall splats, bridge multicast (IGMP/MLD snooping) processing stall, repeatable denial of service. "
        "UNTRUSTED SOURCE: attacker-influenced concurrency triggers, not data - any IGMP/MLD report that creates multicast groups with expiry timers (timer side) plus any bridge port state change / bridge stop / carrier event on the same CPU (process side); both are reachable from an unprivileged user namespace (bridges and IGMP traffic require no special privilege). "
        "COUNTEREVIDENCE CHECKED: the same file already uses the correct discipline on the same lock object at other process-context sites - br_multicast_del_port uses spin_lock_bh at 1073 and br_multicast_dev_del uses spin_lock_bh at 2034 (plus _bh sites 2034/2053/2068/2175/2225/2238/2272 in the sysfs/netlink config paths) - proving the lock is BH-shared and that the plain acquisitions at 1110/1121 (and the plain NET_RX-side sites 1443/1522/1601) are the defect, not the rule. "
        "No local_bh_disable() wraps br_multicast_enable_port/br_multicast_disable_port. This mirrors the upstream bridge multicast lock-discipline cleanups that later converted these paths to spin_lock_bh."
    ),
}

artifact = {
    "version": 1,
    "intent_id": "i022",
    "branch": "timer-dwork-softirq-lock",
    "execution_status": "complete",
    "snapshots_checked": ["s07"],
    "findings": [finding],
    "candidates": [
        {"snapshot": "s07", "path": "net/bridge/br_multicast.c", "line": 1110,
         "status": "reported",
         "reason": ("REPORTED as the finding: br->multicast_lock shared between TIMER-softirq callbacks "
                    "(group_expired:248, port_group_expired:311, router_expired:854, local_router_expired:882, "
                    "port_query_expired:1003, querier_expired:896; timer_setup at 705/732/1051/1054/1982/1984-1991) "
                    "and process-context br_multicast_enable_port (1110) / br_multicast_disable_port (1121), all plain spin_lock; "
                    "sibling process sites del_port (1073) and dev_del (2034) correctly use spin_lock_bh, showing mixed discipline on the same lock object.")},
        {"snapshot": "s07", "path": "drivers/net/tun.c", "line": 495,
         "status": "safe",
         "reason": ("tun_flow_cleanup timer callback (def at 485) takes plain spin_lock(&tun->lock) at 495, but every other "
                    "acquisition of tun->lock in the file uses spin_lock_bh (457, 472, 541, 2264); the plain site is the softirq side itself, "
                    "so no process-context plain holder exists for a timer softirq to spin against.")},
        {"snapshot": "s07", "path": "net/802/garp.c", "line": 408,
         "status": "safe",
         "reason": ("garp_join_timer (def at 404) takes plain spin_lock(&app->lock) at 408, but all process-context sites use "
                    "spin_lock_bh (352, 372, 613) and the other plain site (523, garp_pdu_parse_msg) is the NET_RX softirq receive side; "
                    "the plain acquisitions are on the softirq side, so the invariant (process side must use _bh) is satisfied.")},
        {"snapshot": "s07", "path": "net/802/mrp.c", "line": 593,
         "status": "safe",
         "reason": ("mrp_join_timer (593) and mrp_periodic_timer (612) take plain spin_lock(&app->lock), but process-context sites use "
                    "spin_lock_bh (532, 557, 899) and the other plain site (803) is the PDU-parse NET_RX softirq side; same shape as garp, invariant satisfied.")},
        {"snapshot": "s07", "path": "drivers/net/ethernet/broadcom/bcm63xx_enet.c", "line": 303,
         "status": "safe",
         "reason": ("bcm_enet_refill_rx_timer (def at 298) takes plain spin_lock(&priv->rx_lock) at 303; the only other acquisition in the file "
                    "is bcm_enet_poll (NAPI poll, NET_RX softirq) at 500, also plain. Both sides are softirq-context, and a softirq cannot preempt "
                    "another softirq on the same CPU, so the holder-can-never-resume shape is absent; no process-context plain site exists (only spin_lock_init at 1846/2726).")},
        {"snapshot": "s07", "path": "drivers/net/wireless/intel/iwlwifi/pcie/tx.c", "line": 158,
         "status": "unresolved",
         "reason": ("iwl_pcie_txq_stuck_timer (def at 152) takes plain spin_lock(&txq->lock) at 158 inside a timer_list callback. "
                    "Whether every non-softirq site of the same txq->lock uses spin_lock_irqsave (which would also exclude the timer softirq via hard-IRQ disable) "
                    "was not enumerated before the finalize deadline; the pcie/rx.c and trans.c sibling files have high plain-spin_lock density.")},
        {"snapshot": "s07", "path": "drivers/net/ethernet/chelsio/cxgb4/sge.c", "line": 3306,
         "status": "unresolved",
         "reason": ("sge_tx_timer_cb (def at 3286) takes plain spin_lock(&adap->ptp_lock) at 3306 in a timer callback; "
                    "the full set of ptp_lock acquisition sites and their contexts was not traced before the finalize deadline.")},
        {"snapshot": "s07", "path": "net/sched/sch_pie.c", "line": 433,
         "status": "unresolved",
         "reason": ("pie_timer (def at 427) takes plain spin_lock(root_lock) at 433 (same shape: sch_sfq.c:615 sfq_perturbation, "
                    "sch_red.c:265 red_adaptative_timer). root_lock is the shared qdisc lock; process-context xmit sites take it under rcu_read_lock_bh "
                    "in dev_queue_xmit/__dev_xmit_skb, but whether qdisc change/reset/dump process paths (netlink tc) acquire root_lock without _bh was not verified before the deadline.")},
        {"snapshot": "s07", "path": "drivers/net/wireless/intersil/hostap/hostap_ap.c", "line": 215,
         "status": "unresolved",
         "reason": ("ap_handle_timer (def at 175) takes plain spin_lock(&ap->sta_table_lock) at 215 in a timer callback; "
                    "the process-context sites of sta_table_lock in this snapshot (plain vs spin_lock_bh mix) were not enumerated before the finalize deadline; "
                    "prior analysis of the same file in sibling snapshots found the process-context sites using _bh, which would make this safe, but s07-specific verification is incomplete.")},
    ],
    "limitations": [
        "Search bounded to snapshot s07 only, as required; no other snapshot was inspected.",
        "Static source analysis only: no runtime reproducer, lockdep run, or compile was performed (the snapshot tree lacks .config and generated headers for standalone builds); the br_multicast deadlock is a source-level hypothesis.",
        "The process-context callers of br_multicast_enable_port/br_multicast_disable_port (br_stp_enable_port/br_stp_disable_port from netlink port-state change, bridge stop, and carrier handling) were established from the standard bridge call model rather than line-level tracing inside s07, which is reflected in medium confidence.",
        "A scripted enumeration found 70 timer_list/DEFINE_TIMER callbacks containing plain spin_lock across the tree; deep lock-object pairing was completed only for br_multicast.c (br->multicast_lock), tun.c (tun->lock), garp.c/mrp.c (app->lock) and bcm63xx_enet.c (rx_lock).",
        "Unresolved candidates left for follow-up: iwlwifi pcie/tx.c txq->lock stuck-timer, cxgb4 sge.c adap->ptp_lock, qdisc root_lock in sch_pie/sch_sfq/sch_red perturbation timers, hostap ap_handle_timer sta_table_lock.",
        "hrtimer callback bodies and delayed_work timer-expiry paths were only partially enumerated (the scan keyed on timer_setup/setup_timer/DEFINE_TIMER/.function); hrtimer users whose init uses other macro forms may be missed.",
        "The presence of the literal ks7010 seed bug in s07 was not checked; per instructions the seed is a demonstration only and must never be reported regardless."
    ],
}

fa_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i022.json"
os.makedirs(os.path.dirname(fa_path), exist_ok=True)
tmp = fa_path + ".tmp"
open(tmp, "w").write(json.dumps(artifact, indent=2))
os.replace(tmp, fa_path)
print("wrote", fa_path)

# verify quote occurs literally in file at the reported range
base = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s07/"
src = open(base + "net/bridge/br_multicast.c", errors="replace").read()
lines = src.split("\n")
seg = "\n".join(lines[1114:1121])
assert quote == seg, "QUOTE MISMATCH:\n%r\n---\n%r" % (quote, seg)
print("quote verified literally at net/bridge/br_multicast.c:1115-1121")
