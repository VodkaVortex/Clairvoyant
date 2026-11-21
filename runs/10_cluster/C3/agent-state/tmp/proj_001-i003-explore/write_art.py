import json, time, os
art = {
  "version": 1,
  "intent_id": "i003",
  "branch": "unchecked-tb-deref",
  "execution_status": "complete",
  "snapshots_checked": ["s01"],
  "findings": [
    {
      "snapshot": "s01",
      "path": "drivers/net/gtp.c",
      "start": 1111,
      "end": 1122,
      "quote": "\tif (nla[GTPA_MS_ADDRESS]) {\n\t\t__be32 ip = nla_get_be32(nla[GTPA_MS_ADDRESS]);\n\n\t\treturn ipv4_pdp_find(gtp, ip);\n\t} else if (nla[GTPA_VERSION]) {\n\t\tu32 gtp_version = nla_get_u32(nla[GTPA_VERSION]);\n\n\t\tif (gtp_version == GTP_V0 && nla[GTPA_TID])\n\t\t\treturn gtp0_pdp_find(gtp, nla_get_u64(nla[GTPA_TID]));\n\t\telse if (gtp_version == GTP_V1 && nla[GTPA_I_TEI])\n\t\t\treturn gtp1_pdp_find(gtp, nla_get_u32(nla[GTPA_I_TEI]));\n\t}",
      "confidence": "low",
      "reason": ("CHECK-VALIDATED-ATTR-THEN-CONSUME-OTHERS structural variant of the seed's unchecked-tb-deref mechanism, reported at low confidence because the memory-safety of this specific instance could not be broken. Untrusted source: GTP_CMD_DELPDP (gtp_genl_del_pdp, drivers/net/gtp.c:1140) and GTP_CMD_GETPDP (gtp_genl_get_pdp, drivers/net/gtp.c:1209) are generic-netlink doit handlers (flags GENL_ADMIN_PERM, policy gtp_genl_policy at 1293 which marks NO attribute required/NLA_NESTED, so any attrs[] slot can be NULL for an attacker-crafted message). Presence guarantee checked: both handlers validate ONLY !info->attrs[GTPA_VERSION] (lines 1145 and 1214) before calling gtp_find_pdp(sock_net(skb->sk), info->attrs), which dereferences optional GTPA_LINK (line 1126 'if (nla[GTPA_LINK])') and then version-dependent siblings GTPA_MS_ADDRESS / GTPA_TID / GTPA_I_TEI inside gtp_find_pdp_by_link. Validated-vs-used mismatch: the attribute the handler proves present (GTPA_VERSION, whose VALUE the attacker also fully controls and which decides which sibling is consumed) is not the attribute consumed. Counterevidence checked line by line: each consumed slot IS covered by an inline same-slot presence test (GTPA_MS_ADDRESS at 1111, GTPA_TID at 1120 under 'gtp_version == GTP_V0 && nla[GTPA_TID]', GTPA_I_TEI at 1121-1122 under 'gtp_version == GTP_V1 && nla[GTPA_I_TEI]', GTPA_LINK via gtp_find_dev line 894 'nla_get_u32(nla[GTPA_LINK])' guarded at 1126), so the short-circuit && prevents a NULL deref here and the invariant is ultimately satisfied at the use site; contrast gtp_genl_new_pdp (1046-1072) which validates the sibling attrs before gtp_pdp_add/ipv4_pdp_fill consume them. Impact if the pattern were weakened (guard testing the version slot but consuming siblings unguarded) would be a NULL-pointer dereference (nla_get_* -> *(__u32 *)nla_data(NULL)) from a crafted genl message; as written, no NULL deref is established, hence low confidence."
    }
  ],
  "candidates": [
    {
      "snapshot": "s01",
      "path": "drivers/net/gtp.c",
      "line": 1125,
      "status": "reported",
      "reason": "gtp_genl_del_pdp (1140) / gtp_genl_get_pdp (1209) validate only GTPA_VERSION (1145/1214) yet gtp_find_pdp consumes optional GTPA_LINK/MS_ADDRESS/TID/I_TEI (policy 1293-1303 marks none required); reported at low confidence as the structural validated-attr != consumed-attr variant because same-slot inline guards in gtp_find_pdp_by_link (1111, 1120, 1121-1122) ultimately cover every dereference."
    },
    {
      "snapshot": "s01",
      "path": "kernel/taskstats.c",
      "line": 497,
      "status": "safe",
      "reason": "cmd_attr_pid()/cmd_attr_tgid() call nla_get_u32(info->attrs[TASKSTATS_CMD_ATTR_PID/TGID]) with no local guard, but dispatcher taskstats_user_cmd() (538-548) routes to each handler only when that same slot is non-NULL; REGISTER/DEREGISTER_CPUMASK parses (446/462) are only invoked from guarded branches (542-544); CGROUPSTATS_CMD_ATTR_FD checked at 398-400."
    },
    {
      "snapshot": "s01",
      "path": "net/core/drop_monitor.c",
      "line": 1157,
      "status": "safe",
      "reason": "net_dm_alert_mode_get_from_info() dereferences info->attrs[NET_DM_ATTR_ALERT_MODE] unguarded, but sole caller net_dm_alert_mode_set() checks '!info->attrs[NET_DM_ATTR_ALERT_MODE]' at 1177 first; TRUNC_LEN/QUEUE_LEN guarded at 1193/1201; SW_DROPS/HW_DROPS use NULL-safe '!!info->attrs[...]' at 1268-1269."
    },
    {
      "snapshot": "s01",
      "path": "net/hsr/hsr_netlink.c",
      "line": 247,
      "status": "safe",
      "reason": "hsr_get_node_status checks HSR_A_IFINDEX (247-249) AND HSR_A_NODE_ADDR (250-252) before nla_get_u32/nla_data of those same slots (255, 283, 294); hsr_get_node_list checks HSR_A_IFINDEX (376-378) before its use (381)."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv6/seg6.c",
      "line": 96,
      "status": "safe",
      "reason": "seg6_hmac attrs guarded with a correct || chain (HMACKEYID/SECRETLEN/ALGID at 96-98), SECRET at 123, DST at 173; every nla_get/nla_data follows its same-slot check."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv6/ila/ila_xlat.c",
      "line": 101,
      "status": "safe",
      "reason": "All five attrs uses (LOCATOR, LOCATOR_MATCH, CSUM_MODE, IDENT_TYPE, IFINDEX at 101-121) are inside 'if (info->attrs[X])' presence branches."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv4/fou.c",
      "line": 683,
      "status": "safe",
      "reason": "Every attrs[] use in fou config parsing is inside an 'if (info->attrs[X])' or 'else if' presence branch (AF 683, PORT 699, IPPROTO 704, TYPE 707, LOCAL_V4/PEER_V4/LOCAL_V6/PEER_V6 714-734, PEER_PORT 742, IFINDEX 750)."
    },
    {
      "snapshot": "s01",
      "path": "drivers/block/nbd.c",
      "line": 1781,
      "status": "safe",
      "reason": "All dereferenced attrs guarded inline (SIZE_BYTES 1781, BLOCK_SIZE_BYTES 1784, INDEX 1811 with explicit '!info->attrs[NBD_ATTR_INDEX]' rejects at 1998/2039, TIMEOUT 1902, DEAD_CONN_TIMEOUT 1905, SERVER_FLAGS 1910, CLIENT_FLAGS 1913, SOCKETS with '!info->attrs[NBD_ATTR_SOCKETS]' at 1813 and presence-branch iteration at 1929/2112)."
    },
    {
      "snapshot": "s01",
      "path": "net/l2tp/l2tp_netlink.c",
      "line": 171,
      "status": "safe",
      "reason": "Required attrs (CONN_ID 171, PEER_CONN_ID 177, PROTO_VERSION 183, ENCAP_TYPE 189, SESSION_ID 531, PEER_SESSION_ID 537, PW_TYPE 543) each checked with '!info->attrs[...]' before nla_get_* of the same slot; optional attrs (FD 196, IP6_SADDR/DADDR 200, IP_SADDR/DADDR 208, UDP_SPORT/DPORT 218-221, COOKIE 571-578, PEER_COOKIE 580-587, IFNAME 589, DEBUG 233/311/593) used only inside presence branches; no check-one-use-sibling case found."
    },
    {
      "snapshot": "s01",
      "path": "drivers/target/target_core_user.c",
      "line": 358,
      "status": "safe",
      "reason": "Handler guards both required attrs with correct || logic ('!info->attrs[TCMU_ATTR_CMD_STATUS] || !info->attrs[TCMU_ATTR_DEVICE_ID]' at 358-359) before nla_get_u32/nla_get_s32 of those same slots (364-365); SUPP_KERN_CMD_REPLY use at 419-421 inside a presence 'if'."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/wireless/mac802154_hwsim.c",
      "line": 1,
      "status": "unresolved",
      "reason": "File (distinct from the seed's drivers/net/ieee802154/mac802154_hwsim.c) has 9 nla_data(info->attrs) and 11 nla_get(info->attrs) uses not yet cross-checked against its per-command policies; the finalize instruction stopped the audit before this file."
    },
    {
      "snapshot": "s01",
      "path": "net/wireless/nl80211.c",
      "line": 1,
      "status": "unresolved",
      "reason": "121 nla_data(info->attrs) + ~128 nla_get(info->attrs) uses across hundreds of commands with per-command policies; only nla_get_flag sites (4785, 4796, 7707, 7716, 9239, 9563, 10361, 10601, ...) were inspected and are NULL-safe by helper semantics; full per-handler policy cross-check not completed."
    },
    {
      "snapshot": "s01",
      "path": "net/netlabel/netlabel_mgmt.c",
      "line": 1,
      "status": "unresolved",
      "reason": "netlabel_mgmt.c (5 nla_data + 5 nla_get uses) plus netlabel_unlabeled.c (8 nla_data uses) and netlabel_cipso_v4.c/netlabel_calipso.c (4 each) were only spot-checked for guard style; per-handler policy cross-check unfinished."
    },
    {
      "snapshot": "s01",
      "path": "net/ieee802154/nl-mac.c",
      "line": 1,
      "status": "unresolved",
      "reason": "52 nla_get(info->attrs) uses in the ieee802154 subsystem (adjacent to the seed's subsystem, elevated residual risk) not yet fully cross-checked against ieee802154 policies."
    },
    {
      "snapshot": "s01",
      "path": "net/ncsi/ncsi-netlink.c",
      "line": 1,
      "status": "unresolved",
      "reason": "17 nla_get(info->attrs) uses; the 2 inspected (MULTI_FLAG at 609/701) are NULL-safe nla_get_flag calls; remaining per-handler checks unfinished."
    }
  ],
  "limitations": [
    "Audit bounded to generic-netlink doit handlers that dereference info->attrs[] slots directly; tb[]-based netfilter/ipset/tc/bridge paths were only enumerated by file counts, and rtnetlink RTM_* doit paths belong to intent i005.",
    "nl80211.c (largest consumer), drivers/net/wireless/mac802154_hwsim.c, net/netlabel/*, net/ieee802154/nl-mac.c and net/ncsi/ncsi-netlink.c remain handler-by-handler unverified; a real unchecked-slot variant may survive there.",
    "The reported GTP candidate is structural only: same-slot inline guards cover every dereference, so no NULL-pointer dereference is established; it is kept as a low-confidence hypothesis of the validated-attr-vs-consumed-attr branch shape, not an exploit claim.",
    "No compilation or dynamic reproducer was run; nla_get_* NULL behavior is taken from static reading of include/net/netlink.h (nla_get_u32 -> *(__u32 *)nla_data(nla), nla_data -> nla->nla_data, no NULL check).",
    "The seed instance drivers/net/ieee802154/mac802154_hwsim.c:hwsim_del_edge_nl was read only to confirm the tree matches the seed patch context and is excluded from findings by rule."
  ]
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/findings/i003.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(art, f, indent=2)
cp = {
  "intent_id": "i003",
  "branch": "unchecked-tb-deref",
  "phase": "final",
  "snapshot": "s01",
  "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "status": "complete",
  "final_artifact": path,
  "summary": ("One low-confidence structural candidate (GTP: handlers validate only GTPA_VERSION but gtp_find_pdp consumes optional siblings, drivers/net/gtp.c:1100-1134); no NULL-deref confirmed because same-slot inline guards cover all uses. Safe: taskstats, drop_monitor, hsr, seg6, ila_xlat, fou, nbd, l2tp, tcmu (all with concrete inline-guard evidence). Unresolved: nl80211, wireless mac802154_hwsim, netlabel, ieee802154 nl-mac, ncsi.")
}
cppath = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/checkpoints/i003.json"
with open(cppath, "w") as f:
    json.dump(cp, f, indent=2)
print("artifact written:", path)
print("checkpoint updated:", cppath)
