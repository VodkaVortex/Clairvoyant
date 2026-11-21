import json, os

ckpt_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C4/agent-state/checkpoints/i004.json"
find_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C4/agent-state/findings/i004.json"

checkpoint = {
  "version": 1,
  "intent_id": "i004",
  "branch": "error-path-commit",
  "status": "complete",
  "snapshot": "s01",
  "notes": "Bounded search finished. Heuristic scan (4097 raw hits) over net/ and drivers/net parse/copy helpers; ~20 regions deeply read. 4 findings classified reported (bond ARP target clear-before-EINVAL; macvlan flush-before-error x2; wireguard fwmark commit + peer socket walk before set_port failure). Remaining candidates classified safe/unresolved.",
  "findings": [
    "drivers/net/bonding/bond_netlink.c:249-273",
    "drivers/net/macvlan.c:1554-1597",
    "drivers/net/macvlan.c:1376-1398",
    "drivers/net/wireguard/netlink.c:524-538"
  ]
}

artifact = {
  "version": 1,
  "intent_id": "i004",
  "branch": "error-path-commit",
  "execution_status": "complete",
  "snapshots_checked": ["s01"],
  "findings": [
    {
      "snapshot": "s01",
      "path": "drivers/net/bonding/bond_netlink.c",
      "start": 249,
      "end": 275,
      "quote": "\t\tbond_option_arp_ip_targets_clear(bond);\n\t\tnla_for_each_nested(attr, data[IFLA_BOND_ARP_IP_TARGET], rem) {\n\t\t\t__be32 target;\n\n\t\t\tif (nla_len(attr) < sizeof(target))\n\t\t\t\treturn -EINVAL;",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: rtnetlink IFLA_BOND_ARP_IP_TARGET nested attributes (CAP_NET_ADMIN-gated bond changelink/newlink write). VIOLATED INVARIANT: in bond_changelink() the entire ARP monitoring target list is destructively cleared (bond_option_arp_ip_targets_clear, line 253) BEFORE per-attribute validation; the very next statement inside the iteration loop can 'return -EINVAL' for a nested attribute shorter than sizeof(__be32), so the parse/validation failure is known yet the destructive table wipe has already executed. UNSAFE USE: the doit returns an error to the netlink caller while bond->params.arp_targets stays empty (fail-open ARP link monitoring) with no rollback; additionally, when __bond_opt_set() fails the code only 'break's, so partially-added targets persist before 'if (err) return err'. COUNTEREVIDENCE CHECKED: full block lines 249-273 read - no restore path on either error exit; the explicit nla_len() guard implies the NLA_NESTED outer policy does not pre-filter short inner attributes (otherwise the check would be dead code); attacker impact is bounded by CAP_NET_ADMIN, so this is a config-integrity/availability variant of the seed mechanism (unvalidated write side effect surviving a known error), not memory corruption."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/macvlan.c",
      "start": 1554,
      "end": 1597,
      "quote": "\t\tif (vlan->mode == MACVLAN_MODE_SOURCE &&\n\t\t    vlan->mode != mode)\n\t\t\tmacvlan_flush_sources(vlan->port, vlan);",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: rtnetlink IFLA_MACVLAN_MODE/IFLA_MACVLAN_FLAGS/IFLA_MACVLAN_MACADDR_MODE attributes (values validated for enum membership in macvlan_validate, but apply order still unsafe). VIOLATED INVARIANT: macvlan_changelink() destroys the port's source-MAC filter table (macvlan_flush_sources, line 1566) as a side effect of mode validation, before any later step has succeeded. UNSAFE USE: a later dev_set_promiscuity() failure (~line 1579, 'return err') or macvlan_changelink_sources() failure (line 1596, 'return ret') aborts with an error while the flush and even the already-committed vlan->mode = mode (line 1591, committed before the source-handling block) survive - netlink reports failure but the vlan is left switched out of SOURCE mode and/or with its source table wiped, breaking MAC filtering. COUNTEREVIDENCE CHECKED: lines 1546-1599 fully read; no rollback/restore of sources or mode on any error path; macvlan_validate (lines 1264-1331) does not constrain apply ordering, only value membership; gated by CAP_NET_ADMIN so impact is config destruction, not privilege escalation."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/macvlan.c",
      "start": 1376,
      "end": 1398,
      "quote": "\t} else if (mode == MACVLAN_MACADDR_SET) {\n\t\tmacvlan_flush_sources(vlan->port, vlan);\n\n\t\tif (addr) {\n\t\t\tret = macvlan_hash_add_source(vlan, addr);\n\t\t\tif (ret)\n\t\t\t\treturn ret;",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: rtnetlink IFLA_MACVLAN_MACADDR_DATA/MACADDR nested attribute list driving macvlan_changelink_sources() with user-chosen MACVLAN_MACADDR_SET mode. VIOLATED INVARIANT: for MACADDR_SET the handler unconditionally flushes all existing source entries (line 1380) and then attempts to re-add entries whose allocation can fail; on failure it 'return ret' immediately (lines 1383-1384 and inside the nla_for_each_attr loop at ~1396). UNSAFE USE: after the error return the vlan's source-MAC table is left empty or partially populated with no rollback, so traffic filtering is silently degraded even though the netlink request reported failure. COUNTEREVIDENCE CHECKED: full function lines 1351-1400 read; failures from macvlan_hash_add_source (allocation/hash insert) are realistic under memory pressure; gated by CAP_NET_ADMIN."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/wireguard/netlink.c",
      "start": 524,
      "end": 538,
      "quote": "\tif (info->attrs[WGDEVICE_A_FWMARK]) {\n\t\tstruct wg_peer *peer;\n\n\t\twg->fwmark = nla_get_u32(info->attrs[WGDEVICE_A_FWMARK]);\n\t\tlist_for_each_entry(peer, &wg->peer_list, peer_list)\n\t\t\twg_socket_clear_peer_endpoint_src(peer);\n\t}",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: wireguard genl WG_CMD_SET_DEVICE attributes WGDEVICE_A_FWMARK/WGDEVICE_A_LISTEN_PORT (admissible to any user with CAP_NET_ADMIN in a user-created netns that owns the wg device, per the ns_capable check at lines 514-523). VIOLATED INVARIANT: wg_set_device() performs unconditional write-side commits - ++wg->device_update_gen (line 524), wg->fwmark = nla_get_u32(...) and a full peer-list socket walk invalidating every peer's endpoint source cache (lines 526-532) - BEFORE the listen-port step whose set_port() can fail ('if (ret) goto out', lines 534-538). UNSAFE USE: on set_port() failure (e.g. port already bound) the error is returned to the user, but the fwmark change and the endpoint-cache invalidation across all peers persist - a partial application of a security-relevant routing knob after a known failure. COUNTEREVIDENCE CHECKED: the out: path (lines 596-603) only unlocks, dev_put()s and memzero_explicit()s - no rollback of fwmark or device_update_gen; flags are validated at line 512 before any commit; set_peer() and the PEERS loop (lines 580-588) correctly gate on ret, showing the fwmark block is the unguarded one."
    }
  ],
  "candidates": [
    {
      "snapshot": "s01",
      "path": "net/bridge/br_netlink.c",
      "line": 1328,
      "status": "safe",
      "reason": "br_changelink multicast knobs: presence-gated nla_get_u32/u64 stores into br->multicast_ctx fields; netlink policy (NLA_U32/NLA_U64) enforces types, nla_get_* cannot fail, and every fallible helper result (br_set_forward_delay etc.) IS checked with 'if (err) return err'. Missing range bounds is branch sysctl-unbounded-knob territory, not an ignored error return."
    },
    {
      "snapshot": "s01",
      "path": "net/bridge/br_vlan_options.c",
      "line": 488,
      "status": "safe",
      "reason": "br_vlan_process_global_one_opts: same presence-gated nla_get store pattern with *changed bookkeeping; br_multicast_set_igmp_version/querier results are checked and returned; no parse-error is swallowed."
    },
    {
      "snapshot": "s01",
      "path": "net/core/devlink.c",
      "line": 2157,
      "status": "safe",
      "reason": "devlink_nl_cmd_sb_pool_set_doit: devlink_sb_get_from_info, devlink_sb_pool_index_get_from_info and devlink_sb_th_type_get_from_info all checked with 'if (err) return err' before the size is read (attr presence checked) and passed to devlink_sb_pool_set which returns its error; no commit precedes a known failure."
    },
    {
      "snapshot": "s01",
      "path": "net/core/devlink.c",
      "line": 2374,
      "status": "safe",
      "reason": "devlink_nl_cmd_sb_port_pool_set_doit: identical structure - all *_get_from_info helpers gated on error before threshold read and devlink_sb_port_pool_set commit; safe."
    },
    {
      "snapshot": "s01",
      "path": "net/core/devlink.c",
      "line": 2637,
      "status": "safe",
      "reason": "devlink_nl_cmd_sb_tc_pool_bind_set_doit: pool_type/tc_index/pool_index lookups all error-gated before threshold commit; safe."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv4/nexthop.c",
      "line": 2667,
      "status": "safe",
      "reason": "rtm_nh_get_timer: reads u32, converts with clock_t_to_jiffies, explicitly rejects timer == ~0UL with -EINVAL and only then writes *timer_p; caller rtm_to_nh_config_grp_res checks nla_parse_nested error. Value is validated before use; no ignored failure."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/bonding/bond_options.c",
      "line": 558,
      "status": "safe",
      "reason": "bond_opt_parse: sscanf result rv explicitly guarded by 'if (!rv) goto out;' before val->value/valstr are consumed; no use of uninitialized output on failure."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/wireless/realtek/rtlwifi/debug.c",
      "line": 337,
      "status": "safe",
      "reason": "rtl_debugfs_set_write_h2c: 'if (h2c_len <= 0) return count;' guards the sscanf conversion count before h2c_data[] is packed and passed to fill_h2c_cmd; only the successfully parsed fields are used."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/macsec.c",
      "line": 4116,
      "status": "safe",
      "reason": "macsec_validate_attr: csid from nla_get_u64 is immediately switch-validated (default: -EINVAL) and icv_len is checked against MACSEC_MIN/STD_ICV_LEN plus a dummy tfm allocation test before returning 0; nothing is committed here and every invalid combination returns an error."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/vxlan.c",
      "line": 3392,
      "status": "unresolved",
      "reason": "nla_get_u32 mtu read whose use at ~3394 was flagged; not deeply read before the audit was cut short - presence-gated read then presumably dev_set_mtu-style apply; needs verification."
    },
    {
      "snapshot": "s01",
      "path": "net/batman-adv/netlink.c",
      "line": 555,
      "status": "unresolved",
      "reason": "sel_class/orig_interval nla_get_u32 reads (also line 608) with uses at 561/613; not deeply read; likely presence-gated stores with validation, but ordering of validation vs commit unverified."
    },
    {
      "snapshot": "s01",
      "path": "net/bridge/br_mdb.c",
      "line": 1035,
      "status": "unresolved",
      "reason": "nla_data(entry) used at 1036/1048 without a nearby guard in the scan window; not deeply read - may be inside a correctly-gated parse block; unverified."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/gtp.c",
      "line": 675,
      "status": "unresolved",
      "reason": "hashsize = nla_get_u32 used at 676 without visible guard in scan window; not deeply read."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/team/team.c",
      "line": 2555,
      "status": "unresolved",
      "reason": "nla_parse_nested_deprecated result err used at 2560 without nearby guard detected by the heuristic; likely a false positive (err probably checked between parse and use), but not verified line-by-line."
    }
  ],
  "limitations": [
    "Bounded scan: a heuristic line-window scanner over s01 net/ and drivers/net produced 4097 raw candidate windows; only ~20 regions were deeply read. The remaining filtered candidate list (netlink doit/setsockopt-adjacent parse sites) was not exhaustively verified before the finalize cutoff.",
    "setsockopt option handlers (net/*/sock.c, net/core/sock.c), ioctl handlers outside drivers/net (fs, drivers/tty, drivers/scsi), and procfs/sysfs write fops outside net were not systematically scanned for this branch.",
    "No compilation or runtime reproducer was built; all findings are static source-evidence hypotheses, and netlink policy tables (e.g. the NLA_NESTED policy behind IFLA_BOND_ARP_IP_TARGET) were reasoned about from the presence of explicit length checks rather than directly inspected.",
    "All reported paths are gated by CAP_NET_ADMIN (netns-capable for unprivileged users with user namespaces), so impact is partial-configuration-apply / silent state destruction on error returns rather than memory corruption; the shared mechanism with the seed is the missing error-abort between mutation and a known failure."
  ]
}

with open(ckpt_path, "w") as f:
    json.dump(checkpoint, f, indent=2)
with open(find_path, "w") as f:
    json.dump(artifact, f, indent=2)
print("checkpoint:", ckpt_path)
print("artifact:", find_path)
print(json.dumps({"findings": len(artifact["findings"]), "candidates": len(artifact["candidates"])}))
