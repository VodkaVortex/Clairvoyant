import json, sys
cp = {
  "intent_id": "i015",
  "branch": "helper-param-null-deref",
  "snapshot": "s02",
  "status": "in_progress",
  "phase": sys.argv[1] if len(sys.argv) > 1 else "initial checkpoint before first search",
  "invariant": "attribute pointer from info->attrs[N]/tb[N] (or local holding it) passed as function argument into a helper that dereferences the parameter (nla_get_*/nla_data/nla_len/nla_parse_nested*/nla_validate_nested*/nla_for_each_nested) without its own NULL check, while no caller-side presence guard or policy-required entry covers that exact attribute",
  "priority_surfaces": [
    "net/netfilter/nf_tables_api.c expression/element list helpers",
    "net/openvswitch/flow_netlink.c action parsers",
    "net/ipv4/ip_tunnel_core.c",
    "net/ipv6/seg6_local.c",
    "net/ipv4/nexthop.c",
    "net/core/lwt_bpf.c",
    "net/wireless/pmsr.c",
    "team.c",
    "qeth helpers",
    "net/core/devlink.c helpers",
    "drivers/block/drbd/drbd_nla.c",
    "intermediate-local-routed slot dereferences"
  ],
  "excluded_already_reported": ["mac802154_hwsim.c handlers", "i40e_main.c bridge setlink", "ice_main.c bridge setlink"],
  "candidates": [],
  "notes": []
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/checkpoints/i015.json"
with open(path, "w") as f:
    json.dump(cp, f, indent=2)
print("wrote", path)
