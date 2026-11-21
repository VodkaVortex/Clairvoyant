import json, os
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/checkpoints/i021.json"
data = {
  "intent_id": "i021",
  "branch": "gro-frag-stale-ptr",
  "snapshot": "s05",
  "status": "in_progress",
  "stage": "initial checkpoint before first search",
  "plan": [
    "grep skb_gro_header_pointer/skb_gro_header_slow/skb_gro_pull/skb_gro_receive/pskb_may_pull in net/ and drivers/ of s05",
    "read GRO core (net/core/gro.c or dev.c, include/net/gro.h or netdevice.h) for frag0/NAPI_GRO_CB semantics",
    "deep-read per-protocol *_gro_receive/*_gro_complete handlers (udp, tcp, gre, fou/gue, geneve, vxlan, ip6, sctp, mpls, nsh, esp)",
    "read GSO segmenters (__skb_udp_tunnel_segment etc.) for capture->pskb_may_pull->stale use",
    "audit frag-list walkers (skb_cow_data, frag list consumers)"
  ],
  "candidates": [],
  "findings": []
}
with open(p, "w") as f:
    json.dump(data, f, indent=2)
print("wrote", p)
