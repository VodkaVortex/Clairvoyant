import json, os
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/checkpoints/i008.json"
d = {
  "intent_id": "i008",
  "branch": "loop-parser-stale-state",
  "snapshot": "s02",
  "status": "in_progress",
  "note": "Initial checkpoint before search. Searching snapshots/s02 only for TLV/option/record parse loops and next-record helpers where pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize runs inside the loop/helper while pointer/offset/length state captured earlier stays live and is dereferenced later (pep_get_sb shape).",
  "candidates": [],
  "queries_planned": [
    "grep pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize in net/ with loop context",
    "grep skb_header_pointer usages near pulls",
    "grep next-record helpers: next_tlv, next_opt, parse loop while(...)"
  ]
}
tmp = p + ".tmp"
with open(tmp, "w") as f:
    json.dump(d, f, indent=2)
os.replace(tmp, p)
print("wrote", p)
