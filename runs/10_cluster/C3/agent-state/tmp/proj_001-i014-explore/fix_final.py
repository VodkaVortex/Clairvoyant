import json, os
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/findings/i014.json"
with open(path) as f:
    a = json.load(f)
a["findings"] = []
a["limitations"].insert(0,
  "Negative result for branch helper-param-null-deref on s01: every helper that dereferences an nlattr parameter (nla_parse_nested_deprecated / nla_get_* / nla_data / nla_len) without its own NULL check was traced to its callers, and in each case either a caller-side presence test on the exact slot or an in-helper check covers the argument. The closest structural analogue of the seed (nfqnl_ct_parse forwarding nfqa[NFQA_CT]/nfqa[NFQA_EXP] into ctnetlink glue helpers that parse unguarded) was fully traced and is covered: nfqnl_recv_verdict gates the call on 'if (nfqa[NFQA_CT])' (nfnetlink_queue.c:1203-1206) and the helper itself NULL-checks nfqa[NFQA_EXP] at 1124 before attach_expect; the optional NLA_UNSPEC policy entries (1013-1014) therefore never feed a NULL into ctnetlink_glue_parse/ctnetlink_glue_attach_expect.")
a["limitations"].insert(1,
  "unverified-remainder: the nfqnl_recv_verdict_batch variant's gate around nfqnl_ct_parse was not re-read in this truncated session (the non-batch path was verified gated); likewise l4proto->ctnl_timeout.nlattr_to_obj implementations in nf_conntrack_proto_*.c were assumed guarded by their parse wrappers rather than read.")
with open(path + ".tmp", "w") as f:
    json.dump(a, f, indent=2)
os.replace(path + ".tmp", path)
print("rewrote", path, "findings:", len(a["findings"]), "candidates:", len(a["candidates"]))

# also update checkpoint
ck = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/checkpoints/i014.json"
c = {
  "intent_id": "i014",
  "branch": "helper-param-null-deref",
  "snapshot": "s01",
  "status": "complete",
  "note": "Finalized as bounded negative: all prioritized helper-parameter surfaces traced; every unguarded callee covered by caller-side presence test or in-helper check. nfqnl_ct_parse closest analogue classified safe.",
  "candidates": [c["reason"][:120] for c in a["candidates"]]
}
with open(ck + ".tmp", "w") as f:
    json.dump(c, f, indent=2)
os.replace(ck + ".tmp", ck)
print("updated", ck)
