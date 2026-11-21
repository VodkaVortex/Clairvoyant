import json

findings = [
  {
    "snapshot": "s02",
    "path": "net/netfilter/nft_bitwise.c",
    "start": 158,
    "end": 179,
    "quote": "static int nft_bitwise_init(const struct nft_ctx *ctx,\n\t\t\t    const struct nft_expr *expr,\n\t\t\t    const struct nlattr * const tb[])\n{\n\tstruct nft_bitwise *priv = nft_expr_priv(expr);\n\tu32 len;\n\tint err;\n\n\terr = nft_parse_u32_check(tb[NFTA_BITWISE_LEN], U8_MAX, &len);",
    "confidence": "high",
    "reason": "Untrusted source: an NFT_MSG_NEWRULE nfnetlink message is fully attacker-controlled; nfnetlink_rcv() enforces only netlink_net_capable(skb, CAP_NET_ADMIN) (net/netfilter/nfnetlink.c), satisfiable by an unprivileged local user creating a user namespace that owns the network namespace (same trust model as the seed's GENL_UNS_ADMIN_PERM), and the nft_bitwise expression type is module-autoloadable via nft_expr_type_get/request_module (nf_tables_api.c:2605-2626). The expression's tb[] is parsed by nf_tables_expr_parse (nf_tables_api.c:2703-2706) from tb[NFTA_EXPR_DATA] under nft_bitwise_policy, which types NFTA_BITWISE_LEN/SREG/DREG as plain NLA_U32 with no required semantics, so any of these slots stays NULL when the DATA payload omits it. Violated invariant (helper-param form of the seed): nft_parse_u32_check() (nf_tables_api.c:9177-9188) immediately evaluates ntohl(nla_get_be32(attr)) on its parameter with no NULL check, and nft_bitwise_init passes tb[NFTA_BITWISE_LEN] into it with no in-function presence guard. The dispatch core does NOT close the gap for the general ops: when type->select_ops is consulted (nf_tables_expr_parse, nf_tables_api.c:2711-2726), nft_bitwise_select_ops (nft_bitwise.c:394-420) does check !tb[NFTA_BITWISE_LEN]/SREG/DREG, but that check only selects between &nft_bitwise_ops and &nft_bitwise_fast_ops; the selected ops->init (nft_bitwise_init or nft_bitwise_fast_init) is invoked afterwards by nf_tables_newexpr (nf_tables_api.c:2743-2755) with the SAME tb[] and re-dereferences tb[NFTA_BITWISE_LEN] and tb[NFTA_BITWISE_SREG]/tb[NFTA_BITWISE_DREG] without its own guard. In the non-select_ops path (any expression type whose .select_ops is NULL, with nft_bitwise registered via .select_ops this specific pair is covered; the uncovered exposure is the general pattern, but for THIS expression every entry passes select_ops), so the credible NULL path for nft_bitwise_init itself is via NFTA_BITWISE_OP=NFT_BITWISE_BOOL... [assessed below]. Concretely verified: nft_parse_register_load(tb[NFTA_BITWISE_SREG],...) (line 172) and nft_parse_register_store(ctx, tb[NFTA_BITWISE_DREG],...) (line 177) both route their parameter into nft_parse_register() (nf_tables_api.c:9190-9199) which evaluates ntohl(nla_get_be32(attr)) with no NULL check. Because nft_bitwise_type selects ops through nft_bitwise_select_ops which requires LEN/SREG/DREG present (lines 398-401), the bitwise slots are covered; HOWEVER the identical pattern in nft_exthdr is NOT covered and is the primary reported instance (see next finding). Counterevidence checked: nft_bitwise_policy entries (nft_bitwise.c:60-70 region) are typed-only (NLA_U32/NLA_NESTED), non-required; select_ops gate at 398-401; ops->init re-entry at nf_tables_api.c:2743-2755."
  }
]

# The primary finding: nft_exthdr_init/nft_exthdr_tcp_set_init consume slots their select_ops does not prove
findings.append({
  "snapshot": "s02",
  "path": "net/netfilter/nft_exthdr.c",
  "start": 511,
  "end": 531,
  "quote": "\tif (!tb[NFTA_EXTHDR_OP])\n\t\treturn &nft_exthdr_ipv6_ops;\n\n\tif (tb[NFTA_EXTHDR_SREG] && tb[NFTA_EXTHDR_DREG])\n\t\treturn ERR_PTR(-EOPNOTSUPP);",
  "confidence": "medium",
  "reason": "nft_exthdr_select_ops returns &nft_exthdr_ipv6_ops when NFTA_EXTHDR_OP is absent (line 511-512) WITHOUT proving any other attribute present; for the ipv6 ops it only requires tb[NFTA_EXTHDR_DREG] to select ipv4 ops (line 529) — when OP is absent the ipv6 ops are returned unconditionally even if tb[NFTA_EXTHDR_DREG] is NULL. ops->init = nft_exthdr_init (line 316) then requires DREG/TYPE/OFFSET/LEN (324-327) before use, so the ipv6 path is guarded in init. Similarly nft_exthdr_tcp_set_init (364) requires SREG/TYPE/OFFSET/LEN. Assessment: the select_ops gate at 522 returns nft_exthdr_tcp_set_ops only when tb[NFTA_EXTHDR_SREG] is present (proven), and tcp ops at 525 requires DREG present; each ops->init re-checks its consumed slots with ||-of-negations. No NULL slot reaches a helper parameter on the exthdr paths read. Downgraded to a documented safe-side analysis; the strong finding is nft_bitwise/init (finding 1) only in configurations where nft_bitwise_type.ops is used without select_ops, which this snapshot does not do; hence this is recorded as a candidate (safe) rather than a finding.",
})

# Drop the two weak entries; produce the real final list after verification below.

print("placeholder")
