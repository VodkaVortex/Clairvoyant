import json, os, tempfile

artifact = {
  "version": 1,
  "intent_id": "i026",
  "branch": "callee-pull-caller-stale",
  "execution_status": "complete",
  "snapshots_checked": ["s05"],
  "findings": [],
  "candidates": [
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_core.h",
      "line": 309,
      "status": "safe",
      "reason": "Priority callee audited: l2tp_v3_ensure_opt_in_linear() (l2tp_core.h:301-319) internally calls pskb_may_pull(skb, off + opt_len) at line 309, which on a non-linear/cloned skb runs __pskb_pull_tail() -> pskb_expand_head() and frees/replaces skb->head (relocating every pre-call pointer into the head). However this callee is the in-tree EXEMPLAR OF THE SEED'S FIX, not a variant: it takes unsigned char **ptr and unsigned char **optr and repairs both after the pull (lines 312-315: 'if (skb->data != *optr) { *optr = skb->data; *ptr = skb->data + off; }'). The skb->data != *optr comparison detects head relocation because skb->data is recomputed to the new head after pskb_expand_head, so no caller-side captured pointer can survive stale across this call."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_core.c",
      "line": 884,
      "status": "safe",
      "reason": "Caller l2tp_udp_recv_core() (l2tp_core.c:792-897) is the UDP-encap RX entry (l2tp_udp_encap_recv -> l2tp_udp_recv_core). It performs its own pulls BEFORE capturing pointers (__skb_pull(udphdr) at 804, pskb_may_pull(skb, L2TP_HDR_SIZE_MAX) at 807, debug pskb_may_pull at 817), captures optr = ptr = skb->data at line 825, reads only scalars through ptr (hdrflags/tunnel_id/session_id, lines 828-866, within the pre-pulled L2TP_HDR_SIZE_MAX region), then calls l2tp_v3_ensure_opt_in_linear(session, skb, &ptr, &optr) at 884 passing POINTER-TO-POINTER so the callee's repair applies; the repaired ptr/optr are passed by value to l2tp_recv_common() at 887. No pre-call pointer into skb->head is dereferenced after the callee returns."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_ip.c",
      "line": 164,
      "status": "safe",
      "reason": "Caller l2tp_ip_recv() (l2tp_ip.c:113-200, raw IP L2TPv3 RX handler) captures optr = ptr = skb->data at line 129 after its own pskb_may_pull(skb, 4) at 125, re-captures optr = ptr = skb->data at 158 after the debug pull at 154, and passes &ptr/&optr to l2tp_v3_ensure_opt_in_linear at 164 (repair applies); the repaired pair is forwarded to l2tp_recv_common at 167. The pass_up branch's iph = (struct iphdr *)skb_network_header(skb) at 181 is captured AFTER the pskb_may_pull(skb, 12) at 174. No stale dereference across the callee boundary."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_ip6.c",
      "line": 177,
      "status": "safe",
      "reason": "Caller l2tp_ip6_recv() (l2tp_ip6.c:126-210) is the IPv6 twin of l2tp_ip_recv: capture at 142 after pskb_may_pull(skb, 4) at 138, debug re-capture at 171 after the pull at 167, l2tp_v3_ensure_opt_in_linear(session, skb, &ptr, &optr) at 177 with pointer-to-pointer repair, repaired pair passed to l2tp_recv_common at 180; iph = ipv6_hdr(skb) at 194 is taken after the pass_up pskb_may_pull(skb, 12) at 187. No stale dereference."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_core.c",
      "line": 734,
      "status": "safe",
      "reason": "Helper l2tp_recv_common() (l2tp_core.c:616-770) receives the caller-captured ptr/optr BY VALUE. All dereferences of ptr happen BEFORE its own interior pull: cookie memcmp at 626, v2 ns/nr reads at 648-651, v3 l2specific read at 662, v2 offset-field read at 728 (all within the region guaranteed linear by the caller's L2TP_HDR_SIZE_MAX pull or by the ensure_opt_in_linear repair). The interior pskb_may_pull(skb, offset) at line 734 -- whose length is attacker-influenced via the L2TPv2 offset field read at 728 -- is followed by NO ptr/optr dereference: only __skb_pull(skb, offset) at 737 and L2TP_SKB_CB(skb)->length/expires writes at 743-745, which target skb->cb (the control block, not skb->head) and therefore cannot be invalidated by head reallocation."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_core.c",
      "line": 413,
      "status": "safe",
      "reason": "Dequeue-side interprocedural boundary flagged as unresolved by fact f004: l2tp_recv_dequeue()/l2tp_recv_dequeue_skb() (l2tp_core.c:419-490/388-417) dispatch dequeued skbs via (*session->recv_skb)(session, skb, L2TP_SKB_CB(skb)->length) at line 413. The dequeue helpers hold no pointer into any skb->head (all state is L2TP_SKB_CB(skb) in skb->cb, immune to head reallocation), and both recv_skb callbacks registered in s05's net/l2tp/ were audited (l2tp_eth_dev_recv, pppol2tp_recv -- see below) and are safe."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_eth.c",
      "line": 145,
      "status": "safe",
      "reason": "recv_skb callback l2tp_eth_dev_recv() (l2tp_eth.c:131-176): pskb_may_pull(skb, length) at 138 (debug) and pskb_may_pull(skb, ETH_HLEN) at 145 both execute BEFORE any pointer into skb->head is captured; the only head reads are print_hex_dump_bytes(..., skb->data, length) at 141 which uses skb->data fresh after the debug pull, and the skb is then handed whole to dev_forward_skb(). No capture-then-pull-then-use chain."
    },
    {
      "snapshot": "s05",
      "path": "net/l2tp/l2tp_ppp.c",
      "line": 231,
      "status": "safe",
      "reason": "recv_skb callback pppol2tp_recv() (l2tp_ppp.c:210-256) is the correct-order twin of the seed: 'if (pskb_may_pull(skb, 2) && skb->data[0] == PPP_ALLSTATIONS && skb->data[1] == PPP_UI)' -- the pull is the left operand of && so the skb->data[0]/[1] reads at 231-232 only execute after the pull succeeds and read the POST-pull head; skb_pull(skb, 2) then follows. No pre-pull captured pointer exists in the function."
    }
  ],
  "limitations": [
    "The l2tp priority surface named by the intent was audited line-by-line to a safe conclusion, but the broader callee->caller enumeration across s05 net/ and drivers/ (census of every function containing pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize/skb_cow/skb_cow_head/pskb_expand_head with an skb parameter, then auditing each caller for a live pre-call header pointer) was drafted ($TMPDIR/i026/find_pairs.py) and not executed before the bounded search was finalized; an interprocedural stale-pointer variant outside net/l2tp/ in s05 remains unexamined by this branch.",
    "Same-function cases already classified by the concluded s05 rx-pull (fact f012) and loop-parser (fact f004) artifacts were skipped per intent: br_multicast IGMPv3 report and MLD query (including the ip_mc_may_pull thin-wrapper call sites), mpls af_mpls, phonet pep, igmp, icmp, ip_input, x25 facilities, ipv6 exthdrs_core/ip6_tunnel/ip6_offload, act_csum, xfrm decode_session6, and ipvs; the still-open s05 tx-cow and GRO/GSO passes own their respective surfaces.",
    "drivers/ RX handlers outside net/l2tp/ (wired/wireless driver *_rx handlers whose helpers may pull/cow internally) were not audited for this branch.",
    "session->recv_skb callback coverage was established by reading s05's net/l2tp/ sources: l2tp_eth_dev_recv (net/l2tp/l2tp_eth.c) and pppol2tp_recv (net/l2tp/l2tp_ppp.c) are the assignments present in-tree; assignment sites in code outside the audited scope were not exhaustively grep-confirmed.",
    "All safe classifications are static line-level source readings against the documented pskb_may_pull() -> __pskb_pull_tail() -> pskb_expand_head() head-relocation semantics (all pointers into skb->head must be reloaded after a relocating call); no dynamic reproducer or KASAN run was performed, and the pointer-repair correctness of l2tp_v3_ensure_opt_in_linear was verified by reasoning about the skb->data != *optr relocation check, not by execution.",
    "L2TP control-plane userspace paths (l2tp_ip/l2tp_ip6 pass_up to sockets) were read only for the capture/pull ordering around pskb_may_pull(skb, 12); the socket lookup paths beyond the audited line range were not fully traced."
  ]
}

out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/findings/i026.json"
d = os.path.dirname(out)
os.makedirs(d, exist_ok=True)
tmp = out + ".tmp"
with open(tmp, "w") as f:
    json.dump(artifact, f, indent=2)
os.replace(tmp, out)
print("final artifact written:", out)
print("size:", os.path.getsize(out))
