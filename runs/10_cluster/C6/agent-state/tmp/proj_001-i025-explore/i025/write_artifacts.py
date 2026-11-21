import json, os

ckpt = {
  "version": 1,
  "intent_id": "i025",
  "snapshot": "s04",
  "status": "finalized",
  "branch": "callee-pull-caller-stale",
  "findings": [
    "s04:drivers/net/wireless/marvell/mwl8k.c:1927-1990 medium: caller mwl8k_txq_xmit captures mgmt=(struct ieee80211_mgmt *)skb->data at 1927, callee mwl8k_encapsulate_tx_frame(1943)/mwl8k_add_dma_header(1945) runs pskb_expand_head at 867 freeing the old head, caller refetches only wh (1947) and then dereferences stale mgmt->u.action.category/action_code/capab at 1987/1988/1990 driving TX-queue selection (tid at 1991, mwl8k_tid_queue_mapping at 1992)."
  ],
  "candidates": [
    "s04:net/netfilter/xt_TCPMSS.c:198 safe (iph refetched after callee expand)",
    "s04:net/netfilter/xt_TCPMSS.c:221 safe (ipv6h refetched after callee expand)",
    "s04:net/l2tp/l2tp_core.c:1096 safe (helper repairs ptr/optr)",
    "s04:net/l2tp/l2tp_ip.c:166 safe (repair applies)",
    "s04:net/l2tp/l2tp_ip6.c:176 safe (repair applies)",
    "s04:drivers/net/wireless/marvell/mwl8k.c:867 reported-by-sibling i013 (callee-internal wh; new caller-side mgmt raised here)"
  ]
}
with open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/checkpoints/i025.json","w") as f:
    json.dump(ckpt, f, indent=2)

artifact = {
  "version": 1,
  "intent_id": "i025",
  "branch": "callee-pull-caller-stale",
  "execution_status": "complete",
  "snapshots_checked": ["s04"],
  "findings": [
    {
      "snapshot": "s04",
      "path": "drivers/net/wireless/marvell/mwl8k.c",
      "start": 1927,
      "end": 1990,
      "quote": "struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: the skb handed to mwl8k_txq_xmit() (drivers/net/wireless/marvell/mwl8k.c:1907) comes from the mac80211 TX path and its 802.11 header/action-frame bytes at skb->data are packet data, not kernel-private storage; under AP firmware (priv->ap_fw) the frames include station-triggered action traffic, and the values read drive hardware TX-queue selection. CAPTURE (caller): mgmt = (struct ieee80211_mgmt *)skb->data at line 1927, a raw pointer into skb->head captured before any transformation. CALLEE RELOCATING CALL: line 1943 mwl8k_encapsulate_tx_frame(priv, skb) (priv->ap_fw branch) and line 1945 mwl8k_add_dma_header(priv, skb, 0, 0) (STA branch) both funnel into mwl8k_add_dma_header() (mwl8k.c:843), which at line 866 checks priv->ap_fw && hdrlen < sizeof(struct ieee80211_cts) + REDUCED_TX_HEADROOM (8) and at line 867 calls pskb_expand_head(skb, REDUCED_TX_HEADROOM, 0, GFP_ATOMIC); pskb_expand_head allocates a new head and frees the old data area, so every pre-call pointer into the head must be reloaded. The caller refetches only wh at line 1947 ('wh = &((struct mwl8k_dma_data *)skb->data)->wh;') and never reloads mgmt. STALE USE (after callee returns): lines 1987-1988 read mgmt->u.action.category and mgmt->u.action.action_code and line 1990 reads mgmt->u.action.addba_req.capab through the pre-call pointer with no refetch; capab produces tid at 1991 which selects the TX queue/index via mwl8k_tid_queue_mapping(tid) at 1992 - a kernel TX state transition through potentially freed slab memory. This is the interprocedural twin of the seed's pep_get_sb(): pointer captured in the caller, head-relocating pull performed inside the callee, stale pointer dereferenced after the callee returns without refetching from skb->data. IMPACT: KASAN-detectable slab use-after-free read (up to ~4 bytes at 1987/1988/1990) whose result routes the frame to an attacker-influenced hardware TX queue and starts BA sessions on the wrong tid. COUNTEREVIDENCE: the skb originates from mac80211 TX (largely locally generated frames) rather than a remote RX peer, so byte-level attacker control is weaker than the seed; the expand only triggers under priv->ap_fw with short 802.11 headers (hdrlen < 26, e.g. 10-16 byte non-QoS/null frames); the stale reads influence queue selection only (no write through the stale pointer, unlike the seed's ph->sb_len -= 2); no runtime reproducer was produced."
    }
  ],
  "candidates": [
    {
      "snapshot": "s04",
      "path": "net/netfilter/xt_TCPMSS.c",
      "line": 198,
      "status": "safe",
      "reason": "tcpmss_tg4(): iph captured at 198 via ip_hdr(skb); the iph->ihl * 4 read at line 204 is an argument of the tcpmss_mangle_packet(skb, ...) call at 202 and is therefore evaluated BEFORE the callee runs; the callee's internal pskb_expand_head (xt_TCPMSS.c:155) can free/replace skb->head, but the caller explicitly refetches 'iph = ip_hdr(skb);' inside the ret > 0 branch before touching iph->tot_len/iph->check again. Correct refetch discipline; the scanner hit was the pre-call argument, not a post-return dereference."
    },
    {
      "snapshot": "s04",
      "path": "net/netfilter/xt_TCPMSS.c",
      "line": 221,
      "status": "safe",
      "reason": "tcpmss_tg6(): ipv6h captured at 221 via ipv6_hdr(skb); ipv6h->nexthdr (line 228, feeding ipv6_skip_exthdr) and sizeof(*ipv6h) (line 234, a call argument) are both evaluated before tcpmss_mangle_packet() runs; after the callee returns the caller refetches 'ipv6h = ipv6_hdr(skb);' before updating payload_len and the CHECKSUM_COMPLETE csum. No post-return stale dereference."
    },
    {
      "snapshot": "s04",
      "path": "net/l2tp/l2tp_core.c",
      "line": 1096,
      "status": "safe",
      "reason": "l2tp_udp_encap_recv() captures optr = ptr = skb->data at lines 1036-1037 (after its own __skb_pull/pskb_may_pull at 804/807-area) and calls l2tp_v3_ensure_opt_in_linear(session, skb, &ptr, &optr) at 1096; the callee (net/l2tp/l2tp_core.h:317) computes opt_len from session state, pskb_may_pull()s at ~325, and then repairs both caller pointers when skb->data != *optr ('*optr = skb->data; *ptr = skb->data + off;'). This is the in-tree exemplar of the seed's fix; the repaired pair is forwarded to l2tp_recv_common() at 1101, which only dereferences ptr within the region the repair guarantees linear."
    },
    {
      "snapshot": "s04",
      "path": "net/l2tp/l2tp_ip.c",
      "line": 166,
      "status": "safe",
      "reason": "l2tp_ip_recv() passes &ptr/&optr to the same l2tp_v3_ensure_opt_in_linear() helper at line 166; the pointer-to-pointer repair covers the internal pskb_may_pull, so the pair handed to l2tp_recv_common() at 167 is post-pull valid; the debug-pull and pass_up paths re-capture from skb->data after their own pulls."
    },
    {
      "snapshot": "s04",
      "path": "net/l2tp/l2tp_ip6.c",
      "line": 176,
      "status": "safe",
      "reason": "IPv6 twin l2tp_ip6_recv(): same repairing helper call at 176 with &ptr/&optr; no stale caller-side pointer survives the callee's pull."
    },
    {
      "snapshot": "s04",
      "path": "drivers/net/wireless/marvell/mwl8k.c",
      "line": 867,
      "status": "reported",
      "reason": "The callee-internal same-function case (wh captured at 857, pskb_expand_head at 867, stale wh->frame_control read at 881 and memmove(&tr->wh, wh, hdrlen) source at 885-886) was already raised as the s04 tx-cow-head-realloc finding by the concluded sibling artifact (i013, fact f014) and is not re-counted here; this intent's new surface is the CALLER-side mgmt pointer captured at mwl8k_txq_xmit:1927 that survives the same callee expand and is dereferenced at 1987/1988/1990, which is the finding reported above."
    }
  ],
  "limitations": [
    "All classification is static source analysis on snapshots/s04; no runtime reproducer, KASAN trace, or build was produced. The reported mwl8k finding requires pskb_expand_head to actually execute (priv->ap_fw && hdrlen < sizeof(struct ieee80211_cts) + REDUCED_TX_HEADROOM, i.e. short 802.11 headers under headroom pressure) so the old head is really freed before lines 1987-1990 execute; this was argued from pskb_expand_head semantics, not demonstrated.",
    "The interprocedural scanner ($TMPDIR/i025/scan.py) indexed every function body in s04 net/ and drivers/ (.c and .h) and matched caller captures of the form 'struct T *var = skb->data cast / *_hdr(skb) / skb_header_pointer(...)' against calls to any indexed function name that itself contains pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize/skb_cow/skb_cow_head/pskb_expand_head; only 3 caller chains matched tree-wide. Calls where the skb argument is wrapped or renamed, pointer captures via macros or arithmetic not matching the regex, callees with >200-line bodies (filtered), duplicate function names (only the name set was used), and state passed through structs were not covered; arch/ and fs/ were not scanned.",
    "Indirect dispatch boundaries (function pointers such as session->recv_skb, ndo_start_xmit chains, prot->handlers, netfilter hook indirections) were not interprocedurally resolved, so a stale pointer crossing a callback boundary remains unexamined in s04.",
    "The mwl8k finding's skb is mac80211-generated TX traffic, so the degree of attacker control over the stale bytes is lower than the seed's remote-peer RX packet; whether a forwarded or injected frame with an attacker-chosen short 802.11 header can reach mwl8k_txq_xmit on AP firmware was not established.",
    "Same-function and parse-loop cases already classified by the concluded s04 artifacts (garp_pdu_parse_attr reported by i014; x25_subr, batman-adv bridge_loop_avoidance, nfc nci/hci safe; mwl8k callee-internal wh by i013; mac80211 rx/tdls/mpls/pep by i012) were deliberately not re-audited, and the still-open same-function rx-pull/tx-cow and GRO/GSO passes own their surfaces; this artifact covers only the callee-to-caller boundary."
  ]
}
with open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/findings/i025.json","w") as f:
    json.dump(artifact, f, indent=2)
print("written")
print(json.dumps(json.load(open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/findings/i025.json")), indent=1)[:400])
