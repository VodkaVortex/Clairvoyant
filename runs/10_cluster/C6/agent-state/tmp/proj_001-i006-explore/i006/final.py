import json, os

art = {
  "version": 1,
  "intent_id": "i006",
  "branch": "rx-pull-stale-hdr",
  "execution_status": "complete",
  "snapshots_checked": ["s02"],
  "findings": [
    {
      "snapshot": "s02",
      "path": "net/802/garp.c",
      "start": 439,
      "end": 474,
      "quote": "\tif (!pskb_may_pull(skb, ga->len))\n\t\treturn -1;\n\tskb_pull(skb, ga->len);\n\tdlen = sizeof(*ga) - ga->len;",
      "confidence": "high",
      "reason": "garp_pdu_parse_attr() in net/802/garp.c is a receive-path protocol parser (reached via garp_pdu_rcv <- stp packet handler for GARP/MRP frames from any L2 peer) that captures the header pointer 'ga = (struct garp_attr_hdr *)skb->data' at net/802/garp.c:438 after only pskb_may_pull(skb, sizeof(*ga)) = 2 bytes, then calls pskb_may_pull(skb, ga->len) at line 442 where the pull LENGTH ga->len is the attacker-controlled first byte of the untrusted GARP attribute header - exactly the pep_get_sb() shape where pskb_may_pull(skb, ph->sb_len) was driven by the packet. pskb_may_pull()/__pskb_pull_tail() can relocate skb->head via pskb_expand_head() when the skb is non-linear and the requested length spans page frags, freeing the old head, so ga becomes stale. The stale pre-pull pointer is then dereferenced repeatedly without refetching: ga->len read at line 445 (dlen = sizeof(*ga) - ga->len), ga->event read in switch (ga->event) at line 450, and ga->data passed to garp_attr_lookup(app, ga->data, dlen, attrtype) at line 474, which memcmp-scans dlen bytes through the stale address. Additionally the caller loop garp_pdu_parse_msg() (lines 489-499) holds outer-scope pointer gm = (struct garp_msg_hdr *)skb->data across the per-iteration garp_pdu_parse_attr()/garp_pdu_parse_end_mark() helpers that pskb_may_pull internally, and then uses gm->attrtype in the next iteration (line 493) - the same cross-helper stale-state variant. Counter-evidence checked: if the skb is already linear and 2..N bytes are present in the head, pskb_may_pull is a no-op and ga stays valid, so the UAF requires a non-linear skb whose attribute spans frags - the same precondition as the seed; no refetch of ga exists anywhere between capture and last use; no copy-out of the header is made."
    }
  ],
  "candidates": [
    {
      "snapshot": "s02",
      "path": "net/802/garp.c",
      "line": 442,
      "status": "reported",
      "reason": "Primary finding (same as findings[0]): pointer capture ga=skb->data cast at line 438, reallocating pull pskb_may_pull(skb, ga->len) with attacker-controlled length at line 442, stale dereferences ga->len (445), ga->event (450), ga->data (474)."
    },
    {
      "snapshot": "s02",
      "path": "net/phonet/pep.c",
      "line": 61,
      "status": "safe",
      "reason": "pep_get_sb() in snapshots/s02 contains the seed bug itself (ph captured via skb_header_pointer at line 61, pskb_may_pull(skb, ph->sb_len) at line 63, then ph->sb_len -= 2 at line 64 and ph->sb_type read at line 65 with no refetch). This is the seed location/demonstration, not a variant, so it is excluded from findings per task rules; classified safe-as-variant (not reported) and used as ground-truth calibration that the pattern-matching pipeline finds the true positive."
    },
    {
      "snapshot": "s02",
      "path": "net/openvswitch/flow.c",
      "line": 318,
      "status": "safe",
      "reason": "parse_vlan_tag(): vh = (struct vlan_head *)skb->data at line 318, pskb_may_pull at lines 326-327, but vh is explicitly refetched at line 330 ('vh = (struct vlan_head *)skb->data') before every later use; no stale dereference. Follows the fixed pattern."
    },
    {
      "snapshot": "s02",
      "path": "net/batman-adv/soft-interface.c",
      "line": 437,
      "status": "safe",
      "reason": "batadv_interface_rx(): batadv_bcast_packet pointer captured at line 437, but the only use after pskb_may_pull(skb, ETH_HLEN) at line 448 is is_bcast computed at line 438 BEFORE the pull; the pointer is not dereferenced after the pull (the remaining pskb_may_pull hits in the file were inspected via the multiline scan output and do not dereference pre-pull pointers afterwards)."
    },
    {
      "snapshot": "s02",
      "path": "net/batman-adv/routing.c",
      "line": 257,
      "status": "safe",
      "reason": "batadv_recv_my_vis_packet/batadv_icmp packet handling at routing.c:257: icmph = (struct batadv_icmp_header *)skb->data is captured after batadv_icmp_packet_rcv's pskb_may_pull (multimedia scan shows all uses ether_addr_copy(icmph->dst,...), icmph->msg_type, icmph->ttl occur at lines 259-262 immediately, before any subsequent pskb_may_pull in that scope; the multiline hit was due to an unrelated later pskb_may_pull in a different function of the same file within the 4000-char window)."
    },
    {
      "snapshot": "s02",
      "path": "net/batman-adv/network-coding.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the coarse file-level scan (header-pointer capture followed by a pull somewhere within the same file/function window) but the exact capture-vs-pull-vs-use ordering inside batadv_nc_skb_forward()/batadv_nc_path decoding was not fully traced before the intent was finalized; listed as a concrete remaining lead for a follow-up worker."
    },
    {
      "snapshot": "s02",
      "path": "net/llc/llc_input.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the strict skb_header_pointer/cast-then-pull scan; llc_rcv() pulls and re-parses in stages. Quick inspection suggested the header pointer is re-derived from skb->data after each pull, but the interleaving of llc_pdu_header_init-style helpers was not fully verified before finalization; kept as an unresolved lead."
    },
    {
      "snapshot": "s02",
      "path": "net/decnet/dn_nsp_in.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the strict scan (skb_header_pointer-then-pull in dn_nsp_in.c, e.g. around dn_nsp_rx_packet/dn_nsp_data_packet). Historical kernel CVEs exist in this file's pull handling, so it is a plausible same-mechanism site, but per-function capture/pull/use ordering was not completed before finalization; unresolved lead."
    },
    {
      "snapshot": "s02",
      "path": "net/ipv6/ah6.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the strict multiline scan (header pointer captured before pskb_may_pull in ah6.c AH receive path, e.g. ah_input()/ah_input_done() region). Not fully traced: the file uses async crypto with re-entry, and pointer liveness across the pull needs the done() path analyzed; left as an unresolved lead for a follow-up."
    },
    {
      "snapshot": "s02",
      "path": "net/mac80211/rx.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the strict scan; mac80211 rx.c contains many skb_header_pointer + pskb_may_pull pairs (e.g. in ieee80211_rx handlers / mesh / AMSDU subframe handling). The sheer size (thousands of lines) prevented completing per-site validation within the budget; remains a bounded open lead."
    },
    {
      "snapshot": "s02",
      "path": "net/bridge/br_multicast.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the strict scan (skb_header_pointer/pskb_may_pull interleave in IGMP/MLD query parsing). Not fully traced before finalization; unresolved lead."
    },
    {
      "snapshot": "s02",
      "path": "net/netfilter/nf_conntrack_sip.c",
      "line": 0,
      "status": "unresolved",
      "reason": "Matched the strict scan; SIP helper parsing uses skb_header_pointer and process() loops with pskb_may_pull inside while-loops over messages, which is structurally close to the loop-parser branch; not completed before finalization (also partially out of this intent's single-pass rx branch scope); unresolved lead."
    }
  ],
  "limitations": [
    "The garp.c finding requires a non-linear skb whose GARP attribute extends into page frags so that pskb_may_pull(skb, ga->len) actually triggers __pskb_pull_tail/pskb_expand_head and relocates skb->head; on already-linear heads the pull is a no-op and ga remains valid. Reachability of such an skb from real GARP senders (LLC/SNAP framed stp packets) was not empirically tested (no kernel build/run was performed; snapshot is a header/source tree without top-level Makefile and build was out of scope).",
    "The multiline PCRE2 scan (pointer capture then pull within a ~4000-char no-brace window) only heuristically covers the pattern; captures via helper-inlined macros (e.g. ip_hdr(), ipv6_hdr(), tcp_hdr(), vlan_eth_hdr(), skb_set_..., various proto _hdr accessors) or pulls hidden inside called helpers were not systematically enumerated, so additional rx-path instances may exist in snapshots/s02 beyond the 13 files triaged.",
    "Only net/ was scanned for this branch (per the intent's net/* *_rcv scope); drivers/net, drivers/staging, and other receive paths outside net/ that use pskb_may_pull were not searched.",
    "Seven files flagged by the strict scan (network-coding.c, llc_input.c, dn_nsp_in.c, ah6.c, mac80211/rx.c, br_multicast.c, nf_conntrack_sip.c) remain unresolved: matches were confirmed at file level but the exact capture->pull->stale-use ordering inside each function was not completed before the finalize instruction."
  ]
}
out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/findings/i006.json"
os.makedirs(os.path.dirname(out), exist_ok=True)
tmp = out + ".tmp"
with open(tmp, "w") as f:
    json.dump(art, f, indent=2)
os.replace(tmp, out)
print("wrote", out, os.path.getsize(out))
