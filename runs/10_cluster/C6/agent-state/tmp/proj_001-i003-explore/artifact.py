import json
art = {
  "version": 1,
  "intent_id": "i003",
  "branch": "tx-cow-head-realloc",
  "execution_status": "complete",
  "snapshots_checked": ["s01"],
  "findings": [
    {
      "snapshot": "s01",
      "path": "net/ipv4/ip_tunnel_core.c",
      "start": 195,
      "end": 241,
      "quote": "const struct iphdr *iph = ip_hdr(skb);",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: iptunnel_pmtud_build_icmp() is reached from skb_tunnel_check_pmtu() (ip_tunnel_core.c:407-427) on UDP-tunnel TX paths (geneve.c:836/943, vxlan_core.c:2449/2507, bareudp.c:320/384) with reply=true when the tunnel port is a bridge port; the skb carries a forwarded packet whose L2+IP bytes are attacker-controlled (the outer sender's frame). VIOLATED INVARIANT: iph is captured at line 197 as ip_hdr(skb), a raw pointer into skb->head, and every documented head-reallocating helper runs afterwards in the same scope before iph is refetched: pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr)) at 203 (may __pskb_pull_tail -> pskb_expand_head), pskb_trim(skb, ...) at 210 (may realloc tail), and skb_cow(skb, sizeof(*niph) + sizeof(*icmph) + ETH_HLEN) at 215 (pskb_expand_head frees the old head when cloned). The ICV equal-then-use guarantee is absent: nothing reloads iph = ip_hdr(skb) between the cow and the uses. UNSAFE USE: stale iph dereferenced at 238 (.ttl = iph->ttl), 240 (.saddr = iph->daddr), 241 (.daddr = iph->saddr) inside the new ICMP header pushed with skb_push; these values are then checksummed and sent — a state transition (ICMP DEST_UNREACH/FRAG_NEEDED construction) through potentially freed slab memory, same shape as the seed's pep_get_sb() (ph live across pskb_may_pull, then ph->sb_len -= 2). IMPACT: slab use-after-free read of 1+4+4 bytes whose result is transmitted in a generated ICMP packet (info leak of freed slab contents into attacker-visible fields); KASAN-detectable. COUNTEREVIDENCE: requires a cloned or non-linear inner skb at that point (fresh local tunnel egress skbs are often linear/unshared, in which case pskb_expand_head is a no-op); the ICMP error is only built when netif_is_any_bridge_port(dev) and pkt_type != PACKET_HOST; IPv6 twin at 290-331 is the same pattern. No runtime reproducer was built (static analysis only)."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv4/ip_tunnel_core.c",
      "start": 288,
      "end": 331,
      "quote": "const struct ipv6hdr *ip6h = ipv6_hdr(skb);",
      "confidence": "medium",
      "reason": "IPv6 twin of the above: iptunnel_pmtud_build_icmpv6() captures ip6h = ipv6_hdr(skb) at 290, then runs pskb_may_pull(skb, ETH_HLEN + sizeof(struct ipv6hdr)) at 297, pskb_trim(skb, IPV6_MIN_MTU - ...) at 304, and skb_cow(skb, sizeof(*nip6h) + sizeof(*icmp6h) + ETH_HLEN) at 309 — any of which may pskb_expand_head the skb and free the old head — and then dereferences the stale ip6h at 329 (.hop_limit = ip6h->hop_limit), 330 (.saddr = ip6h->daddr), 331 (.daddr = ip6h->saddr) while building the ICMPv6 PKT_TOOBIG error. Same reachability (skb_tunnel_check_pmtu reply path from geneve/vxlan/bareudp bridged ports), same unvalidated-capture-then-use invariant break, same consequence class (UAF read whose result is transmitted; hop_limit is also a 1-byte info leak into the generated packet). Same counterevidence: non-linear/cloned inner skb required; not dynamically reproduced."
    },
    {
      "snapshot": "s01",
      "path": "net/mac80211/tdls.c",
      "start": 2028,
      "end": 2050,
      "quote": "struct ieee80211_tdls_data *tf = (void *)skb->data;",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: ieee80211_process_tdls_channel_switch() gets an ETH_P_TDLS action frame received over the air from a peer TDLS station (queued to sdata->skb_queue and dispatched from mac80211 RX); skb->data bytes are fully attacker-controlled. VIOLATED INVARIANT: tf is captured as a cast of skb->data at 2029; skb_linearize(skb) at 2039 ('we want to access the entire packet') can pskb_expand_head the skb (freeing/replacing the head) whenever the skb is cloned or non-linear; there is no refetch of tf before the post-linearize dereference. UNSAFE USE: stale tf->action_code read at 2045 to select the REQUEST/RESPONSE handler — a state transition (dispatch decision) through potentially freed slab memory, exactly the seed's capture -> reallocating helper -> stale dereference shape with the same missing ICV-equivalent (no revalidation after the linearize). IMPACT: KASAN-detectable slab UAF read; the chosen handler re-parses the skb itself so impact is limited to the dispatch decision on stale bytes rather than proven memory corruption. COUNTEREVIDENCE: requires a cloned/non-linear TDLS skb reaching this worker (driver RX dependent — GRO/fraglist RX or monitor-path re-injection); if the skb is already linear and unshared, skb_linearize is a no-op. Not dynamically reproduced."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/wireless/mediatek/mt76/mt7925/mcu.c",
      "start": 493,
      "end": 502,
      "quote": "struct mt7925_mcu_rxd *rxd = (struct mt7925_mcu_rxd *)skb->data;",
      "confidence": "low",
      "reason": "UNTRUSTED SOURCE: mt7925_mcu_rx_event() parses the head of an skb received from the mt7925 firmware via the mt76 PCIe/SDIO event path; the head bytes are firmware-supplied. VIOLATED INVARIANT: rxd is captured as (struct mt7925_mcu_rxd *)skb->data at 494; skb_linearize(skb) at 496 can pskb_expand_head and free the old head for a cloned/non-linear skb; rxd is not refetched. UNSAFE USE: rxd->option is read at 499 through the potentially stale pointer to branch between the unsolicited-event dispatcher and the normal event path — a kernel state transition (event routing) through potentially freed slab memory, same missing validate-then-use guarantee as the seed. IMPACT: KASAN-detectable slab UAF read that misroutes an MCU event. COUNTEREVIDENCE: the untrusted source is on-device firmware, not a remote network peer, and mt76 event skbs are typically allocated linear and unshared, in which case the reallocation never triggers; whether a cloned/non-linear MCU event skb can reach here was not proven. Reported at low confidence as the same stale-pointer-after-linearize pattern."
    }
  ],
  "candidates": [
    {
      "snapshot": "s01",
      "path": "net/ipv4/ip_tunnel_core.c",
      "line": 240,
      "status": "reported",
      "reason": "iptunnel_pmtud_build_icmp(): iph captured 197; pskb_may_pull 203 / pskb_trim 210 / skb_cow 215 may reallocate head; stale iph->ttl/daddr/saddr read 238/240/241 for the generated ICMP header. Raise as finding."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv4/ip_tunnel_core.c",
      "line": 330,
      "status": "reported",
      "reason": "iptunnel_pmtud_build_icmpv6(): ip6h captured 290; pskb_may_pull 297 / pskb_trim 304 / skb_cow 309; stale ip6h->hop_limit/daddr/saddr read 329-331 for the ICMPv6 error. Raise as finding."
    },
    {
      "snapshot": "s01",
      "path": "net/mac80211/tdls.c",
      "line": 2045,
      "status": "reported",
      "reason": "tf captured from skb->data 2029; skb_linearize 2039 can free/replace head; tf->action_code read 2045 without refetch. Raise as finding."
    },
    {
      "snapshot": "s01",
      "path": "drivers/net/wireless/mediatek/mt76/mt7925/mcu.c",
      "line": 499,
      "status": "reported",
      "reason": "rxd captured from skb->data 494; skb_linearize 496; rxd->option read 499 without refetch; firmware-supplied skb, reallocation precondition unproven. Low-confidence finding."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv6/exthdrs.c",
      "line": 591,
      "status": "safe",
      "reason": "ipv6_rpl_srh_rcv(): after pskb_expand_head(skb, ...) at 591 (only when segments_left==0) the code refetches oldhdr = ipv6_hdr(skb) at 595 and re-derives ipv6_hdr(skb)/skb_transport_header(skb) for the memmove/memcpy at 599-600; hdr is not dereferenced after the expand (last uses at 577-590 precede it). Correct refetch discipline."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv6/exthdrs.c",
      "line": 753,
      "status": "safe",
      "reason": "ipv6_rthdr_rcv(): after pskb_expand_head(skb, 0, 0, GFP_ATOMIC) at 753 for cloned skbs, hdr is explicitly refetched 'hdr = (struct ipv6_rt_hdr *)skb_transport_header(skb)' at 756 before the segments_left decrement and all later uses; rthdr/addr derived after; no stale pointer survives."
    },
    {
      "snapshot": "s01",
      "path": "net/ipv6/exthdrs.c",
      "line": 271,
      "status": "safe",
      "reason": "ipv6_dest_hao(): both hao and ipv6h are refetched immediately after pskb_expand_head at 271 (hao recomputed from skb_network_header(skb)+optoff at 273-274, ipv6h = ipv6_hdr(skb) at 275) with the comment 'update all variable using below by copied skbuff'; swap at 283 uses refetched pointers."
    },
    {
      "snapshot": "s01",
      "path": "net/openvswitch/actions.c",
      "line": 791,
      "status": "safe",
      "reason": "ovs_vport_output(): the 'data' variable flagged by the scanner is this_cpu_ptr(&ovs_frag_data_storage), a per-CPU struct, not a pointer into the skb; skb_cow_head(skb, data->l2_len) at 791 is called BEFORE any pointer into the skb is taken (skb_push/memcpy at 802-804 follow it); l2_data was memcpy'd out in prepare_frag(). No stale skb pointer."
    },
    {
      "snapshot": "s01",
      "path": "net/sched/sch_frag.c",
      "line": 27,
      "status": "safe",
      "reason": "sch_frag_xmit(): same per-CPU sch_frag_data_storage pattern as OVS; data is not an skb-head pointer; skb_cow_head precedes the skb_push/memcpy of the MAC header; no captured skb-header pointer survives."
    },
    {
      "snapshot": "s01",
      "path": "net/xfrm/xfrm_input.c",
      "line": 307,
      "status": "safe",
      "reason": "xfrm6_remove_beet_encap(): skb_cow_head(skb, size + skb->mac_len) at 307 runs before __skb_push and before ip6h = ipv6_hdr(skb) at 317; all writes (318-320) use the post-cow pointer. xfrm4_remove_tunnel_encap/xfrm6_remove_tunnel_encap likewise call skb_unclone before taking ipip_hdr/ipipv6_hdr pointers. No stale use."
    },
    {
      "snapshot": "s01",
      "path": "net/core/skbuff.c",
      "line": 2270,
      "status": "safe",
      "reason": "skb_ensure_writable()/_pskb_expand_head region: 'sk = skb->sk' is a pointer to the socket object, not into skb->head; pskb_expand_head frees only the head/data area, so sk and other control-block pointers remain valid. Not the violated invariant."
    },
    {
      "snapshot": "s01",
      "path": "net/mac80211/rx.c",
      "line": 2251,
      "status": "safe",
      "reason": "ieee80211_rx_h_defrag(): cache (per-sdata fragment cache) and status (skb control block, IEEE80211_SKB_RXCB) are not pointers into skb->head; skb_linearize at 2251 relocates only head data, and the code comment at 2255 explicitly notes data/hdr pointers must not be used across the linearize and refetches skb->data afterwards. Control block survives linearize. No stale head pointer."
    }
  ],
  "limitations": [
    "All findings are static-analysis hypotheses: no runtime reproducer or KASAN trace was produced; triggering each requires the skb to actually be cloned or non-linear at the flagged point (pskb_expand_head is otherwise a no-op), which depends on the specific RX/GRO/driver path and was not dynamically verified.",
    "The automated audit only recognized pointer captures of the form 'type *var = <expr mentioning skb/hdr/data>' within the enclosing function of each skb_cow_head/skb_cow/skb_unclone/skb_share_check/pskb_expand_head/skb_linearize/__skb_linearize/__pskb_pull_tail/pskb_may_pull/pskb_pull call site (171 chains, 56 with no refetch on cow/linearize/expand calls); pointers passed into helper functions, captured in outer loops, or obtained via memcpy/arithmetic not matching the regex may be missed.",
    "Most of the 56 no-refetch scanner hits were pattern-screened rather than deeply read line-by-line (they captured device/driver-private pointers such as ndev, ethsw, ptp_data, local, ifmsh, strp, net, dst, sk, info, ct_ftp_info that are not pointers into skb->head and survive head reallocation); only the top candidates were deep-read within the triage limit.",
    "Only net/ and drivers/ .c files were scanned; arch/, fs/, headers, and macros generating call sites were not individually audited; drivers/ hits outside drivers/net and net/mac80211 were only pattern-screened.",
    "pskb_may_pull/pskb_pull variants belong primarily to the parallel rx-pull-stale-hdr intent (i002) and were included here only where they appear on TX/edit paths (ip_tunnel_core.c PMTU builders); the RX-path pull audit for s01 is out of scope for this artifact."
  ]
}
out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/findings/i003.json"
import os
os.makedirs(os.path.dirname(out), exist_ok=True)
tmp = out + ".tmp"
with open(tmp, "w") as f:
    json.dump(art, f, indent=1)
os.replace(tmp, out)
print("written", out)
