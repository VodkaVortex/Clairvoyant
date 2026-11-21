import json, os

findings_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/findings/i008.json"
ckpt_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/agent-state/checkpoints/i008.json"

artifact = {
  "version": 1,
  "intent_id": "i008",
  "branch": "loop-parser-stale-state",
  "execution_status": "complete",
  "snapshots_checked": ["s02"],
  "findings": [
    {
      "snapshot": "s02",
      "path": "net/decnet/dn_route.c",
      "start": 547,
      "end": 574,
      "quote": "unsigned char *ptr = skb->data;\n\n\tif (!pskb_may_pull(skb, 21)) /* 20 for long header, 1 for shortest nsp */\n\t\tgoto drop_it;\n\n\tskb_pull(skb, 20);\n\tskb_reset_transport_header(skb);\n\n\t/* Destination info */\n\tptr += 2;\n\tcb->dst = dn_eth2dn(ptr);",
      "confidence": "medium",
      "reason": "UNTRUSTED SOURCE: dn_route_rx_long() is the DECnet (ETH_P_DNA_RT) receive-path header parser, reached from dn_route_rcv dispatch after only a 1-byte flag pull; packet bytes are fully attacker-controlled on any interface carrying DECnet. MISSING GUARANTEE: the parser caches 'unsigned char *ptr = skb->data' (line 550) BEFORE calling pskb_may_pull(skb, 21) (line 552). pskb_may_pull() on a non-linear/cloned skb calls __pskb_pull_tail(), which invokes pskb_expand_head(); pskb_expand_head() (net/core/skbuff.c:1195, kfree(data) at skbuff.c:1266) allocates a new head and frees the old data area, so every pre-call pointer into skb->head is invalidated. No refetch of ptr from skb->data occurs after the pull. UNSAFE USE: after the pull, ptr is advanced and dereferenced repeatedly to parse the 20-byte long route header: cb->dst = dn_eth2dn(ptr) and memcmp(ptr, dn_hiord_addr, 4) at lines 560-561, cb->src = dn_eth2dn(ptr) and memcmp at 568-569, and cb->hops = *ptr++ at line 574. This is the exact pep_get_sb() shape (pointer captured before a head-relocating pull, then dereferenced after it) realized in a helper whose parse state ('ptr' cursor plus cb->dst/src/hops) crosses the pull boundary and is consumed by later routing state (dn_route_rx_packet uses cb->src/cb->dst). COUNTEREVIDENCE / LIMITS: unlike the seed, the pull length here is the constant 21 rather than an attacker-controlled field, so relocation requires the arriving skb to be non-linear or cloned at this point (e.g. hardware-GRO/fraglist deliveries, or a cloned skb from packet taps); on a fully-linear, unshared skb pskb_may_pull is a no-op and no UAF occurs. Also, the same broken pattern exists in dn_route_rx_short() (net/decnet/dn_route.c:587-602, ptr cached at 590 before pskb_may_pull(skb, 6) at 592, dereferenced at 598-602) and in fr_rx() (drivers/net/wan/hdlc_fr.c:873-940, 'u8 *data = skb->data' and fh cached at 873-874, used at 927-940 after skb_share_check at 922 which may clone-and-replace via skb_clone/consume_skb; note skb_clone shares the existing head rather than reallocating it, so the fr_rx case is weaker). EXPLOIT IMPACT NOT FULLY PROVEN: reachability additionally requires DECnet support enabled (CONFIG_DECNET) on the receiving host; I did not construct a reproducer proving a non-linear skb reaches this point. Reported as a hypothesis with medium confidence: the validated-equals-used invariant (pointer into a buffer a later call may reallocate) is violated in source, matching the seed mechanism."
    }
  ],
  "candidates": [
    {
      "snapshot": "s02",
      "path": "net/decnet/dn_route.c",
      "line": 587,
      "status": "reported",
      "reason": "dn_route_rx_short(): 'unsigned char *ptr = skb->data' captured at line 590 before pskb_may_pull(skb, 6) at 592; ptr dereferenced at 598 (*(__le16 *)ptr), 600, and 602 (*ptr & 0x3f) without refetch. Same mechanism as the primary finding in dn_route_rx_long; reported together as the identical pattern in the sibling short-header parser."
    },
    {
      "snapshot": "s02",
      "path": "net/phonet/pep.c",
      "line": 57,
      "status": "reported",
      "reason": "pep_get_sb() in snapshot s02 still contains the unfixed seed pattern: ph = skb_header_pointer(skb, 0, 2, &h) at line 67, pskb_may_pull(skb, ph->sb_len) at 68 with attacker-controlled length, then ph->sb_len -= 2 and *ptype = ph->sb_type at 70-71 and __skb_pull(skb, 2 + ph->sb_len) at 77 through the stale pointer. This is the seed bug itself present in this snapshot (loop: pipe_handler_do_rcv/pipe_rcv_status iterate pep_get_sb as a next-record helper), confirming the snapshot predates the fix; included as a same-mechanism hit, not a novel variant."
    },
    {
      "snapshot": "s02",
      "path": "drivers/net/wan/hdlc_fr.c",
      "line": 873,
      "status": "unresolved",
      "reason": "fr_rx(): 'struct fr_hdr *fh = (struct fr_hdr *)skb->data' and 'u8 *data = skb->data' captured at 873-874; skb_share_check(skb, GFP_ATOMIC) at 922 may replace the skb via skb_clone + consume_skb; data dereferenced at 927-940 (data[3], data[4], data[5], data+6, data+8) and fh->fecn/fh->becn earlier. Weaker than the seed: skb_clone() shares the old head buffer rather than freeing it, and consume_skb only drops a reference, so the captured data/fh pointers remain valid into the shared head; a genuine UAF would need a concurrent modifier of that shared head. Left unresolved because the capture-across-helper-that-may-replace-skb shape is present but the head is not documented to be freed by this path."
    },
    {
      "snapshot": "s02",
      "path": "net/ipv4/esp4.c",
      "line": 417,
      "status": "safe",
      "reason": "esp_input(): scanner flagged 'aead' used after skb_linearize at off ~17, but 'aead' is a crypto_aead pointer from x->data, not a pointer into skb->head; skb_linearize cannot invalidate it. No pointer-into-skb survives the pull."
    },
    {
      "snapshot": "s02",
      "path": "net/ipv6/esp6.c",
      "line": 354,
      "status": "safe",
      "reason": "esp6_input(): same false positive as esp4 - 'aead' is a crypto algorithm handle, not an skb data pointer; no stale skb-head pointer across the linearize."
    }
  ],
  "limitations": [
    "Search bounded to snapshot s02 only, per intent; other snapshots not examined.",
    "Automated function-level scanner covered functions containing both a header-pointer capture (skb_header_pointer, skb->data/head cast, skb_network/mac/transport_header, skb_pull_data) and a pull/linearize/cow call; it does not model pointer aliasing through helper return values or state passed via per-protocol control blocks beyond what was read manually, so whole-helper next-record iterators that hide the capture in the callee (other than pep_get_sb) could be missed.",
    "Loop-interior pull analysis (pattern B) returned zero hits with the heuristic used, but the heuristic only tracked variables captured before the loop header and dereferenced after the first interior pull with simple regex use-matching; nested helpers called inside loops were not interprocedurally analyzed.",
    "DECnet finding reachability requires CONFIG_DECNET and a non-linear or cloned skb at dn_route_rx_long/dn_route_rx_short; I did not build or run a reproducer proving such an skb arrives on that path, so impact is expressed as hypothesis with medium confidence.",
    "grep-based prefilter: 130 files in net/ plus drivers were enumerated for pull APIs; coverage of drivers/, net/mac80211, and netfilter helpers relied on the same scanner rather than exhaustive manual reading (max 12 candidates triaged as instructed)."
  ]
}

tmp = findings_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(artifact, f, indent=2)
os.replace(tmp, findings_path)
print("wrote", findings_path)

# update checkpoint to completed
ckpt = {
  "intent_id": "i008",
  "branch": "loop-parser-stale-state",
  "snapshot": "s02",
  "status": "complete",
  "note": "Finalized. Primary finding: net/decnet/dn_route.c dn_route_rx_long (ptr captured at 550 before pskb_may_pull(skb,21) at 552, dereferenced at 560-574) and dn_route_rx_short (590/592/598-602) - stale-pointer-across-pull in next-record-style RX header parsers; medium confidence (constant pull length; needs non-linear/cloned skb + CONFIG_DECNET). Seed pattern itself still present unfixed in s02 net/phonet/pep.c:57 pep_get_sb. fr_rx (hdlc_fr.c:873) unresolved (skb_share_check clones, head shared not freed). esp4/esp6 scanner hits safe (aead not an skb pointer). Final artifact written.",
  "candidates": [
    {"path": "net/decnet/dn_route.c", "line": 547, "status": "reported", "reason": "dn_route_rx_long stale ptr across pskb_may_pull"},
    {"path": "net/decnet/dn_route.c", "line": 587, "status": "reported", "reason": "dn_route_rx_short stale ptr across pskb_may_pull"},
    {"path": "net/phonet/pep.c", "line": 57, "status": "reported", "reason": "seed pattern unfixed in this snapshot"},
    {"path": "drivers/net/wan/hdlc_fr.c", "line": 873, "status": "unresolved", "reason": "skb_share_check path; clone shares head, no freed-head proof"},
    {"path": "net/ipv4/esp4.c", "line": 417, "status": "safe", "reason": "aead is crypto handle, not skb pointer"},
    {"path": "net/ipv6/esp6.c", "line": 354, "status": "safe", "reason": "same false positive"}
  ]
}
tmp2 = ckpt_path + ".tmp"
with open(tmp2, "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(tmp2, ckpt_path)
print("wrote", ckpt_path)
