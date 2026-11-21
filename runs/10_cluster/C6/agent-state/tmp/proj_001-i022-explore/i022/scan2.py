import os, re, json, sys
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"
RELOC = re.compile(r"\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|skb_unclone|skb_share_check|skb_ensure_writable|skb_try_make_writable|skb_linearize_cow|skb_header_unclone|pskb_network_may_pull)\s*\(")
callees = set(json.load(open(os.path.join(os.environ["TMPDIR"], "i022", "callees.json"))).keys())
# add multi-arg known pull-wrapper families by name pattern
pat = re.compile(r"^(ip_mc_may_pull|ipv6_mc_may_pull|lowpan_fetch_skb|.*_check_hdr|.*_hdr_ok|.*hdr_ok|.*_may_pull|.*_pull_skb|.*_pull_data|check_header|.*_pull_rcsum)$")
# capture forms: type *var = <expr with skb->data / *_hdr(skb) / skb_header_pointer>
CAP = re.compile(r"^\s*(?:const\s+)?(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*(?:skb->data|_hdr\(skb|skb_header_pointer|skb_network_header|skb_mac_header|skb_transport_header).*)")
# also value-capture style assignments to existing pointer vars
RECAP = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*(?:skb->data|_hdr\(skb\)|skb_header_pointer|skb_network_header\(skb\)|skb_transport_header\(skb\)|skb_mac_header\(skb\)).*);")

hits = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in (".git", "tools", "Documentation")]
    for fn in filenames:
        if not fn.endswith((".c", ".h")):
            continue
        p = os.path.join(dirpath, fn)
        rel = os.path.relpath(p, ROOT)
        try:
            lines = open(p, errors="ignore").read().split("\n")
        except OSError:
            continue
        for i, line in enumerate(lines):
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", line):
                name = m.group(1)
                if name not in callees and not pat.match(name):
                    continue
                # must look like a call, not a definition in this line
                if re.search(r"^\s*(static\s+)?(?:inline\s+)?[A-Za-z_].*\b" + name + r"\s*\($", line):
                    continue
                # search backward up to 60 lines for a capture of a pointer
                window = lines[max(0, i-60):i]
                for j, wl in enumerate(window[::-1]):
                    cm = CAP.match(wl) or RECAP.match(wl)
                    if cm:
                        var = cm.group(1)
                        # does var appear after the call line (next 40 lines) as deref?
                        post = lines[i+1:i+41]
                        for pl in post:
                            if re.search(r"\b" + re.escape(var) + r"\s*(->|\[|\.)", pl):
                                hits.append((rel, i+1, name, var, j, lines[i]))
                                break
                        break
seen = set()
out = []
for h in hits:
    key = (h[0], h[1])
    if key in seen: continue
    seen.add(key)
    out.append(h)
for h in out:
    print(f"{h[0]}:{h[1]} call={h[2]} captured_var={h[3]} dist={h[4]}")
print("TOTAL", len(out))
