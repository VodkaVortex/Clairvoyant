import json, re
data = json.load(open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/agent-state/tmp/proj_001-i007-explore/unguarded_uses.json"))

def relevant(r):
    a, attr = r['array'], r['attr']
    if a in ('info->attrs', 'attrs'):
        return True
    if attr.startswith(('IFLA_','TCA_','NLA_','NL80211_','NL802154_','IEEE802154_','MAC802154_','DEVLINK_','L2TP_','BATADV_','TIPC_','WGPEER_','WGDEVICE_','NCSI_','MPTCP_','SEG6_','NET_DM_','TEAM_','NBD_','IPSET_','NFT_','XFRM_','RDMA_NLDEV','NFC_','TASKSTATS_','CGROUP_','FOU_','ILA_','SMC_','GTP_','NLBL_','TS_','HWSIM_')):
        return True
    return False

rel = [r for r in data if relevant(r)]

# Direct deref: nla_* helper applied to the slot on same line
deref_re = re.compile(r'\b(nla_data|nla_len|nla_get_\w+|nla_nest\w+|nla_strcmp|nla_strlcpy|nla_memcpy|nla_is_nested|nla_parse\w*|nla_validate\w*|nla_find|nla_for_each\w+)\s*\(')
arrow_re = re.compile(r'\[\s*[A-Z][A-Z0-9_]*\s*\]\s*->')

p1 = []
for r in rel:
    u = r['use']
    has_deref = bool(deref_re.search(u)) or bool(arrow_re.search(u))
    if has_deref:
        p1.append(r)

print(f"relevant: {len(rel)}, direct-deref flagged: {len(p1)}")
byfile = {}
for r in p1:
    byfile.setdefault(r['file'], []).append(r)
for f in sorted(byfile):
    print(f"\n== {f} ({len(byfile[f])})")
    for r in byfile[f]:
        g = 'CONDFREE' if r['guarded'] is False else 'EARLIER-USE'
        print(f"  L{r['line']} {r['func']}() {g}: {r['use'][:120]}")
