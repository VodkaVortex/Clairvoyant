import json
T = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/agent-state/tmp/proj_001-i021-explore"
rs = json.load(open(T + "/i021_terms.json"))
strong = [r for r in rs if r['index'] in ('count','size','len','cnt','copied','n','nbytes','length','data_cnt','tmp_len','bytes','l','datalen','buflen') or (r['idx_assign'] and ('min' in r['idx_assign'][1] or r['idx_assign'][1].rstrip(';').strip() in ('count','size','cnt','length','nbytes')))]
print('strong candidates:', len(strong))
for r in strong:
    print("%s:%d  %s   | arr=%s idx=%s assign=%s guard=%s" % (r['path'], r['term_line'], r['term_src'], r['array'], r['index'], r['idx_assign'], r['nearby_guard']))
