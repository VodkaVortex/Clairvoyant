import json
P = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i046.json'
def load():
    return json.load(open(P))
def save(d):
    json.dump(d, open(P,'w'), indent=1)
def add(d, cand):
    for c in d['candidates']:
        if c.get('path')==cand.get('path') and c.get('line')==cand.get('line'):
            return
    d['candidates'].append(cand)
def prog(d, s):
    if s not in d['progress']:
        d['progress'].append(s)
