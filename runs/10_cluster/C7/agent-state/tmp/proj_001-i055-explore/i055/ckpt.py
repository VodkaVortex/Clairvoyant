import json, os
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i055.json"
def write(status, note):
    d = {"intent_id":"i055","branch":"hardirq-shared-lock","snapshot":"s11","status":status,"note":note,
         "candidates":[],"updated":__import__("datetime").datetime.now().isoformat()}
    tmp=p+".tmp"; open(tmp,"w").write(json.dumps(d,indent=1)); os.replace(tmp,p)
if __name__=="__main__":
    import sys
    write(sys.argv[1], sys.argv[2])
