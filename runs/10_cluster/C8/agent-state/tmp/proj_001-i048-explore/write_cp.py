import json, os, sys
cp_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i048.json"
data = {
  "version": 1, "intent_id": "i048", "branch": "fixed-epidx-rest", "snapshot": "s12",
  "phase": "initial",
  "invariant": "USB consumer code must validate altsetting[i].desc.bNumEndpoints > k before indexing endpoint[k].desc.* (or altsetting[0].desc.* at probe/bind/init) outside drivers/media/usb and drivers/net; same for interface-level indices excluded (if-alt-count branch).",
  "queries_run": [
    "grep -rn '\\.endpoint\\[' excluding drivers/media/usb and drivers/net",
    "grep -rn 'endpoint\\[' (broader) excluding media-usb/net-usb"
  ],
  "candidate_files": sorted(set(l.split(':')[0] for l in open(os.environ.get('TMPDIR','/tmp') + '/endpoint_hits2.txt') if l.startswith('./drivers/') or l.startswith('./sound/'))),
  "classified": [],
  "notes": "Initial sweep found 151 hits; tools/ userspace examples excluded. Next: arrow pattern '->endpoint[', get_endpoint macro, usb_pipe_endpoint NULL-deref pattern."
}
os.makedirs(os.path.dirname(cp_path), exist_ok=True)
tmp = cp_path + '.tmp'
with open(tmp,'w') as f: json.dump(data,f,indent=1)
os.replace(tmp,cp_path)
print("wrote", cp_path)
