import json, os, tempfile

path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i032.json"
a = json.load(open(path))

a['findings'][0]['conclusion'] = ("sc92031_tx_timeout takes priv->lock with plain spin_lock while the ISR-scheduled RX/TX tasklet takes the same lock in softirq; the missing spin_lock_bh lets the tasklet spin forever against the preempted timeout holder on one CPU (soft-lockup/DoS).")
a['findings'][1]['conclusion'] = ("ath5k's SWBA beacontq tasklet takes ah->block with plain spin_lock (base.c:2204) while process users use spin_lock_bh; inconsistent BH discipline is a medium-confidence variant whose deadlock needs hardirq preemption or a plain process acquirer.")
a['coverage_gaps'][0] = ("The ~200-file tasklet_init inventory was deep-read only for the network/staging drivers in candidates; sound/, drivers/dma/, drivers/crypto/, drivers/mmc/ and drivers/scsi/ tasklet bodies were not audited for a plain-spin_lock process partner.")

d = os.path.dirname(path)
tmp = tempfile.NamedTemporaryFile('w', dir=d, delete=False, suffix='.tmp')
json.dump(a, tmp, indent=1)
tmp.flush(); os.fsync(tmp.fileno()); tmp.close()
os.replace(tmp.name, path)

a2 = json.load(open(path))
print('all findings <=300:', all(len(f['conclusion']) <= 300 for f in a2['findings']))
print('all unresolved <=300:', all(len(c['conclusion']) <= 300 for c in a2['candidates'] if c['status'] == 'unresolved'))
print('all gaps <=300:', all(len(g) <= 300 for g in a2['coverage_gaps']))
print('sizes', os.path.getsize(path))
