import subprocess, sys, os
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"
p=sys.argv[1]
os.system(f"rm -rf /tmp/i049view; mkdir -p /tmp/i049view")
subprocess.run(["cp","-r",ROOT+"/"+p,"/tmp/i049view/"])
