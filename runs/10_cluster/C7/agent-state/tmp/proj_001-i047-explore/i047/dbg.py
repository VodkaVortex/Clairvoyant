import re, os, sys
sys.path.insert(0, os.environ.get("TMPDIR","/tmp") + "/i047")
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
# quick check of parse_funcs on msm_serial.c
exec(open(os.environ.get("TMPDIR","/tmp") + "/i047/ctx.py").read().split("# gather candidate files")[0].split("ROOT =")[0].replace('import re, os','import re, os').replace("from collections import defaultdict","from collections import defaultdict"))
