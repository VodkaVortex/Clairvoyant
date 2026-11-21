import json, os, sys
ckpt_path = sys.argv[1]
data = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
atomic_path = ckpt_path + ".tmp"
with open(atomic_path, "w") as f:
    json.dump(data, f, indent=2)
os.replace(atomic_path, ckpt_path)
