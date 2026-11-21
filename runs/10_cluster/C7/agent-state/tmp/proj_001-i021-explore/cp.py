import json, os, sys
p = sys.argv[1]
d = json.load(open(p)) if os.path.exists(p) else {}
d.setdefault("intent_id","i021"); d["intent_id"]="i021"
d["branch"]="timer-dwork-softirq-lock"
d["snapshot"]="s06"
d.setdefault("updates",[])
d["updates"].append({"ts": __import__("time").time(), "note": sys.argv[2]})
json.dump(d, open(p,"w"), indent=1)
print("wrote", p)
