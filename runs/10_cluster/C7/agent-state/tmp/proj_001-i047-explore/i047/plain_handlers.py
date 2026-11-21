import json, re, sys, collections
hl = json.load(open("/tmp/proj_001-i047-explore/i047/handler_locks.json")) if False else json.load(open(sys.argv[1]))
plain_api = {"spin_lock","spin_trylock","spin_lock_nested"}
res = []
for h in hl:
    pl = [l for l in h["locks"] if l["api"] in plain_api]
    safe = [l for l in h["locks"] if l["api"] not in plain_api]
    if pl:
        res.append({"handler": h["handler"], "path": h["path"], "reg_line": h["reg_line"], "def_line": h["def_line"], "plain": pl, "safe": [x["api"] for x in safe]})
print(json.dumps(res, indent=1))
