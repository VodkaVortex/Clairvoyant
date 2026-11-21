import json, os, sys
cp = sys.argv[1]
state = sys.argv[2] if len(sys.argv) > 2 else None
data = {
  "version": 1,
  "intent_id": "i030",
  "branch": "media-epidx",
  "snapshot": "s08",
  "status": state or "started",
  "updated_at": __import__("time").time(),
  "candidates": []
}
tmp = cp + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=1)
os.replace(tmp, cp)
print("wrote", cp)
