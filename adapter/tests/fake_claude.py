#!/usr/bin/env python3
"""Offline Claude CLI fixture for an end-to-end dispatcher smoke test."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


if "--version" in sys.argv:
    print("fake-claude 1.0")
    raise SystemExit(0)

prompt = sys.stdin.read()
system = ""
if "--system-prompt" in sys.argv:
    system = sys.argv[sys.argv.index("--system-prompt") + 1]

if "bootstrap worker" in system:
    events = [{"event": "done", "description": "mechanism profile; four branches", "complete": False}]
elif "planning worker" in system:
    if prompt.count("artifact=") >= 4:
        events = [{"event": "complete", "sources": ["f002"],
                   "description": "offline fixture observed branch coverage"}]
    elif "artifact=" in prompt:
        events = [{"event": "message", "text": "waiting for open snapshot intents"}]
    else:
        events = [
            {"event": "intent", "sources": ["f001"],
             "description": f"SNAPSHOT={snapshot}; BRANCH=data-flow; search only snapshots/{snapshot}"}
            for snapshot in ("s01", "s02", "s03", "s04")
        ]
else:
    match = re.search(r"Required final artifact path: (.+)", prompt)
    if not match:
        print(json.dumps({"event": "error", "message": "missing artifact path"}))
        raise SystemExit(0)
    selected = re.search(r"Assigned snapshot: (s\d+)", prompt)
    if not selected:
        print(json.dumps({"event": "error", "message": "missing assigned snapshot"}))
        raise SystemExit(0)
    branch = re.search(r"Assigned branch: ([^\n]+)", prompt)
    if not branch:
        print(json.dumps({"event": "error", "message": "missing assigned branch"}))
        raise SystemExit(0)
    artifact = Path(match.group(1).strip())
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps({
        "version": 1,
        "intent_id": artifact.stem,
        "branch": branch.group(1).strip(),
        "execution_status": "complete",
        "snapshots_checked": [selected.group(1)],
        "findings": [],
        "candidates": [],
        "coverage_gaps": ["offline fixture did not inspect source"],
        "limitations": ["offline fixture"],
    }))
    events = [{"event": "done",
               "description": f"artifact={artifact}; branch=offline; snapshots={selected.group(1)}; findings=0",
               "complete": False}]

for event in events:
    print(json.dumps(event))
