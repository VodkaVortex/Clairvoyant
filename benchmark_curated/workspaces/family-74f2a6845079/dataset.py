"""Frozen family data and private historical ground truth; never sent to the model."""
from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path

from source_units import extract_functions

HERE = Path(__file__).resolve().parent


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                            text=True, errors="replace", timeout=180)
    if result.returncode:
        raise ValueError(f"git {args[0]} failed: {result.stderr[:500]}")
    return result.stdout


def table(name: str) -> list[dict]:
    with (HERE / "data" / name).open() as handle:
        return list(csv.DictReader(handle))


def data_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((HERE / "data").glob("*")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def changed_units(repo: Path, sha: str) -> list[dict]:
    parent = git(repo, "rev-parse", sha + "^1").strip()
    changes = git(repo, "diff-tree", "--no-commit-id", "--name-status", "-r", "-M",
                  parent, sha).splitlines()
    units = []
    for line in changes:
        fields = line.split("\t")
        if len(fields) < 2 or fields[0].startswith("A"):
            continue
        old = fields[1]
        new = fields[2] if fields[0].startswith("R") else old
        if Path(old).suffix not in {".c", ".h"}:
            continue
        source = git(repo, "show", f"{parent}:{old}")
        diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--unified=0",
                   parent, sha, "--", old, new)
        ranges = []
        for match in re.finditer(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", diff, re.M):
            start, count = int(match[1]), int(match[2] or "1")
            ranges.append([max(1, start), max(1, start + max(1, count) - 1)])
        functions = [{"name": f.name, "start": f.line_start, "end": f.line_end}
                     for f in extract_functions(old, source)
                     if any(f.line_start <= end and f.line_end >= start for start, end in ranges)]
        if ranges:
            units.append({"path": old, "ranges": ranges, "functions": functions})
    return units


def prepare(repo: Path, seed_prefix: str, scope: str, mode: str, ref: str) -> dict:
    assignments = table("case_family_map.csv")
    seeds = [r for r in assignments if r["hexsha"].startswith(seed_prefix)]
    if len(seeds) != 1 or len(seed_prefix) < 7:
        raise ValueError("seed must uniquely identify one copied family member (at least 7 hex digits)")
    seed = seeds[0]
    if scope == "cluster" and not seed["root_cause_cluster_uid"]:
        raise ValueError("seed has no formal cluster; use --scope family for added-later cases")
    peers = [r for r in assignments if r["hexsha"] != seed["hexsha"] and
             (scope == "family" or r["root_cause_cluster_uid"] == seed["root_cause_cluster_uid"])]
    seed_sha = git(repo, "rev-parse", seed["hexsha"] + "^{commit}").strip()
    patch = git(repo, "show", "--no-ext-diff", "--no-textconv", "--format=medium", seed_sha, "--")
    if len(patch) > 100_000:
        raise ValueError("seed patch exceeds 100000 characters; choose a smaller seed")
    pattern = next(r for r in table("patterns.csv") if r["hexsha"] == seed_sha)
    demonstration = {k: pattern[k] for k in ("hexsha", "one_line_summary", "vulnerability_summary",
                                            "vulnerability_pattern")}
    demonstration["patch"] = patch
    snapshots, targets = {}, []
    fixed_ref = git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").strip()
    if mode == "snapshot":
        snapshots["s01"] = fixed_ref
    for index, peer in enumerate(peers, 1):
        sha = peer["hexsha"]
        snapshot = f"s{index:02d}" if mode == "historical" else "s01"
        parent = git(repo, "rev-parse", sha + "^1").strip()
        if mode == "historical":
            snapshots[snapshot] = parent
        info = next(r for r in table("patterns.csv") if r["hexsha"] == sha)
        targets.append({"hexsha": sha, "title": info["one_line_summary"],
                        "cluster": peer["root_cause_cluster_uid"], "origin": peer["how_it_joined"],
                        "snapshot": snapshot, "parent": parent, "units": changed_units(repo, sha)})
    return {"version": 1, "repo": str(repo.resolve()), "seed": demonstration,
            "scope": scope, "mode": mode, "reference": fixed_ref,
            "dataset_sha256": data_digest(), "snapshots": snapshots, "targets": targets,
            "evaluation_note": "Historical location recovery, not exploit confirmation. Snapshot mode does not measure historical recall."}


def evaluate(manifest: dict, findings: list[dict], status: str) -> dict:
    results = []
    for target in manifest["targets"]:
        tier, matched = "not_found", []
        if manifest["mode"] != "historical":
            tier = "not_evaluated_on_different_revision"
        elif not target["units"]:
            tier = "not_measurable"
        else:
            for finding in findings:
                if finding["snapshot"] != target["snapshot"]:
                    continue
                for unit in target["units"]:
                    if finding["path"] != unit["path"]:
                        continue
                    level = "file_only"
                    if any(finding["start"] <= f["end"] and finding["end"] >= f["start"]
                           for f in unit["functions"]):
                        level = "changed_function"
                    if any(finding["start"] <= end and finding["end"] >= start for start, end in unit["ranges"]):
                        level = "exact_hunk"
                    if ["not_found", "file_only", "changed_function", "exact_hunk"].index(level) > ["not_found", "file_only", "changed_function", "exact_hunk"].index(tier):
                        tier = level
                    matched.append(finding["id"])
        results.append({"hexsha": target["hexsha"], "title": target["title"],
                        "snapshot": target["snapshot"], "coverage": tier,
                        "matched_finding_ids": sorted(set(matched))})
    measurable = sum(bool(t["units"]) for t in manifest["targets"]) if manifest["mode"] == "historical" else 0
    exact = sum(r["coverage"] == "exact_hunk" for r in results)
    located = sum(r["coverage"] in {"exact_hunk", "changed_function"} for r in results)
    return {"run_status": status, "provisional": status not in {"finished", "budget_exhausted"},
            "mode": manifest["mode"], "seed": manifest["seed"]["hexsha"],
            "target_count": len(results), "measurable": measurable,
            "exact_hunk_count": exact, "located_in_changed_function_or_hunk": located,
            "exact_hunk_recall": exact / measurable if measurable else None,
            "note": manifest["evaluation_note"], "targets": results}
