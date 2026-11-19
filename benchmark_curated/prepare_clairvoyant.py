#!/usr/bin/env python3
"""Build frozen benchmark workspaces/manifests for the curated ten clusters."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DEFAULT_REPO = Path("/mnt/raid/home/yangshuangning/linux")
DEFAULT_BENCHMARK = HERE.parent / "benchmark"
DEFAULT_SOURCE = REPO_ROOT / "src/vuln_clustering/results"
DEFAULT_PATTERNS = REPO_ROOT / "src/vuln_pattern_extraction/results/patterns.csv"
CODE_FILES = (
    "client.py",
    "config.toml",
    "dataset.py",
    "prompt.txt",
    "run.py",
    "search_tools.py",
    "source_units.py",
)


def read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader), list(reader.fieldnames or [])


def write_csv(path: Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def curated_digest() -> str:
    digest = hashlib.sha256()
    for name in ("selection.csv", "members.csv", "seeds.csv"):
        digest.update(name.encode())
        digest.update((HERE / name).read_bytes())
    return digest.hexdigest()


def checked(command: list[str], *, cwd: Path, timeout: int = 3600) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{(result.stderr or result.stdout)[-4000:]}"
        )
    return result.stdout


def load_inputs(args: argparse.Namespace) -> tuple[list[dict[str, str]], dict[str, list[dict[str, str]]], dict[str, dict[str, str]]]:
    selection, _ = read_csv(HERE / "selection.csv")
    members, _ = read_csv(HERE / "members.csv")
    seeds, _ = read_csv(HERE / "seeds.csv")
    expected_labels = [f"C{i}" for i in range(1, 11)]
    if [row["cluster_label"] for row in selection] != expected_labels:
        raise ValueError("selection.csv must contain C1 through C10 in order")
    by_label: dict[str, list[dict[str, str]]] = {label: [] for label in expected_labels}
    for row in members:
        if row["cluster_label"] not in by_label:
            raise ValueError(f"unknown cluster label in members.csv: {row['cluster_label']}")
        by_label[row["cluster_label"]].append(row)
    seed_by_label = {row["cluster_label"]: row for row in seeds}
    if set(seed_by_label) != set(expected_labels):
        raise ValueError("seeds.csv must contain exactly one row for every C1-C10 cluster")
    for selected in selection:
        label = selected["cluster_label"]
        rows = by_label[label]
        picked = [row for row in rows if row["role"] == "seed"]
        targets = [row for row in rows if row["role"] == "target"]
        if len(picked) != 1 or len(targets) != len(rows) - 1:
            raise ValueError(f"{label}: expected one seed and all remaining members as targets")
        if len(rows) != int(selected["member_count"]):
            raise ValueError(f"{label}: member count differs from selection.csv")
        seed_row = seed_by_label[label]
        if seed_row["seed_hexsha"] != picked[0]["hexsha"]:
            raise ValueError(f"{label}: seeds.csv does not match members.csv")
        if seed_row["family_uid"] != selected["family_uid"]:
            raise ValueError(f"{label}: seeds.csv family does not match selection.csv")
        if int(seed_row["target_count"]) != len(targets):
            raise ValueError(f"{label}: seeds.csv target count is wrong")
    return selection, by_label, seed_by_label


def prepare_workspace(
    args: argparse.Namespace,
    selected: dict[str, str],
    members: list[dict[str, str]],
    seed: dict[str, str],
    source: dict[str, tuple[list[dict[str, str]], list[str]]],
    digest: str,
) -> tuple[Path, str]:
    label = selected["cluster_label"]
    family_uid = selected["family_uid"]
    cluster_uid = f"rootcause-curated-{label.lower()}"
    workspace = args.workspaces / family_uid
    provenance = workspace / "data/provenance.json"
    if provenance.is_file():
        saved = json.loads(provenance.read_text(encoding="utf-8"))
        if saved.get("curated_sha256") != digest or saved.get("cluster_label") != label:
            raise ValueError(f"stale curated workspace: {workspace}")
        return workspace, cluster_uid
    if workspace.exists():
        raise ValueError(f"incomplete curated workspace: {workspace}")

    family_rows, family_fields = source["vulnerability_families.csv"]
    link_rows, link_fields = source["family_cluster_links.csv"]
    cluster_rows, cluster_fields = source["root_cause_clusters.csv"]
    family_case_rows, family_case_fields = source["case_family_map.csv"]
    cluster_case_rows, cluster_case_fields = source["case_cluster_map.csv"]
    pattern_rows, pattern_fields = source["patterns.csv"]
    family_by_id = {row["family_uid"]: row for row in family_rows}
    cluster_by_id = {row["root_cause_cluster_uid"]: row for row in cluster_rows}
    family_case_by_sha = {row["hexsha"]: row for row in family_case_rows}
    cluster_case_by_sha = {row["hexsha"]: row for row in cluster_case_rows}
    pattern_by_sha = {row["hexsha"]: row for row in pattern_rows}
    shas = [row["hexsha"] for row in members]
    source_cluster_uids = selected["source_cluster_uids"].split(";")
    missing = {
        "family": [] if family_uid in family_by_id else [family_uid],
        "clusters": [uid for uid in source_cluster_uids if uid not in cluster_by_id],
        "family_cases": [sha for sha in shas if sha not in family_case_by_sha],
        "cluster_cases": [sha for sha in shas if sha not in cluster_case_by_sha],
        "patterns": [sha for sha in shas if sha not in pattern_by_sha],
    }
    if any(missing.values()):
        raise ValueError(f"{label}: source catalog is incomplete: {missing}")

    family = dict(family_by_id[family_uid])
    family["root_cause_cluster_count"] = "1"
    family["original_fix_count"] = str(len(shas))

    base_cluster = dict(cluster_by_id[source_cluster_uids[0]])
    base_cluster.update({
        "root_cause_cluster_uid": cluster_uid,
        "cluster_size": str(len(shas)),
        "how_cluster_was_kept": "curated_selection",
        "source_refined_cluster_uids": json.dumps(source_cluster_uids),
        "root_cause": selected["pattern_name"],
        "broken_rule": selected["pattern_type"],
        "what_still_differs": json.dumps([selected["primary_consequence"]]),
        "member_hexshas": json.dumps(shas),
    })

    link = {field: "" for field in link_fields}
    link.update({
        "family_uid": family_uid,
        "root_cause_cluster_uid": cluster_uid,
        "fix_count": str(len(shas)),
        "distinguishing_dimension": selected["pattern_name"],
    })

    family_cases = []
    cluster_cases = []
    patterns = []
    for member in members:
        sha = member["hexsha"]
        family_case = dict(family_case_by_sha[sha])
        family_case.update({
            "root_cause_cluster_uid": cluster_uid,
            "family_uid": family_uid,
            "how_it_joined": "root_cause_cluster",
            "decision": "in_family",
        })
        family_cases.append(family_case)
        cluster_case = dict(cluster_case_by_sha[sha])
        cluster_case.update({
            "root_cause_cluster_uid": cluster_uid,
            "kept_or_left_out": "kept",
            "left_out_reason": "",
        })
        cluster_cases.append(cluster_case)
        patterns.append(pattern_by_sha[sha])

    args.workspaces.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{family_uid}.", dir=args.workspaces))
    try:
        for name in CODE_FILES:
            shutil.copy2(args.benchmark / name, temporary / name)
        data = temporary / "data"
        write_csv(data / "vulnerability_families.csv", [family], family_fields)
        write_csv(data / "family_cluster_links.csv", [link], link_fields)
        write_csv(data / "root_cause_clusters.csv", [base_cluster], cluster_fields)
        write_csv(data / "case_family_map.csv", family_cases, family_case_fields)
        write_csv(data / "case_cluster_map.csv", cluster_cases, cluster_case_fields)
        write_csv(data / "patterns.csv", patterns, pattern_fields)
        atomic_json(data / "provenance.json", {
            "version": 1,
            "curated_sha256": digest,
            "cluster_label": label,
            "family_uid": family_uid,
            "curated_cluster_uid": cluster_uid,
            "source_cluster_uids": source_cluster_uids,
            "seed": seed["seed_hexsha"],
            "member_count": len(shas),
            "source_selection": str(HERE / "selection.csv"),
            "source_members": str(HERE / "members.csv"),
        })
        temporary.rename(workspace)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return workspace, cluster_uid


def prepare_manifest(
    args: argparse.Namespace,
    selected: dict[str, str],
    members: list[dict[str, str]],
    seed: dict[str, str],
    workspace: Path,
    cluster_uid: str,
) -> Path:
    family_uid = selected["family_uid"]
    output = args.prepared / family_uid / cluster_uid
    manifest_path = output / "evaluation/manifest.json"
    expected_targets = {row["hexsha"] for row in members if row["role"] == "target"}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        actual_targets = {row["hexsha"] for row in manifest["targets"]}
        if manifest["seed"]["hexsha"] != seed["seed_hexsha"] or actual_targets != expected_targets:
            raise ValueError(f"stale curated manifest: {manifest_path}")
        return output
    if output.exists():
        raise ValueError(f"incomplete curated manifest directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{cluster_uid}.", dir=output.parent) as temporary:
        generated = Path(temporary) / "output"
        checked([
            sys.executable,
            "-B",
            str(workspace / "run.py"),
            "prepare",
            "--repo",
            str(args.repo),
            "--seed",
            seed["seed_hexsha"],
            "--scope",
            "cluster",
            "--mode",
            "historical",
            "--output",
            str(generated),
        ], cwd=workspace)
        generated.rename(output)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--source-data", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS)
    parser.add_argument("--workspaces", type=Path, default=HERE / "workspaces")
    parser.add_argument("--prepared", type=Path, default=HERE / "prepared")
    args = parser.parse_args()
    for name in ("repo", "benchmark", "source_data", "patterns", "workspaces", "prepared"):
        setattr(args, name, getattr(args, name).resolve())
    return args


def main() -> int:
    args = parse_args()
    if not (args.repo / ".git").exists():
        raise ValueError(f"not a Linux Git repository: {args.repo}")
    for name in CODE_FILES:
        if not (args.benchmark / name).is_file():
            raise FileNotFoundError(args.benchmark / name)
    source = {
        name: read_csv(args.source_data / name)
        for name in (
            "vulnerability_families.csv",
            "family_cluster_links.csv",
            "root_cause_clusters.csv",
            "case_family_map.csv",
            "case_cluster_map.csv",
        )
    }
    source["patterns.csv"] = read_csv(args.patterns)
    selection, members_by_label, seeds = load_inputs(args)
    digest = curated_digest()
    index = []
    for position, selected in enumerate(selection, 1):
        label = selected["cluster_label"]
        workspace, cluster_uid = prepare_workspace(
            args, selected, members_by_label[label], seeds[label], source, digest
        )
        prepared = prepare_manifest(
            args, selected, members_by_label[label], seeds[label], workspace, cluster_uid
        )
        row = {
            "cluster_label": label,
            "family_uid": selected["family_uid"],
            "cluster_uid": cluster_uid,
            "seed": seeds[label]["seed_hexsha"],
            "target_count": int(seeds[label]["target_count"]),
            "workspace": str(workspace),
            "prepared": str(prepared),
        }
        index.append(row)
        print(
            f"PREPARED {position}/10 {label} seed={row['seed'][:12]} "
            f"targets={row['target_count']}",
            flush=True,
        )
    atomic_json(HERE / "prepared_index.json", {
        "version": 1,
        "curated_sha256": digest,
        "cluster_count": len(index),
        "target_count": sum(row["target_count"] for row in index),
        "clusters": index,
    })
    print(f"READY clusters={len(index)} targets={sum(row['target_count'] for row in index)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
