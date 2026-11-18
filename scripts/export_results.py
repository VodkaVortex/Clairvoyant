#!/usr/bin/env python3
"""Export source-free Clairvoyant evaluation and runtime summaries."""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-exact", type=int, default=20)
    parser.add_argument("--previous-measurable", type=int, default=64)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    clusters = []
    exact_hits = []
    runtime = []
    for index in range(1, 11):
        cluster = f"C{index}"
        root = args.runs_root / cluster
        report = json.loads((root / "evaluation.json").read_text(encoding="utf-8"))
        findings_count = len(json.loads((root / "findings.json").read_text(encoding="utf-8")))
        clusters.append({
            "cluster": cluster,
            "target_count": report["target_count"],
            "measurable": report["measurable"],
            "exact_hunk_count": report["exact_hunk_count"],
            "exact_hunk_recall": report["exact_hunk_recall"],
            "accepted_findings": findings_count,
            "run_status": report["run_status"],
            "provisional": report["provisional"],
        })
        for target in report["targets"]:
            if target["coverage"] == "exact_hunk":
                exact_hits.append({
                    "cluster": cluster,
                    "snapshot": target["snapshot"],
                    "hexsha": target["hexsha"],
                    "title": target["title"],
                    "matched_finding_ids": ";".join(target["matched_finding_ids"]),
                })
        database = root / "agent-state/clairvoyant.db"
        if database.is_file():
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                done, leased, opened = connection.execute(
                    """
                    SELECT sum(target_fact IS NOT NULL),
                           sum(target_fact IS NULL AND worker IS NOT NULL),
                           sum(target_fact IS NULL AND worker IS NULL)
                    FROM intents WHERE project_id = 'proj_001'
                    """
                ).fetchone()
            runtime.append({"cluster": cluster, "done": done, "leased": leased, "open": opened})

    exact = sum(row["exact_hunk_count"] for row in clusters)
    measurable = sum(row["measurable"] for row in clusters)
    aggregate = {
        "exported_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "metric": "exact_hunk_historical_location_recall",
        "exact_hunk_count": exact,
        "measurable": measurable,
        "rate": exact / measurable,
        "previous": {
            "exact_hunk_count": args.previous_exact,
            "measurable": args.previous_measurable,
            "rate": args.previous_exact / args.previous_measurable,
        },
        "delta_exact": exact - args.previous_exact,
        "delta_rate": exact / measurable - args.previous_exact / args.previous_measurable,
        "provisional": any(row["provisional"] for row in clusters),
    }
    write_json(args.output / "aggregate.json", aggregate)
    write_json(args.output / "runtime_progress.json", runtime)

    with (args.output / "per_cluster.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=clusters[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(clusters)
    with (args.output / "exact_hits.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=exact_hits[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(exact_hits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
