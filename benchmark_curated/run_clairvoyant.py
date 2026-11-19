#!/usr/bin/env python3
"""Run the curated ten clusters with a bounded independent Clairvoyant pool."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
CLAIRVOYANT = HERE.parent / "clairvoyant_variant_search"
DEFAULT_OUTPUT = CLAIRVOYANT / "runs/10_cluster"


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def load_index(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    clusters = payload.get("clusters")
    if payload.get("cluster_count") != 10 or not isinstance(clusters, list) or len(clusters) != 10:
        raise ValueError("prepared_index.json must describe exactly ten curated clusters")
    if [row.get("cluster_label") for row in clusters] != [f"C{i}" for i in range(1, 11)]:
        raise ValueError("prepared_index.json labels must be C1 through C10")
    return clusters


def saved_result(output: Path) -> dict | None:
    path = output / "evaluation.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def recent_error_markers(output: Path) -> dict[str, int]:
    counts = {"rate_limit": 0, "connection": 0, "model_error": 0}
    patterns = {
        "rate_limit": (
            "rate limit",
            "too many requests",
            "http 429",
            "status code 429",
            "status=429",
        ),
        "connection": ("connection error", "econnreset", "socket hang up", "network error"),
        "model_error": (
            "overloaded",
            "http 529",
            "status code 529",
            "status=529",
            "model request failed",
        ),
    }
    log_dir = output / "agent-state/worker-logs"
    for path in list(log_dir.glob("*.stderr.txt")) + list(log_dir.glob("*.debug.log")):
        try:
            with path.open("rb") as handle:
                handle.seek(max(0, path.stat().st_size - 65536))
                text = handle.read().decode("utf-8", errors="replace").lower()
        except OSError:
            continue
        for name, needles in patterns.items():
            if any(needle in text for needle in needles):
                counts[name] += 1
    return counts


def cluster_health(root: Path, row: dict) -> dict:
    output = root / row["cluster_label"]
    state = output / "agent-state"
    result = saved_result(output)
    return {
        "target_count": row["target_count"],
        "prepared": (output / "private/evaluation/manifest.json").is_file(),
        "stream_logs": len(list((state / "worker-logs").glob("*.stream.jsonl"))),
        "terminal_events": len(list((state / "terminal-events").glob("*.json"))),
        "artifacts": len(list((state / "findings").glob("*.json"))),
        "errors": recent_error_markers(output),
        "run_status": result.get("run_status") if result else None,
        "provisional": result.get("provisional") if result else None,
        "exact": result.get("exact_hunk_count") if result else None,
        "measurable": result.get("measurable") if result else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=HERE / "prepared_index.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--max-intents", type=int, default=16)
    parser.add_argument("--worker-max-turns", type=int, default=100)
    parser.add_argument("--worker-timeout", type=int, default=3600)
    parser.add_argument("--small-timeout", type=int, default=7200)
    parser.add_argument("--large-timeout", type=int, default=14400)
    parser.add_argument("--large-threshold", type=int, default=8)
    parser.add_argument("--stagger-seconds", type=int, default=600)
    parser.add_argument("--model", default="GLM-5.3")
    parser.add_argument("--effort", choices=("low", "medium", "high"), default="high")
    args = parser.parse_args()
    for name in ("index", "output"):
        setattr(args, name, getattr(args, name).resolve())
    if args.jobs < 1 or args.workers < 1:
        parser.error("--jobs and --workers must be positive")
    return args


def main() -> int:
    args = parse_args()
    if not os.environ.get("GLM_API_KEY"):
        raise ValueError("GLM_API_KEY is not set")
    clusters = load_index(args.index)
    args.output.mkdir(parents=True, exist_ok=True)
    log_dir = args.output / "_logs"
    log_dir.mkdir(exist_ok=True)
    status_path = args.output / "batch_status.json"
    health_path = args.output / "health.json"
    lock = threading.Lock()
    state: dict[str, object] = {
        "started_at": timestamp(),
        "model": args.model,
        "effort": args.effort,
        "jobs": args.jobs,
        "workers_per_cluster": args.workers,
        "max_batch_workers": args.jobs * args.workers,
        "active": [],
        "completed": {},
        "failed": {},
    }

    def save_state() -> None:
        with lock:
            atomic_json(status_path, state)

    stop_health = threading.Event()

    def monitor() -> None:
        while not stop_health.wait(60):
            snapshot = {
                "updated_at": timestamp(),
                "batch": dict(state),
                "clusters": {row["cluster_label"]: cluster_health(args.output, row) for row in clusters},
            }
            atomic_json(health_path, snapshot)

    def run_one(row: dict, delay: int) -> tuple[str, dict]:
        label = row["cluster_label"]
        if delay:
            print(f"STAGGER {label} waiting={delay}s", flush=True)
            time.sleep(delay)
        output = args.output / label
        existing = saved_result(output)
        if existing and existing.get("run_status") in {"finished", "budget_exhausted"}:
            return label, {"status": "skipped", "evaluation": existing}
        timeout = args.large_timeout if int(row["target_count"]) >= args.large_threshold else args.small_timeout
        command = [
            sys.executable,
            str(CLAIRVOYANT / "run.py"),
            "run",
            "--repo",
            "/mnt/raid/home/yangshuangning/linux",
            "--prepared-root",
            str(HERE / "prepared"),
            "--workspaces-root",
            str(HERE / "workspaces"),
            "--seed",
            row["seed"],
            "--output",
            str(output),
            "--model",
            args.model,
            "--effort",
            args.effort,
            "--workers",
            str(args.workers),
            "--max-intents",
            str(args.max_intents),
            "--worker-max-turns",
            str(args.worker_max_turns),
            "--worker-timeout",
            str(args.worker_timeout),
            "--timeout",
            str(timeout),
        ]
        with lock:
            active = state["active"]
            assert isinstance(active, list)
            active.append(label)
            atomic_json(status_path, state)
        print(
            f"START {label} seed={row['seed'][:12]} targets={row['target_count']} timeout={timeout}",
            flush=True,
        )
        log = log_dir / f"{label}.log"
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[{timestamp()}] $ {' '.join(command)}\n")
            handle.flush()
            result = subprocess.run(
                command,
                cwd=CLAIRVOYANT,
                stdout=handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
        evaluation = saved_result(output)
        payload = {
            "status": "done" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "finished_at": timestamp(),
            "evaluation": evaluation,
        }
        with lock:
            active = state["active"]
            assert isinstance(active, list)
            if label in active:
                active.remove(label)
            destination = state["completed"] if result.returncode == 0 else state["failed"]
            assert isinstance(destination, dict)
            destination[label] = payload
            atomic_json(status_path, state)
        exact = evaluation.get("exact_hunk_count") if evaluation else None
        measurable = evaluation.get("measurable") if evaluation else None
        print(f"DONE {label} rc={result.returncode} exact={exact}/{measurable}", flush=True)
        return label, payload

    save_state()
    health_thread = threading.Thread(target=monitor, daemon=True)
    health_thread.start()
    # Longest clusters first minimizes the final tail. The second project is
    # deliberately delayed so API health can be observed at 16 batch workers
    # before the independent pool reaches its configured maximum of 32.
    ordered = sorted(clusters, key=lambda row: (-int(row["target_count"]), row["cluster_label"]))
    failures = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(run_one, row, args.stagger_seconds if index == 1 else 0): row
                for index, row in enumerate(ordered)
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    _, payload = future.result()
                    failures += payload.get("status") == "failed"
                except Exception as exc:
                    label = futures[future]["cluster_label"]
                    failures += 1
                    with lock:
                        failed = state["failed"]
                        assert isinstance(failed, dict)
                        failed[label] = {"status": "exception", "error": str(exc), "finished_at": timestamp()}
                        atomic_json(status_path, state)
                    print(f"FAILED {label}: {exc}", file=sys.stderr, flush=True)
    finally:
        stop_health.set()
        health_thread.join(timeout=2)
        with lock:
            state["finished_at"] = timestamp()
            atomic_json(status_path, state)
        atomic_json(health_path, {
            "updated_at": timestamp(),
            "batch": state,
            "clusters": {row["cluster_label"]: cluster_health(args.output, row) for row in clusters},
        })
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
