#!/usr/bin/env python3
"""Prepare, run, and evaluate one Clairvoyant Linux variant-search cluster."""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
DEFAULT_REPO = Path("/mnt/raid/home/yangshuangning/linux")
DEFAULT_PREPARED = EXPERIMENTS / "benchmark_large_scale" / "prepared"
DEFAULT_WORKSPACES = EXPERIMENTS / "benchmark_large_scale" / "workspaces"
DEFAULT_CLAIRVOYANT = EXPERIMENTS / ".clairvoyant-build" / "release" / "clairvoyant"
DEFAULT_CLAUDE = Path("/mnt/raid/home/yangshuangning/claude-code-2.1.88/claude")
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
MAX_FINDING_LINES = 100


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def checked(command: list[str], *, cwd: Path | None = None, timeout: int = 600,
            env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True,
                            timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout)[-4000:]
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def find_manifest(seed: str, prepared_root: Path) -> tuple[Path, dict]:
    matches: list[tuple[Path, dict]] = []
    for path in prepared_root.glob("*/rootcause-*/evaluation/manifest.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["seed"]["hexsha"].startswith(seed):
            matches.append((path, manifest))
    if len(seed) < 7 or len(matches) != 1:
        raise ValueError(f"seed must uniquely identify one prepared cluster; matches={len(matches)}")
    return matches[0]


def find_family_workspace(seed: str, workspaces_root: Path) -> Path:
    matches = []
    for workspace in workspaces_root.glob("family-*"):
        path = workspace / "data" / "case_family_map.csv"
        if not path.is_file():
            continue
        with path.open(newline="", encoding="utf-8") as handle:
            if any(row["hexsha"].startswith(seed) for row in csv.DictReader(handle)):
                matches.append(workspace)
    if len(matches) != 1:
        raise ValueError(f"cannot identify family workspace for {seed}; matches={len(matches)}")
    return matches[0]


def git(command: list[str], *, timeout: int = 1200) -> None:
    checked(["git", *command], timeout=timeout)


def materialize_snapshot(repo: Path, revision: str, snapshot: str,
                         public: Path, private: Path) -> None:
    destination = public / "snapshots" / snapshot
    hidden_git = private / "snapshot-git" / snapshot
    if destination.is_dir() and hidden_git.is_dir():
        return
    if destination.exists() or hidden_git.exists():
        raise ValueError(f"partial snapshot exists for {snapshot}; use a new output directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    hidden_git.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{snapshot}.preparing-{os.getpid()}")
    if temporary.exists():
        shutil.rmtree(temporary)
    print(f"materializing {snapshot} (C/header files only)...", flush=True)
    try:
        git(["clone", "--shared", "--no-checkout", str(repo), str(temporary)])
        git(["-C", str(temporary), "sparse-checkout", "set", "--no-cone", "*.c", "*.h"])
        git(["-C", str(temporary), "checkout", "--detach", revision])
        (temporary / ".git").rename(hidden_git)
        temporary.rename(destination)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def prepare(args: argparse.Namespace) -> dict:
    output, repo = args.output.resolve(), args.repo.resolve()
    public, private = output / "public", output / "private"
    manifest_path = private / "evaluation" / "manifest.json"
    source_path, source_manifest = find_manifest(args.seed, args.prepared_root)
    if manifest_path.is_file():
        current = json.loads(manifest_path.read_text(encoding="utf-8"))
        if current["seed"]["hexsha"] != source_manifest["seed"]["hexsha"]:
            raise ValueError("output was prepared for a different seed")
        manifest = current
    else:
        if output.exists() and any(output.iterdir()):
            raise ValueError("output is non-empty but has no private manifest; choose a new output")
        manifest = source_manifest
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, manifest_path)
        atomic_json(public / "seed.json", manifest["seed"])
        model_input = {
            "seed": manifest["seed"],
            "snapshots": list(manifest["snapshots"]),
            "task": "Find other instances of the seed mechanism in independent Linux source snapshots.",
        }
        atomic_json(public / "model_input.json", model_input)
        (public / "TASK.md").write_text(
            "# Linux kernel vulnerability variant search\n\n"
            "Derive a transferable invariant from `seed.json`, then inspect every directory below "
            "`snapshots/`. Snapshot IDs are opaque and independent. The seed is not a reportable "
            "finding. Git metadata and hidden evaluation labels are intentionally unavailable.\n",
            encoding="utf-8",
        )
    for snapshot, revision in manifest["snapshots"].items():
        materialize_snapshot(repo, revision, snapshot, public, private)
    atomic_json(public / "snapshot_inventory.json", {
        "snapshots": list(manifest["snapshots"]),
        "note": "opaque independent trees; revisions and targets are hidden",
    })
    workspace = find_family_workspace(manifest["seed"]["hexsha"], args.workspaces_root)
    atomic_json(private / "adapter.json", {
        "version": 1,
        "seed": manifest["seed"]["hexsha"],
        "family_workspace": str(workspace),
        "source_manifest": str(source_path),
    })
    print(f"prepared seed={manifest['seed']['hexsha'][:12]} snapshots={len(manifest['snapshots'])} "
          f"output={output}", flush=True)
    return manifest


def yaml_string(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def write_dispatch_config(args: argparse.Namespace, public: Path, state: Path) -> Path:
    worker = HERE / "worker.py"
    lines = [
        f"db_path: {yaml_string(state / 'clairvoyant.db')}",
        "runtime:",
        "  interval: 1",
        f"  max_workers: {args.workers}",
        "  max_running_projects: 1",
        f"  max_project_workers: {args.workers}",
        "  healthcheck_timeout: 30",
        "  prompt_group: default",
        "tasks:",
        "  bootstrap:",
        f"    timeout: {args.worker_timeout}",
        "    conclude_timeout: 120",
        "  reason:",
        f"    timeout: {args.worker_timeout}",
        f"    max_intents: {args.max_intents}",
        "  explore:",
        f"    timeout: {args.worker_timeout}",
        "    conclude_timeout: 120",
        "worker_name: linux-variant",
        "bootstrap_intent: derive a transferable Linux-kernel vulnerability mechanism profile",
        "workers:",
    ]
    roles = (("bootstrap", 1), ("reason", 1), ("explore", args.workers))
    for role, maximum in roles:
        lines += [
            f"  - name: linux-variant-{role}",
            "    type: command",
            f"    task_types: [{role}]",
            f"    max_running: {maximum}",
            "    program: /usr/bin/python3",
            "    args:",
            f"      - {yaml_string(worker)}",
            "      - --role",
            f"      - {role}",
            "    env:",
            '      GLM_API_KEY: "${GLM_API_KEY}"',
            '      GLM_MODEL: "${GLM_MODEL}"',
            '      GLM_EFFORT: "${GLM_EFFORT}"',
            '      GLM_ANTHROPIC_BASE_URL: "${GLM_ANTHROPIC_BASE_URL}"',
            '      CLAUDE_BIN: "${CLAUDE_BIN}"',
            '      LANDLOCK_BIN: "${LANDLOCK_BIN}"',
            '      VARIANT_PUBLIC_ROOT: "${VARIANT_PUBLIC_ROOT}"',
            '      VARIANT_STATE_ROOT: "${VARIANT_STATE_ROOT}"',
            '      VARIANT_WORKER_TIMEOUT: "${VARIANT_CLAUDE_TIMEOUT}"',
            '      VARIANT_EXPLORE_TIMEOUT: "${VARIANT_EXPLORE_TIMEOUT}"',
            '      CLAUDE_MAX_TURNS: "${CLAUDE_MAX_TURNS}"',
        ]
    path = state / "dispatch.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def ensure_landlock() -> Path:
    source = HERE / "landlock-run.c"
    binary = HERE / ".bin" / "landlock-run"
    if not binary.is_file() or binary.stat().st_mtime_ns < source.stat().st_mtime_ns:
        binary.parent.mkdir(parents=True, exist_ok=True)
        checked(["gcc", "-O2", "-Wall", "-Wextra", "-o", str(binary), str(source)])
    return binary


def sandbox_command(command: list[str], *, public: Path, state: Path,
                    clairvoyant: Path, claude: Path) -> list[str]:
    wrapper = ensure_landlock()
    # Never allow HERE as a directory: run outputs (including hidden manifests)
    # live below it. Expose only the worker implementation and public prompts.
    readonly = [Path("/usr"), Path("/etc"), Path("/dev"), Path("/proc"),
                HERE / "worker.py", HERE / "done_tool.py", HERE / "prompts", ensure_landlock(),
                public, clairvoyant, claude]
    result = [str(wrapper)]
    for path in readonly:
        if path.exists():
            result += ["--ro", str(path)]
    # Shells, compilers, and test runners routinely write to /dev/null.  Keep
    # the rest of /dev read-only while granting this single harmless sink.
    if Path("/dev/null").exists():
        result += ["--rw", "/dev/null"]
    result += ["--rw", str(state), "--", *command]
    return result


def parse_value(result: subprocess.CompletedProcess[str]) -> dict:
    envelope = json.loads(result.stdout)
    if envelope.get("result") != "ok":
        raise RuntimeError(f"Clairvoyant error: {result.stdout[-2000:]}")
    return envelope["response"]["value"]


def project_status(clairvoyant: Path, db: Path, project_id: str) -> str:
    result = checked([str(clairvoyant), "observe", "--db-path", str(db),
                      "--project-id", project_id])
    projects = parse_value(result)["projects"]
    return projects[0]["status"] if projects else "missing"


def create_project(clairvoyant: Path, db: Path, state: Path, public: Path,
                   manifest: dict) -> str:
    saved = state / "project.json"
    if saved.is_file():
        return json.loads(saved.read_text(encoding="utf-8"))["project_id"]
    snapshots = ", ".join(manifest["snapshots"])
    seed = manifest["seed"]
    origin = (
        f"Public workspace: {public}. Seed: {seed['one_line_summary']}. "
        "The full public demonstration is in seed.json. Snapshot IDs: " + snapshots
    )
    goal = (
        "Search every independent snapshot for credible variants of the seed's root-cause "
        "mechanism; preserve exact source evidence and resolve every promising candidate."
    )
    hint = (
        "Use only the public workspace. Never inspect Git metadata or hidden evaluation data. "
        "Plan complementary semantic branches rather than only seed-name searches."
    )
    result = checked([
        str(clairvoyant), "project", "--db-path", str(db), "create",
        "--title", f"linux-variant-{seed['hexsha'][:12]}",
        "--origin", origin, "--goal", goal, "--hint", hint,
        "--hint-creator", "variant-adapter",
    ])
    project_id = parse_value(result)["project"]["id"]
    atomic_json(saved, {"project_id": project_id})
    return project_id


def run_dispatch(args: argparse.Namespace, manifest: dict) -> str:
    if not os.environ.get("GLM_API_KEY"):
        raise ValueError("GLM_API_KEY is not set")
    output = args.output.resolve()
    public, state = output / "public", output / "agent-state"
    state.mkdir(parents=True, exist_ok=True)
    for path in (args.clairvoyant, args.claude):
        if not path.is_file():
            raise FileNotFoundError(path)
    config = write_dispatch_config(args, public, state)
    db = state / "clairvoyant.db"
    project_id = create_project(args.clairvoyant, db, state, public, manifest)
    environment = os.environ.copy()
    environment.update({
        "GLM_MODEL": args.model,
        "GLM_EFFORT": args.effort,
        "GLM_ANTHROPIC_BASE_URL": args.base_url,
        "CLAUDE_BIN": str(args.claude),
        "LANDLOCK_BIN": str(ensure_landlock()),
        "VARIANT_PUBLIC_ROOT": str(public),
        "VARIANT_STATE_ROOT": str(state),
        # Return a durable worker event before Clairvoyant's outer lease
        # timeout, otherwise the dispatcher releases and immediately retries
        # the same intent forever.
        "VARIANT_CLAUDE_TIMEOUT": str(max(30, args.worker_timeout - 60)),
        # Preserve most of the worker lease for a same-session finalize phase.
        # GLM often keeps auditing after it has already found a credible source
        # candidate; the adapter resumes that exact session and requires it to
        # turn accumulated evidence into the native done event.
        "VARIANT_EXPLORE_TIMEOUT": str(min(1200, max(30, args.worker_timeout - 660))),
        "CLAUDE_MAX_TURNS": str(args.worker_max_turns),
    })
    deadline = time.monotonic() + args.timeout
    dispatch_log = state / "dispatch.log"
    consecutive_failures = 0
    tick = 0
    status = project_status(args.clairvoyant, db, project_id)
    while status == "active" and tick < args.max_ticks and time.monotonic() < deadline:
        tick += 1
        # Let Clairvoyant refill the worker pool so independent intents run
        # concurrently.  The invocation may span bootstrap -> reason ->
        # explore, therefore its supervisor uses the whole run deadline rather
        # than a single worker's timeout.
        command = [str(args.clairvoyant), "dispatch", "--config", str(config),
                   "--db-path", str(db), "--refill-once"]
        secured = sandbox_command(command, public=public, state=state,
                                  clairvoyant=args.clairvoyant, claude=args.claude)
        remaining = max(1, int(deadline - time.monotonic()))
        try:
            result = subprocess.run(secured, cwd=public, env=environment, text=True,
                                    capture_output=True,
                                    timeout=remaining)
            with dispatch_log.open("a", encoding="utf-8") as handle:
                handle.write(f"\n===== tick {tick} rc={result.returncode} =====\n")
                handle.write(result.stdout)
                handle.write(result.stderr)
            consecutive_failures = consecutive_failures + 1 if result.returncode else 0
        except subprocess.TimeoutExpired as exc:
            with dispatch_log.open("a", encoding="utf-8") as handle:
                handle.write(f"\n===== tick {tick} timeout =====\n{exc.stdout or ''}\n{exc.stderr or ''}\n")
            consecutive_failures += 1
        status = project_status(args.clairvoyant, db, project_id)
        print(f"tick={tick}/{args.max_ticks} project={project_id} status={status} "
              f"failures={consecutive_failures}", flush=True)
        if consecutive_failures >= 3:
            status = "failed"
            break
    if status == "active":
        status = "budget_exhausted" if time.monotonic() >= deadline else "failed"
    atomic_json(state / "run_status.json", {
        "project_id": project_id, "status": status, "ticks": tick,
        "wall_timeout": args.timeout, "model": args.model, "effort": args.effort,
    })
    for format_name, filename in (("timeline", "timeline.txt"), ("yaml", "project.yaml")):
        result = subprocess.run([
            str(args.clairvoyant), "project", "--db-path", str(db), "export",
            project_id, "--format", format_name,
        ], text=True, capture_output=True)
        (state / filename).write_text(result.stdout + result.stderr, encoding="utf-8")
    return status


def safe_source_path(value: object) -> str:
    if not isinstance(value, str) or not value or PurePosixPath(value).is_absolute():
        raise ValueError("path must be a non-empty relative source path")
    if any(part in {"", ".", "..", ".git"} for part in value.split("/")):
        raise ValueError("unsafe source path")
    if Path(value).suffix not in {".c", ".h"}:
        raise ValueError("only C source and headers are measurable")
    return value


def normalize_finding_range(start: int, end: int, quote: object,
                            lines: list[str]) -> tuple[int, int, str | None]:
    """Bound an oversized report without consulting hidden evaluation data."""
    if end - start + 1 <= MAX_FINDING_LINES:
        return start, end, None

    declared = "\n".join(lines[start - 1:end])
    if isinstance(quote, str) and len(quote.strip()) >= 8:
        offset = declared.find(quote)
        if offset >= 0:
            quote_start = start + declared[:offset].count("\n")
            quote_end = min(end, quote_start + quote.count("\n"))
            quote_span = quote_end - quote_start + 1
            if quote_span <= MAX_FINDING_LINES:
                remaining = MAX_FINDING_LINES - quote_span
                before = min(quote_start - start, remaining // 2)
                after = min(end - quote_end, remaining - before)
                remaining -= before + after
                if remaining:
                    extra_before = min(quote_start - start - before, remaining)
                    before += extra_before
                    remaining -= extra_before
                if remaining:
                    after += min(end - quote_end - after, remaining)
                return (quote_start - before, quote_end + after,
                        "literal_quote_window")

    return start, min(end, start + MAX_FINDING_LINES - 1), "leading_window"


def compact_source_text(value: str) -> str:
    """Compare source evidence while ignoring formatting-only whitespace."""
    return re.sub(r"\s+", "", value)


def collect_findings(output: Path, manifest: dict) -> tuple[list[dict], list[dict]]:
    public = output / "public"
    artifact_dir = output / "agent-state" / "findings"
    findings: list[dict] = []
    audits: list[dict] = []
    for artifact in sorted(artifact_dir.glob("*.json")) if artifact_dir.is_dir() else []:
        audit = {"artifact": str(artifact), "accepted": 0,
                 "normalized": [], "rejected": []}
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            rows = payload.get("findings", [])
            if not isinstance(rows, list):
                raise ValueError("findings must be a list")
            for index, row in enumerate(rows):
                try:
                    if not isinstance(row, dict):
                        raise ValueError("finding must be an object")
                    snapshot = row.get("snapshot")
                    if snapshot not in manifest["snapshots"]:
                        raise ValueError("unknown snapshot")
                    path = safe_source_path(row.get("path"))
                    start, end = row.get("start"), row.get("end")
                    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
                        raise ValueError("invalid positive line range")
                    source_path = public / "snapshots" / snapshot / path
                    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if end > len(lines):
                        raise ValueError("reported range exceeds file length")
                    original_start, original_end = start, end
                    start, end, normalization = normalize_finding_range(
                        start, end, row.get("quote"), lines
                    )
                    normalizations = []
                    if normalization:
                        normalizations.append({
                            "index": index,
                            "method": normalization,
                            "original_start": original_start,
                            "original_end": original_end,
                            "start": start,
                            "end": end,
                        })
                    selected = "\n".join(lines[start - 1:end])
                    submitted_quote = row.get("quote")
                    if not isinstance(submitted_quote, str) or not submitted_quote.strip():
                        quote = selected
                        normalizations.append({
                            "index": index,
                            "method": "source_quote_generated",
                            "reason": "submitted quote was missing",
                        })
                    elif submitted_quote in selected:
                        quote = submitted_quote
                    elif compact_source_text(submitted_quote) in compact_source_text(selected):
                        quote = selected
                        normalizations.append({
                            "index": index,
                            "method": "whitespace_normalized_source_quote",
                            "reason": "submitted quote differed only in source whitespace",
                        })
                    else:
                        raise ValueError("quote describes source text not present in the range")
                    confidence = row.get("confidence")
                    reason = row.get("reason")
                    if confidence not in ALLOWED_CONFIDENCE:
                        raise ValueError("invalid confidence")
                    if not isinstance(reason, str) or not reason.strip():
                        raise ValueError("missing reason")
                    findings.append({
                        "id": f"finding-{len(findings) + 1:04d}",
                        "snapshot": snapshot, "path": path, "start": start, "end": end,
                        "quote": quote, "confidence": confidence, "reason": reason,
                        "intent_id": payload.get("intent_id", artifact.stem),
                        "branch": payload.get("branch", ""),
                    })
                    audit["accepted"] += 1
                    audit["normalized"].extend(normalizations)
                except (OSError, ValueError) as exc:
                    audit["rejected"].append({"index": index, "error": str(exc)})
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            audit["error"] = str(exc)
        audits.append(audit)
    return findings, audits


def load_evaluator(workspace: Path):
    module_name = "clairvoyant_frozen_dataset"
    sys.path.insert(0, str(workspace))
    try:
        spec = importlib.util.spec_from_file_location(module_name, workspace / "dataset.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load frozen evaluator")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def evaluate(args: argparse.Namespace, status: str | None = None) -> dict:
    output = args.output.resolve()
    manifest = json.loads((output / "private/evaluation/manifest.json").read_text(encoding="utf-8"))
    adapter = json.loads((output / "private/adapter.json").read_text(encoding="utf-8"))
    if status is None:
        saved = output / "agent-state/run_status.json"
        status = json.loads(saved.read_text(encoding="utf-8"))["status"] if saved.is_file() else "prepared"
    findings, audits = collect_findings(output, manifest)
    evaluation_status = "finished" if status == "completed" else status
    evaluator = load_evaluator(Path(adapter["family_workspace"]))
    report = evaluator.evaluate(manifest, findings, evaluation_status)
    # Only a completed Clairvoyant project is a final experiment result.
    # Frozen evaluators do not consistently classify adapter failures as
    # provisional, so preserve that distinction here.
    if status != "completed":
        report["provisional"] = True
    atomic_json(output / "findings.json", findings)
    atomic_json(output / "artifact_validation.json", audits)
    atomic_json(output / "evaluation.json", report)
    with (output / "evaluation.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["hexsha", "title", "snapshot", "coverage", "matched_finding_ids"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["targets"]:
            writer.writerow({**row, "matched_finding_ids": ";".join(row["matched_finding_ids"])})
    print(f"status={evaluation_status} findings={len(findings)} exact={report['exact_hunk_count']}/"
          f"{report['measurable']} located={report['located_in_changed_function_or_hunk']}/"
          f"{report['measurable']}", flush=True)
    return report


def doctor(args: argparse.Namespace) -> int:
    landlock = ensure_landlock()
    missing = [str(path) for path in (args.repo, args.prepared_root, args.workspaces_root,
                                      args.clairvoyant, args.claude) if not path.exists()]
    if missing:
        raise FileNotFoundError("missing required paths: " + ", ".join(missing))
    version = checked([str(args.claude), "--version"]).stdout.strip()
    checked([str(args.clairvoyant), "--help"])
    with tempfile.TemporaryDirectory(prefix="clairvoyant-variant-doctor.") as temporary:
        root = Path(temporary)
        public, state = root / "public", root / "state"
        public.mkdir()
        state.mkdir()
        config_args = argparse.Namespace(workers=4, worker_timeout=30, max_intents=4)
        config = write_dispatch_config(config_args, public, state)
        health_env = os.environ.copy()
        health_env.update({
            "GLM_API_KEY": health_env.get("GLM_API_KEY", "doctor-placeholder"),
            "GLM_MODEL": "GLM-5.3",
            "GLM_EFFORT": "low",
            "GLM_ANTHROPIC_BASE_URL": "https://llm.shtech.org",
            "CLAUDE_BIN": str(args.claude),
            "LANDLOCK_BIN": str(landlock),
            "VARIANT_PUBLIC_ROOT": str(public),
            "VARIANT_STATE_ROOT": str(state),
            "VARIANT_CLAUDE_TIMEOUT": "30",
            "VARIANT_EXPLORE_TIMEOUT": "30",
            "CLAUDE_MAX_TURNS": "100",
        })
        checked([str(args.clairvoyant), "dispatch", "--config", str(config),
                 "--startup-healthcheck-only"], env=health_env)
        allowed = root / "allowed.txt"
        denied = root.parent / f"{root.name}.denied.txt"
        allowed.write_text("allowed")
        denied.write_text("denied")
        probe = subprocess.run([
            str(landlock), "--ro", "/usr", "--ro", str(allowed), "--",
            "/usr/bin/python3", "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).read_text(); "
            "pathlib.Path(sys.argv[2]).read_text()", str(allowed), str(denied),
        ], text=True, capture_output=True)
        denied.unlink()
        if probe.returncode == 0 or "PermissionError" not in probe.stderr:
            raise RuntimeError("Landlock probe did not deny a non-allow-listed file")
    print(f"clairvoyant={args.clairvoyant}\nclaude={version}\nlandlock=ready\n"
          f"dispatch_config=valid\nglm_key={'present' if os.environ.get('GLM_API_KEY') else 'missing'}")
    return 0


def api_smoke(args: argparse.Namespace) -> int:
    if not os.environ.get("GLM_API_KEY"):
        raise ValueError("GLM_API_KEY is not set")
    landlock = ensure_landlock()
    with tempfile.TemporaryDirectory(prefix="clairvoyant-glm-smoke.") as temporary:
        root = Path(temporary)
        public, state = root / "public", root / "state"
        public.mkdir()
        state.mkdir()
        environment = os.environ.copy()
        environment.update({
            "GLM_MODEL": args.model,
            "GLM_ANTHROPIC_BASE_URL": args.base_url,
            "CLAUDE_BIN": str(args.claude),
            "LANDLOCK_BIN": str(landlock),
            "VARIANT_PUBLIC_ROOT": str(public),
            "VARIANT_STATE_ROOT": str(state),
            "VARIANT_WORKER_TIMEOUT": str(args.worker_timeout),
            "CAIRN_PROJECT_ID": "api-smoke",
        })
        prompt = (
            "# Task\nReturn a planning WorkerEvent.\n\n## Context\n"
            "### Graph\norigin: Linux kernel source snapshots\ngoal: verify GLM worker transport\n"
            "facts:\n  - id: f001\n    description: seed mechanism is available\n\n"
            "### Valid facts\nf001\n\n### Open Intents\n[]\n"
        )
        result = subprocess.run(
            [sys.executable, str(HERE / "worker.py"), "--role", "reason"],
            input=prompt, text=True, capture_output=True, env=environment,
            timeout=args.worker_timeout + 30,
        )
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        print(result.stdout, end="")
        events = scan_worker_output(result.stdout)
        if result.returncode or not events or any(event.get("event") == "error" for event in events):
            return 2
    return 0


def scan_worker_output(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("event"), str):
            events.append(value)
    return events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "run", "evaluate", "doctor", "api-smoke"):
        sub = commands.add_parser(name)
        sub.add_argument("--output", type=Path,
                         required=name in {"prepare", "run", "evaluate"})
        sub.add_argument("--repo", type=Path, default=DEFAULT_REPO)
        sub.add_argument("--prepared-root", type=Path, default=DEFAULT_PREPARED)
        sub.add_argument("--workspaces-root", type=Path, default=DEFAULT_WORKSPACES)
        sub.add_argument("--clairvoyant", type=Path, default=DEFAULT_CLAIRVOYANT)
        sub.add_argument("--claude", type=Path, default=DEFAULT_CLAUDE)
        if name in {"prepare", "run"}:
            sub.add_argument("--seed", required=True)
        if name == "run":
            sub.add_argument("--model", default="GLM-5.3")
            sub.add_argument("--effort", choices=("low", "medium", "high"), default="low")
            sub.add_argument("--base-url", default="https://llm.shtech.org")
            sub.add_argument("--workers", type=int, default=16)
            sub.add_argument("--max-intents", type=int, default=16)
            sub.add_argument("--worker-timeout", type=int, default=1200)
            sub.add_argument(
                "--worker-max-turns", type=int, default=100,
                help="hard cap on Claude Code turns per worker (1-100)",
            )
            sub.add_argument("--timeout", type=int, default=7200)
            sub.add_argument("--max-ticks", type=int, default=64)
        if name == "api-smoke":
            sub.add_argument("--model", default="GLM-5.3")
            sub.add_argument("--base-url", default="https://llm.shtech.org")
            sub.add_argument("--worker-timeout", type=int, default=180)
    args = parser.parse_args()
    if args.command == "run" and not 1 <= args.worker_max_turns <= 100:
        parser.error("--worker-max-turns must be between 1 and 100")
    for name in ("repo", "prepared_root", "workspaces_root", "clairvoyant", "claude", "output"):
        value = getattr(args, name, None)
        if value is not None:
            setattr(args, name, value.resolve())
    return args


def main() -> int:
    args = parse_args()
    if args.command == "doctor":
        return doctor(args)
    if args.command == "api-smoke":
        return api_smoke(args)
    if args.command == "prepare":
        prepare(args)
        return 0
    if args.command == "evaluate":
        evaluate(args)
        return 0
    manifest = prepare(args)
    try:
        status = run_dispatch(args, manifest)
    except Exception:
        state = args.output / "agent-state"
        state.mkdir(parents=True, exist_ok=True)
        atomic_json(state / "run_status.json", {"status": "failed"})
        evaluate(args, "failed")
        raise
    evaluate(args, status)
    return 0 if status in {"completed", "budget_exhausted"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
