#!/usr/bin/env python3
"""Standalone one-seed kernel search experiment. Python 3.11+, Git, no pip dependencies."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from client import ModelClient, Trace
from dataset import HERE, data_digest, evaluate, git, prepare, table
from search_tools import SourceTools


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def model_input(manifest):
    # Deliberately excludes family descriptions, peers, commit identities, target paths, and ground truth.
    return {"seed": manifest["seed"], "snapshots": list(manifest["snapshots"]),
            "task": "Find other instances of this seed's mechanism by searching complete source trees. "
                    "Snapshot IDs are independent trees, not file hints. Findings must cite source you read."}


def save_results(output, manifest, state):
    atomic_json(output / "findings.json", state["findings"])
    report = evaluate(manifest, state["findings"], state["status"])
    atomic_json(output / "evaluation.json", report)
    fields = ["hexsha", "title", "snapshot", "coverage", "matched_finding_ids"]
    with (output / "evaluation.csv").open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["targets"]:
            writer.writerow({**row, "matched_finding_ids": ";".join(row["matched_finding_ids"])})
    print(f"status={state['status']} findings={len(state['findings'])} "
          f"exact={report['exact_hunk_count']}/{report['measurable']} "
          f"located={report['located_in_changed_function_or_hunk']}/{report['measurable']}", flush=True)
    for target in report["targets"]:
        print(f"  {target['hexsha'][:12]} {target['coverage']} {target['title']}", flush=True)
    print(f"output={output}", flush=True)
    return report


def compact(messages, findings, trace, step, coverage=None, maximum=120000):
    removed = 0
    # Preserve the system prompt and seed. Complete old assistant/tool-result pairs can be evicted;
    # full unabridged interactions remain in trace.jsonl. Current reports are supplied explicitly.
    while len(messages) > 4 and len(json.dumps(messages, ensure_ascii=False)) > maximum:
        del messages[2:4]
        removed += 2
    if removed:
        trace.log("context_compacted", step=step, removed_messages=removed)
    context = list(messages)
    if findings or coverage:
        recorded = [{key: finding[key] for key in ("id", "snapshot", "path", "start", "end")}
                    for finding in findings]
        # Keep the ledger ahead of the interaction history so the latest tool result remains
        # the most recent instruction. Deliberately omit executable report fields.
        context.insert(2, {"role": "user", "content": json.dumps({
            "recorded_findings": recorded,
            "coverage": coverage,
            "instruction": "Do not resubmit recorded findings. Complete every clue's remaining "
                           "snapshot coverage before finishing.",
        }, ensure_ascii=False)})
    return context


def recovery_feedback(action, error):
    """Explain how to recover using only model-visible actions, never target labels."""
    guidance = (
        "Correct the failed action or use list/search to obtain missing source information. "
        "Do not repeat unchanged invalid arguments. Provide a specific reason, not a placeholder."
    )
    if action.get("action") in {"read", "report"}:
        guidance += (
            " Line numbers are 1-based JSON integers: 1 <= start <= end. "
            "A read covers at most 180 lines and a report at most 40. "
            "If you do not know the line numbers, search for the desired function or symbol "
            "in the same snapshot and file, then read around an observed match. "
            "Use an actual symbol from your investigation as the search pattern, not placeholder text. "
            "Do not guess a range or silently replace zero with one. "
            "Reports also require a previously read range and an exact source quote."
        )
    if action.get("action") == "report":
        guidance += (
            " Report start/end should identify only the smallest actionable location where the "
            "defect should be fixed. Do not expand the range to include every supporting check, "
            "caller, or later use; cite distant evidence already read in the reason instead."
        )
        start, end = action.get("start"), action.get("end")
        if "range too wide" in error and type(start) is int and type(end) is int and start <= end:
            guidance += f" The failed report spans {end - start + 1} lines; reduce it to at most 40."
    if action.get("action") == "finish" and "cannot finish" in error:
        guidance += (
            " Continue checking the named remaining snapshots with search/read actions. "
            "Set coverage_for to the relevant clue shown in the error when an action genuinely "
            "tests that clue, then finish only after no snapshots remain."
        )
    return {"failed_action": action, "error": error, "guidance": guidance}


def execute(args, client_factory=ModelClient):
    output, repo = args.output.resolve(), args.repo.resolve()
    if output == repo or output.is_relative_to(repo):
        raise ValueError("experiment output must be outside the Linux repository")
    manifest_path = output / "evaluation" / "manifest.json"
    if args.resume:
        if not manifest_path.exists():
            raise ValueError("no saved experiment to resume")
        manifest = json.loads(manifest_path.read_text())
        if (manifest["repo"] != str(repo) or not manifest["seed"]["hexsha"].startswith(args.seed)
                or manifest["scope"] != args.scope or manifest["mode"] != args.mode
                or manifest["dataset_sha256"] != data_digest()):
            raise ValueError("resume identity mismatch: repo/seed/scope/mode/dataset changed")
    else:
        if output.exists() and any(output.iterdir()):
            raise ValueError("output is not empty; choose another directory or use --resume")
        manifest = prepare(repo, args.seed, args.scope, args.mode, args.ref)
        atomic_json(manifest_path, manifest)
        atomic_json(output / "seed.json", manifest["seed"])
        atomic_json(output / "model_input.json", model_input(manifest))
    if args.command == "prepare":
        print(f"prepared seed={manifest['seed']['hexsha'][:12]} snapshots={len(manifest['snapshots'])} "
              f"targets={len(manifest['targets'])} mode={manifest['mode']} output={output}")
        return 0
    with args.config.open("rb") as handle:
        config = tomllib.load(handle)["llm"]
    for key in ("retries", "max_tokens", "timeout"):
        if type(config[key]) is not int or config[key] < 1:
            raise ValueError(f"invalid llm.{key}")
    if args.steps < 1:
        raise ValueError("steps must be positive")
    secret = os.environ.get(config["api_key_env"], "")
    trace = Trace(output / "trace.jsonl", secret)
    system = (HERE / "prompt.txt").read_text()
    identity = {"config": config, "prompt_sha256": hashlib.sha256(system.encode()).hexdigest(),
                "code_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.glob("*.py")}}
    state_path = output / "state.json"
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if state["identity"] != identity:
            raise ValueError("code, prompt, or model config changed; start a new experiment")
    else:
        state = {"identity": identity, "step": 0, "status": "prepared", "reads": [], "findings": [],
                 "coverage": {"clues": {"seed": {"started_step": 0, "covered": {}}}},
                 "messages": [{"role": "system", "content": system},
                              {"role": "user", "content": json.dumps(model_input(manifest), ensure_ascii=False)}]}
        atomic_json(state_path, state)
    if state["status"] == "finished":
        save_results(output, manifest, state)
        return 0
    tools = SourceTools(repo, manifest["snapshots"], state["reads"], state["findings"],
                        state.get("coverage"))
    trace.log("run_started", seed=manifest["seed"]["hexsha"], mode=manifest["mode"],
              step=state["step"], step_budget=args.steps, resumed=args.resume, identity=identity)
    try:
        client = client_factory(config, trace)
        state["status"] = "running"
        while state["step"] < args.steps:
            step = state["step"] + 1
            messages = compact(state["messages"], tools.findings, trace, step,
                               tools.coverage_status())
            if state.get("pending_tool_error"):
                # Place the correction after findings so it remains prominent even after compaction.
                messages.append({"role": "user", "content": json.dumps({
                    "recovery_required": state["pending_tool_error"],
                    "instruction": "Use the error details to choose a corrected action. "
                                   "If line locations are unknown, search first and use returned line numbers.",
                }, ensure_ascii=False)})
            raw, action = client.action(messages, step)
            trace.log("model_action", step=step, action=action)
            try:
                result = tools.execute(action, step)
            except (ValueError, OSError, TimeoutError) as exc:
                result = {"error": str(exc)}
            if "error" in result:
                state["pending_tool_error"] = recovery_feedback(action, result["error"])
                result["recovery"] = state["pending_tool_error"]
            else:
                state.pop("pending_tool_error", None)
            trace.log("tool_result", step=step, action=action.get("action"), result=result)
            # Explicit source observations are the only feedback. No target scores enter the model loop.
            state["messages"] += [{"role": "assistant", "content": raw},
                                  {"role": "user", "content": json.dumps({"tool_result": result}, ensure_ascii=False)}]
            state.update(step=step, reads=tools.reads, findings=tools.findings,
                         coverage=tools.coverage)
            if result.get("finished"):
                state["status"] = "finished"
            atomic_json(state_path, state)
            # Always retain partial outputs without revealing evaluation to the model.
            atomic_json(output / "findings.json", state["findings"])
            print(f"step={step}/{args.steps} action={action.get('action')} "
                  f"findings={len(tools.findings)} error={result.get('error', '')[:140]}", flush=True)
            if state["status"] == "finished":
                break
        if state["status"] == "running":
            state["status"] = "budget_exhausted"
    except KeyboardInterrupt:
        state["status"] = "interrupted"
        trace.log("interrupted", step=state["step"])
    except Exception as exc:
        state["status"] = "failed"
        trace.log("run_error", step=state["step"], error=str(exc))
        print(f"run failed: {str(exc).replace(secret, '[REDACTED]') if secret else exc}", file=sys.stderr)
    finally:
        state.update(reads=tools.reads, findings=tools.findings, coverage=tools.coverage)
        atomic_json(state_path, state)
        report = save_results(output, manifest, state)
        trace.log("run_completed", status=state["status"], step=state["step"], evaluation=report)
    return 0 if state["status"] in {"finished", "budget_exhausted"} else 2


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List the copied 26 family cases and seed choices")
    for name in ("prepare", "run"):
        sub = commands.add_parser(name)
        sub.add_argument("--repo", type=Path, default=Path("/mnt/raid/home/yangshuangning/linux"))
        sub.add_argument("--seed", required=True, help="Fix commit prefix from the copied family")
        sub.add_argument("--scope", choices=("cluster", "family"), default="cluster")
        sub.add_argument("--mode", choices=("historical", "snapshot"), default="historical")
        sub.add_argument("--ref", default="HEAD", help="Revision searched in snapshot mode")
        sub.add_argument("--output", type=Path, required=True)
        sub.add_argument("--resume", action="store_true")
        sub.add_argument("--config", type=Path, default=HERE / "config.toml")
        sub.add_argument("--steps", type=int, default=40, help="Total action budget, including resumed steps")
    sub = commands.add_parser("evaluate", help="Re-evaluate saved findings without API calls")
    sub.add_argument("--output", type=Path, required=True)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "list":
        family = table("vulnerability_families.csv")[0]
        print(f"{family['family_uid']} | {family['family_name']}")
        names = {r["hexsha"]: r["one_line_summary"] for r in table("patterns.csv")}
        for row in table("case_family_map.csv"):
            print(f"{row['hexsha']} | {row['root_cause_cluster_uid'] or 'added_later (no cluster)'} | {names[row['hexsha']]}")
        return 0
    if args.command == "evaluate":
        output = args.output.resolve()
        manifest = json.loads((output / "evaluation/manifest.json").read_text())
        state = json.loads((output / "state.json").read_text())
        save_results(output, manifest, state)
        return 0
    return execute(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
