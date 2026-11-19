"""Read-only, bounded source tools. No shell, history, labels, or working-tree edits."""
from __future__ import annotations

import os
import select
import subprocess
import time
from pathlib import Path, PurePosixPath

from dataset import git


def source_path(value, *, empty=False):
    if not isinstance(value, str) or (not value and not empty):
        raise ValueError("path must be a source path")
    if value and (PurePosixPath(value).is_absolute() or any(p in {"..", ".git"} for p in value.split("/"))
                  or any(c in value for c in (":", "\x00", "\n", "\\")) or value.startswith("-")):
        raise ValueError("invalid source path")
    return value


def bounded_grep(repo, revision, pattern, path, offset):
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 500 or "\x00" in pattern:
        raise ValueError("pattern must be 1..500 characters")
    # :(literal) prevents model-supplied paths from being interpreted as Git pathspec magic.
    pathspecs = [":(glob)**/*.c", ":(glob)**/*.h"] if not path else [":(literal)" + path]
    args = ["git", "-C", str(repo), "grep", "-n", "-I", "-E", "-e", pattern, revision, "--", *pathspecs]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    chunks, size, lines, truncated, complete = [], 0, 0, False, False
    deadline = time.monotonic() + 60
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([proc.stdout], [], [], max(0, remaining))[0]:
                raise ValueError("source search timed out after 60 seconds; narrow path/pattern")
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                complete = True
                break
            chunks.append(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")
            if lines >= offset + 81 or size > 2_000_000:
                truncated = True
                break
    finally:
        if complete:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdout.close()
    content = b"".join(chunks).decode("utf-8", errors="replace")
    if not truncated and proc.returncode not in (0, 1):
        raise ValueError("git grep failed: " + content[:500])
    raw = content.splitlines()[offset:offset + 81]
    results, chars = [], 0
    consumed = 0
    for line in raw[:80]:
        prefix = revision + ":"
        if line.startswith(prefix):
            line = line[len(prefix):]
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[1].isdigit() and Path(parts[0]).suffix in {".c", ".h"}:
            item = {"path": parts[0], "line": int(parts[1]), "text": parts[2][:500]}
            if chars + len(item["text"]) > 16000:
                truncated = True
                break
            results.append(item)
            chars += len(item["text"])
        consumed += 1
    return {"matches": results, "truncated": truncated or len(raw) > 80,
            "next_offset": offset + consumed, "offset": offset}


class SourceTools:
    def __init__(self, repo: Path, snapshots: dict, reads=None, findings=None, coverage=None):
        self.repo, self.snapshots = repo, snapshots
        self.reads = list(reads or [])
        self.findings = list(findings or [])
        self.coverage = dict(coverage or {
            "clues": {"seed": {"started_step": 0, "covered": {}}},
        })
        self.coverage["clues"] = {
            clue: {"started_step": record["started_step"],
                   "covered": dict(record.get("covered", {}))}
            for clue, record in self.coverage.get("clues", {}).items()
        }

    def coverage_status(self):
        clues = {}
        for clue, record in self.coverage["clues"].items():
            covered = {sid: record["covered"][sid]
                       for sid in self.snapshots if sid in record["covered"]}
            clues[clue] = {
                "started_step": record["started_step"],
                "covered": covered,
                "remaining": [sid for sid in self.snapshots if sid not in covered],
            }
        return {"clues": clues,
                "incomplete": [clue for clue, record in clues.items() if record["remaining"]]}

    def apply_coverage(self, action, step, snapshots):
        clue = action.get("coverage_for")
        if clue is None:
            return None
        if not isinstance(clue, str) or clue not in self.coverage["clues"]:
            raise ValueError("coverage_for must name a recorded clue: "
                             + ", ".join(self.coverage["clues"]))
        for sid in snapshots:
            self.coverage["clues"][clue]["covered"][sid] = step
        return self.coverage_status()

    def validate_coverage(self, action):
        if "coverage_for" not in action:
            return
        clue = action["coverage_for"]
        if not isinstance(clue, str) or clue not in self.coverage["clues"]:
            raise ValueError("coverage_for must name a recorded clue: "
                             + ", ".join(self.coverage["clues"]))

    def revision(self, snapshot):
        if snapshot not in self.snapshots:
            raise ValueError("unknown snapshot; choose one of " + ", ".join(self.snapshots))
        return self.snapshots[snapshot]

    def execute(self, action: dict, step: int):
        reason = action.get("reason")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 5000:
            raise ValueError("include a concise public reason")
        kind = action.get("action")
        if kind == "finish":
            status = self.coverage_status()
            if status["incomplete"]:
                missing = "; ".join(
                    f"{clue}=>{','.join(status['clues'][clue]['remaining'])}"
                    for clue in status["incomplete"]
                )
                return {"error": "cannot finish: incomplete clue coverage: " + missing,
                        "coverage": status}
            return {"finished": True, "coverage": status}
        if kind in {"search", "read"}:
            self.validate_coverage(action)
        snapshot = action.get("snapshot")
        if kind == "search":
            path = source_path(action.get("path", ""), empty=True)
            offset = action.get("offset", 0)
            if type(offset) is not int or not 0 <= offset <= 5000:
                raise ValueError("offset must be 0..5000")
            ids = list(self.snapshots) if snapshot == "all" else [snapshot]
            output = {}
            for sid in ids:
                output[sid] = bounded_grep(self.repo, self.revision(sid), action.get("pattern"), path, offset)
            coverage = self.apply_coverage(action, step, ids)
            if coverage:
                output["coverage_update"] = coverage
            return output
        revision = self.revision(snapshot)
        path = source_path(action.get("path", ""), empty=kind == "list")
        if kind == "list":
            offset = action.get("offset", 0)
            if type(offset) is not int or not 0 <= offset <= 100000:
                raise ValueError("offset must be 0..100000")
            args = ["ls-tree", "-r", "--name-only", revision]
            if path:
                args += ["--", path]
            paths = [p for p in git(self.repo, *args).splitlines() if Path(p).suffix in {".c", ".h"}]
            return {"paths": paths[offset:offset + 150], "total": len(paths),
                    "next_offset": offset + min(150, max(0, len(paths) - offset))}
        if Path(path).suffix not in {".c", ".h"}:
            raise ValueError("read/report supports C source and headers only")
        start, end = action.get("start"), action.get("end")
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            raise ValueError("start/end must be positive line numbers")
        if end - start + 1 > (40 if kind == "report" else 180):
            raise ValueError("range too wide: read <=180 lines, report <=40 lines")
        if kind == "report":
            evidence = [r for r in self.reads if r["snapshot"] == snapshot and r["path"] == path
                        and r["start"] <= start <= end <= r["end"]]
            if not evidence:
                raise ValueError("read the complete reported range before reporting")
            quote = action.get("quote")
            if not isinstance(quote, str) or len(quote.strip()) < 8:
                raise ValueError("quote must contain at least 8 non-whitespace characters")
            read = evidence[-1]
            selected = "\n".join(read["source"].splitlines()[start - read["start"]:end - read["start"] + 1])
            if quote not in selected:
                raise ValueError("quote does not occur literally in cited source lines")
            if action.get("confidence") not in {"high", "medium", "low"}:
                raise ValueError("invalid confidence")
            for f in self.findings:
                if (f["snapshot"], f["path"], f["start"], f["end"]) == (snapshot, path, start, end):
                    return {"error": f"finding already recorded as {f['id']}; do not submit it again. "
                                     "Search or read a different candidate, or finish if the "
                                     "investigation is complete."}
            finding = {**action, "id": f"finding-{len(self.findings) + 1:04d}",
                       "step": step, "read_step": read["step"]}
            self.findings.append(finding)
            self.coverage["clues"][finding["id"]] = {
                "started_step": step, "covered": {snapshot: step},
            }
            return {"recorded": finding["id"], "status": "unconfirmed_hypothesis",
                    "coverage_update": self.coverage_status()}
        if kind != "read":
            raise ValueError("unknown action; use list/search/read/report/finish")
        size = int(git(self.repo, "cat-file", "-s", f"{revision}:{path}").strip())
        if size > 10_000_000:
            raise ValueError("source file too large")
        lines = git(self.repo, "show", f"{revision}:{path}").splitlines()
        if start > len(lines):
            raise ValueError(f"start exceeds file length ({len(lines)} lines)")
        stop = min(end, len(lines))
        while stop > start and len("\n".join(lines[start - 1:stop])) > 24000:
            stop -= 1
        source = "\n".join(lines[start - 1:stop])
        if len(source) > 24000:
            raise ValueError("source line too long")
        record = {"snapshot": snapshot, "path": path, "start": start, "end": stop,
                  "source": source, "step": step}
        self.reads.append(record)
        result = {"snapshot": snapshot, "path": path, "start": start, "end": stop,
                  "total_lines": len(lines), "truncated": stop < end,
                  "source": "\n".join(f"{start + i}: {line}" for i, line in enumerate(source.splitlines()))}
        coverage = self.apply_coverage(action, step, [snapshot])
        if coverage:
            result["coverage_update"] = coverage
        return result
