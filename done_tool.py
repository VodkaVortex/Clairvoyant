#!/usr/bin/env python3
"""Expose Clairvoyant's terminal Done event as a Claude Code MCP tool."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


ALLOWED_CONFIDENCE = {"high", "medium", "low"}
MAX_SHORT_TEXT_CHARS = 300
MAX_FACT_CARD_BYTES = 8192
MAX_LIMITATION_CHARS = 600


def response(request_id: object, *, result: object | None = None,
             error: dict | None = None) -> None:
    payload: dict[str, object] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), flush=True)


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def validate_artifact(path: Path, expected_intent: str,
                      expected_snapshot: str, expected_branch: str) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("final artifact must be a version-1 JSON object")
    if payload.get("intent_id") != expected_intent:
        raise ValueError(
            f"artifact intent_id must be {expected_intent!r}; got {payload.get('intent_id')!r}"
        )
    if payload.get("branch") != expected_branch:
        raise ValueError(
            f"artifact branch must be {expected_branch!r}; got {payload.get('branch')!r}"
        )
    if payload.get("execution_status") != "complete":
        raise ValueError("artifact execution_status must be 'complete'")
    if payload.get("snapshots_checked") != [expected_snapshot]:
        raise ValueError(
            f"artifact snapshots_checked must be [{expected_snapshot!r}]"
        )
    for field in ("findings", "candidates", "coverage_gaps", "limitations"):
        if not isinstance(payload.get(field), list):
            raise ValueError(f"artifact {field} must be a list")
    return payload


def short_card_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or "\n" in text or "\r" in text or len(text) > MAX_SHORT_TEXT_CHARS:
        return None
    return text


def card_limitation_text(value: object) -> str | None:
    """One card line for a limitation: whitespace collapsed, long text shortened."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    if len(text) > MAX_LIMITATION_CHARS:
        text = text[:MAX_LIMITATION_CHARS].rstrip() + " ... (see artifact)"
    return text


def card_location(row: dict, *, finding: bool, expected_snapshot: str) -> str | None:
    if row.get("snapshot") != expected_snapshot:
        return None
    path = row.get("path")
    if not isinstance(path, str) or not path.strip() or "\n" in path or "\r" in path:
        return None
    if finding:
        start, end = row.get("start"), row.get("end")
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return None
        return f"{path.strip()}:{start}-{end}"
    line = row.get("line")
    if type(line) is not int or line < 1:
        return None
    return f"{path.strip()}:{line}"


def build_fact_card(artifact: Path, payload: dict, snapshot: str,
                    intent: str, branch: str) -> str:
    """Build a short Fact card without rejecting Done for bad short fields."""
    finding_lines: list[str] = []
    for row in payload["findings"]:
        if not isinstance(row, dict) or row.get("confidence") not in ALLOWED_CONFIDENCE:
            continue
        location = card_location(row, finding=True, expected_snapshot=snapshot)
        conclusion = short_card_text(row.get("conclusion"))
        if location is not None and conclusion is not None:
            finding_lines.append(
                f"finding location={location} confidence={row['confidence']} "
                f"conclusion={conclusion}"
            )

    unresolved_lines: list[str] = []
    for row in payload["candidates"]:
        if not isinstance(row, dict) or row.get("status") != "unresolved":
            continue
        location = card_location(row, finding=False, expected_snapshot=snapshot)
        conclusion = short_card_text(row.get("conclusion"))
        if location is not None and conclusion is not None:
            unresolved_lines.append(
                f"unresolved location={location} conclusion={conclusion}"
            )

    gap_lines = [
        f"coverage_gap={text}"
        for value in payload["coverage_gaps"]
        if (text := short_card_text(value)) is not None
    ]
    limitation_lines = [
        f"limitation={text}"
        for value in payload["limitations"]
        if (text := card_limitation_text(value)) is not None
    ]
    header = f"intent={intent} snapshot={snapshot} branch={branch} status=complete"
    artifact_line = f"artifact=findings/{artifact.name}"
    omitted_findings = 0
    omitted_limitations = 0
    omitted_followups = 0

    def render() -> str:
        lines = [header, *finding_lines]
        if omitted_findings:
            lines.append(f"omitted_findings={omitted_findings}; see artifact")
        lines.extend([*unresolved_lines, *gap_lines])
        if omitted_followups:
            lines.append(f"omitted_followups={omitted_followups}; see artifact")
        lines.extend(limitation_lines)
        if omitted_limitations:
            lines.append(f"omitted_limitations={omitted_limitations}; see artifact")
        lines.append(artifact_line)
        return "\n".join(lines)

    # Preserve complete lines only. Findings are discarded first, then
    # limitations, then coverage gaps and follow-up leads.
    card = render()
    while len(card.encode("utf-8")) > MAX_FACT_CARD_BYTES:
        if finding_lines:
            finding_lines.pop()
            omitted_findings += 1
        elif limitation_lines:
            limitation_lines.pop()
            omitted_limitations += 1
        elif gap_lines:
            gap_lines.pop()
            omitted_followups += 1
        elif unresolved_lines:
            unresolved_lines.pop()
            omitted_followups += 1
        else:
            break
        card = render()
    return card


def call_done(arguments: object) -> dict:
    if not isinstance(arguments, dict):
        raise ValueError("done arguments must be an object")
    description = str(arguments.get("description", "")).strip()
    if not description:
        raise ValueError("done.description must contain the concrete result and evidence")

    artifact = Path(os.environ["VARIANT_ARTIFACT_PATH"]).resolve()
    terminal = Path(os.environ["VARIANT_DONE_PATH"]).resolve()
    intent = os.environ["CAIRN_INTENT_ID"]
    snapshot = os.environ["VARIANT_EXPECTED_SNAPSHOT"]
    branch = os.environ["VARIANT_EXPECTED_BRANCH"]
    payload = validate_artifact(artifact, intent, snapshot, branch)
    fact_card = build_fact_card(artifact, payload, snapshot, intent, branch)
    atomic_json(terminal, {
        "event": "done",
        "description": fact_card,
        "complete": False,
    })
    return {
        "content": [{
            "type": "text",
            "text": "Clairvoyant Done accepted. The current Intent is terminating now.",
        }],
        "isError": False,
    }


def main() -> int:
    for raw in sys.stdin:
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(request, dict):
            continue
        request_id = request.get("id")
        method = request.get("method")
        if method == "initialize":
            requested = request.get("params", {}).get("protocolVersion")
            response(request_id, result={
                "protocolVersion": requested or "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "clairvoyant-done", "version": "1.0.0"},
            })
        elif method == "tools/list":
            response(request_id, result={"tools": [{
                "name": "done",
                "description": (
                    "Terminally conclude the current Clairvoyant Intent after the required "
                    "final artifact has been written. Call immediately when one credible "
                    "finding is supported, or after a bounded evidence-backed negative search. "
                    "A successful call stops this Claude Code worker."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "minLength": 1,
                            "description": (
                                "Formal result: finding locations and check/use evidence, or "
                                "bounded negative evidence and limitations."
                            ),
                        }
                    },
                    "required": ["description"],
                    "additionalProperties": False,
                },
            }]})
        elif method == "tools/call":
            params = request.get("params", {})
            if not isinstance(params, dict) or params.get("name") != "done":
                response(request_id, result={
                    "content": [{"type": "text", "text": "unknown tool"}],
                    "isError": True,
                })
                continue
            try:
                response(request_id, result=call_done(params.get("arguments", {})))
            except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
                response(request_id, result={
                    "content": [{"type": "text", "text": f"Done rejected: {exc}"}],
                    "isError": True,
                })
        elif method == "ping":
            response(request_id, result={})
        elif request_id is not None:
            response(request_id, error={"code": -32601, "message": "method not found"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
