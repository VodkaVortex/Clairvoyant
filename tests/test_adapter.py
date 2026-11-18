from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("clairvoyant_variant_run", HERE / "run.py")
assert SPEC and SPEC.loader
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class AdapterTests(unittest.TestCase):
    def test_context_only_drops_generic_prompt(self):
        worker_spec = importlib.util.spec_from_file_location("clairvoyant_worker", HERE / "worker.py")
        assert worker_spec and worker_spec.loader
        worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(worker)
        prompt = "network instructions\n## Context\n### Graph\nconfirmed facts"
        self.assertNotIn("network instructions", worker.context_only(prompt))
        self.assertIn("confirmed facts", worker.context_only(prompt))

    def test_literal_quote_validation_and_hidden_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            source = output / "public/snapshots/s01/net/demo.c"
            source.parent.mkdir(parents=True)
            source.write_text("int demo(void) {\n\treturn unsafe_value;\n}\n")
            artifacts = output / "agent-state/findings"
            artifacts.mkdir(parents=True)
            (artifacts / "i001.json").write_text(json.dumps({
                "version": 1,
                "intent_id": "i001",
                "branch": "data flow",
                "snapshots_checked": ["s01"],
                "findings": [{
                    "snapshot": "s01", "path": "net/demo.c", "start": 2, "end": 2,
                    "quote": "return unsafe_value", "confidence": "high", "reason": "evidence",
                }],
            }))
            findings, audits = RUN.collect_findings(output, {"snapshots": {"s01": "hidden"}})
            self.assertEqual(len(findings), 1)
            self.assertEqual(audits[0]["accepted"], 1)
            payload = json.loads((artifacts / "i001.json").read_text())
            payload["findings"][0]["quote"] = "return \n\t unsafe_value"
            (artifacts / "i001.json").write_text(json.dumps(payload))
            findings, audits = RUN.collect_findings(output, {"snapshots": {"s01": "hidden"}})
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["quote"], "\treturn unsafe_value;")
            self.assertEqual(audits[0]["normalized"][0]["method"],
                             "whitespace_normalized_source_quote")
            payload["findings"][0]["quote"] = "invented quote"
            (artifacts / "i001.json").write_text(json.dumps(payload))
            findings, audits = RUN.collect_findings(output, {"snapshots": {"s01": "hidden"}})
            self.assertEqual(findings, [])
            self.assertIn("source text not present", audits[0]["rejected"][0]["error"])

    def test_oversized_range_is_normalized_around_literal_quote(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            source = output / "public/snapshots/s01/net/demo.c"
            source.parent.mkdir(parents=True)
            lines = [f"int value_{index} = {index};" for index in range(1, 161)]
            source.write_text("\n".join(lines) + "\n")
            artifacts = output / "agent-state/findings"
            artifacts.mkdir(parents=True)
            quote = "\n".join(lines[1:4])
            (artifacts / "i001.json").write_text(json.dumps({
                "version": 1,
                "intent_id": "i001",
                "branch": "data flow",
                "snapshots_checked": ["s01"],
                "findings": [{
                    "snapshot": "s01", "path": "net/demo.c", "start": 1, "end": 153,
                    "quote": quote, "confidence": "high", "reason": "evidence",
                }],
            }))

            findings, audits = RUN.collect_findings(
                output, {"snapshots": {"s01": "hidden"}}
            )

            self.assertEqual(len(findings), 1)
            self.assertEqual((findings[0]["start"], findings[0]["end"]), (1, 100))
            self.assertEqual(audits[0]["accepted"], 1)
            self.assertEqual(audits[0]["rejected"], [])
            self.assertEqual(audits[0]["normalized"], [{
                "index": 0,
                "method": "literal_quote_window",
                "original_start": 1,
                "original_end": 153,
                "start": 1,
                "end": 100,
            }])

    def test_path_escape_is_rejected(self):
        for path in ("../secret.c", "/tmp/secret.c", ".git/config", "net/demo.rs"):
            with self.assertRaises(ValueError):
                RUN.safe_source_path(path)

    def test_worker_builds_short_fact_card(self):
        worker_spec = importlib.util.spec_from_file_location("clairvoyant_worker_summary", HERE / "worker.py")
        assert worker_spec and worker_spec.loader
        worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(worker)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "i002.json"
            artifact.write_text(json.dumps({
                "version": 1,
                "intent_id": "i002",
                "branch": "data-flow",
                "execution_status": "complete",
                "snapshots_checked": ["s01"],
                "findings": [{
                    "snapshot": "s01", "path": "net/demo.c", "start": 10, "end": 12,
                    "quote": "full source", "reason": "full detailed reason",
                    "confidence": "high", "conclusion": "Unchecked length reaches a fixed index.",
                }],
                "candidates": [
                    {
                        "snapshot": "s01", "path": "net/lead.c", "line": 42,
                        "status": "unresolved", "reason": "full candidate evidence",
                        "conclusion": "Confirm whether the caller bounds the index.",
                    },
                    {
                        "snapshot": "s01", "path": "net/safe.c", "line": 7,
                        "status": "safe", "reason": "bounded",
                    },
                ],
                "coverage_gaps": ["The alternate parser was not reached by the bounded audit."],
                "limitations": ["long limitation retained only in artifact"],
            }))
            card = worker.build_fact_card(
                artifact, expected_snapshot="s01", expected_intent="i002",
                expected_branch="data-flow",
            )
            self.assertIn("intent=i002 snapshot=s01 branch=data-flow status=complete", card)
            self.assertIn("finding location=net/demo.c:10-12 confidence=high", card)
            self.assertIn("unresolved location=net/lead.c:42", card)
            self.assertIn("coverage_gap=The alternate parser", card)
            self.assertIn("artifact=findings/i002.json", card)
            self.assertNotIn("full source", card)
            self.assertNotIn("full detailed reason", card)
            self.assertNotIn("net/safe.c", card)
            self.assertNotIn("limitation retained", card)

    def test_done_mcp_runs_inside_landlock_and_writes_fact_card(self):
        landlock = HERE / ".bin/landlock-run"
        self.assertTrue(landlock.is_file(), "landlock-run must be built for this test")
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            artifact = state / "findings/i002.json"
            terminal = state / "terminal-events/i002.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(json.dumps({
                "version": 1,
                "intent_id": "i002",
                "branch": "data-flow",
                "execution_status": "complete",
                "snapshots_checked": ["s01"],
                "findings": [
                    {
                        "snapshot": "s01", "path": "net/demo.c",
                        "start": 10, "end": 12, "quote": "full source",
                        "reason": "full detailed reason", "confidence": "high",
                        "conclusion": "Unchecked length reaches a fixed index.",
                    },
                    {
                        "snapshot": "s01", "path": "net/oversized.c",
                        "start": 20, "end": 21, "quote": "other source",
                        "reason": "other detailed reason", "confidence": "medium",
                        "conclusion": "x" * 301,
                    },
                ],
                "candidates": [{
                    "snapshot": "s01", "path": "net/lead.c", "line": 42,
                    "status": "unresolved", "reason": "full candidate evidence",
                    "conclusion": "Confirm whether the caller bounds the index.",
                }],
                "coverage_gaps": ["The alternate parser was not reached."],
                "limitations": ["long limitation retained only in artifact"],
            }))
            requests = "\n".join(json.dumps(value) for value in [
                {
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {
                        "name": "done",
                        "arguments": {
                            "description": "MODEL_DESCRIPTION_SHOULD_NOT_BE_STORED"
                        },
                    },
                },
            ]) + "\n"
            environment = os.environ.copy()
            environment.update({
                "VARIANT_ARTIFACT_PATH": str(artifact),
                "VARIANT_DONE_PATH": str(terminal),
                "VARIANT_EXPECTED_SNAPSHOT": "s01",
                "VARIANT_EXPECTED_BRANCH": "data-flow",
                "CAIRN_INTENT_ID": "i002",
            })
            completed = subprocess.run(
                [
                    str(landlock),
                    "--ro", "/usr", "--ro", "/etc", "--ro", "/dev",
                    "--rw", "/dev/null", "--ro", "/proc/self",
                    "--ro", str(HERE / "done_tool.py"),
                    "--rw", str(state), "--",
                    "/usr/bin/python3", str(HERE / "done_tool.py"),
                ],
                input=requests,
                text=True,
                capture_output=True,
                timeout=10,
                env=environment,
                cwd=HERE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            responses = [json.loads(line) for line in completed.stdout.splitlines()]
            self.assertEqual([response["id"] for response in responses], [1, 2, 3])
            self.assertEqual(responses[1]["result"]["tools"][0]["name"], "done")
            self.assertFalse(responses[2]["result"]["isError"])

            card = json.loads(terminal.read_text())["description"]
            self.assertIn("intent=i002 snapshot=s01 branch=data-flow status=complete", card)
            self.assertIn("conclusion=Unchecked length reaches a fixed index.", card)
            self.assertIn("unresolved location=net/lead.c:42", card)
            self.assertIn("coverage_gap=The alternate parser was not reached.", card)
            self.assertIn("artifact=findings/i002.json", card)
            self.assertNotIn("net/oversized.c", card)
            self.assertNotIn("MODEL_DESCRIPTION_SHOULD_NOT_BE_STORED", card)
            self.assertNotIn("full source", card)
            self.assertNotIn("full detailed reason", card)
            self.assertNotIn("limitation retained", card)

    def test_explore_context_selects_same_snapshot_same_branch_and_triggers(self):
        worker_spec = importlib.util.spec_from_file_location(
            "clairvoyant_worker_context", HERE / "worker.py"
        )
        assert worker_spec and worker_spec.loader
        worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(worker)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            db = sqlite3.connect(state / "clairvoyant.db")
            db.executescript("""
                CREATE TABLE facts (id TEXT, project_id TEXT, description TEXT);
                CREATE TABLE intents (
                    id TEXT, project_id TEXT, target_fact TEXT,
                    description TEXT, creator TEXT
                );
                CREATE TABLE intent_sources (
                    intent_id TEXT, project_id TEXT, fact_id TEXT, ordinal INTEGER
                );
            """)
            cards = {
                "f001": "mechanism summary",
                "f002": "intent=i002 snapshot=s01 branch=branch-a status=complete\nartifact=findings/i002.json",
                "f003": "intent=i003 snapshot=s02 branch=branch-b status=complete\nartifact=findings/i003.json",
                "f004": "intent=i004 snapshot=s03 branch=branch-a status=complete\nartifact=findings/i004.json",
                "f005": "intent=i005 snapshot=s04 branch=branch-c status=complete\nartifact=findings/i005.json",
            }
            db.executemany(
                "INSERT INTO facts VALUES (?, 'proj_001', ?)", cards.items()
            )
            db.executemany(
                "INSERT INTO intents VALUES (?, 'proj_001', ?, '', ?)",
                [
                    ("i001", "f001", "dispatcher.bootstrap"),
                    ("i002", "f002", "linux-variant-reason"),
                    ("i003", "f003", "linux-variant-reason"),
                    ("i004", "f004", "linux-variant-reason"),
                    ("i005", "f005", "linux-variant-reason"),
                    ("i010", None, "linux-variant-reason"),
                ],
            )
            db.execute(
                "INSERT INTO intent_sources VALUES ('i010', 'proj_001', 'f005', 0)"
            )
            db.commit()
            db.close()

            mechanism, selected = worker.relevant_fact_context(
                state, "proj_001", "i010", "s01", "branch-a"
            )
            self.assertEqual(mechanism, "mechanism summary")
            selected_ids = [fact_id for fact_id, _ in selected]
            self.assertEqual(selected_ids, ["f002", "f004", "f005"])

    def test_explore_intent_has_exactly_one_snapshot(self):
        worker_spec = importlib.util.spec_from_file_location("clairvoyant_worker_intent", HERE / "worker.py")
        assert worker_spec and worker_spec.loader
        worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(worker)
        prompt = (
            "## Context\n### Current Intent Description\n```\n"
            "SNAPSHOT=s03; BRANCH=ring-state; search only snapshots/s03\n```\n"
        )
        self.assertEqual(worker.assigned_snapshot(prompt), "s03")
        self.assertEqual(worker.assigned_branch(prompt), "ring-state")
        with self.assertRaises(ValueError):
            worker.assigned_snapshot(prompt.replace("s03", "s03 and SNAPSHOT=s04", 1))

    def test_stream_result_extracts_final_text(self):
        worker_spec = importlib.util.spec_from_file_location("clairvoyant_worker_stream", HERE / "worker.py")
        assert worker_spec and worker_spec.loader
        worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(worker)
        raw = "\n".join([
            json.dumps({"type": "system", "subtype": "init"}),
            json.dumps({"type": "result", "result": '{"event":"done","description":"ok"}'}),
        ])
        self.assertIn('"event":"done"', worker.extract_stream_result(raw))

    def test_stream_session_id_uses_latest_envelope(self):
        worker_spec = importlib.util.spec_from_file_location(
            "clairvoyant_worker_session", HERE / "worker.py"
        )
        assert worker_spec and worker_spec.loader
        worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(worker)
        raw = "\n".join([
            json.dumps({"type": "system", "session_id": "session-one"}),
            "not-json",
            json.dumps({"type": "assistant", "session_id": "session-two"}),
        ])
        self.assertEqual(worker.extract_session_id(raw), "session-two")


if __name__ == "__main__":
    unittest.main()

