"""Tests for the branch registry flow in worker.py.

Run with:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import worker  # noqa: E402


PROJECT = "proj_001"
BRANCHES = [
    {"name": "and-presence-guard", "definition": "Find && joined negated presence guards."},
    {"name": "unchecked-tb-deref", "definition": "Find tb[] slots used without a check."},
]


def make_db(state: Path, *, facts: list[tuple[str, str, str | None]],
            intents: list[tuple[str, str, str | None, str]], hints: int = 0) -> None:
    """facts: (id, description, unused); intents: (id, description, target_fact, creator)."""
    connection = sqlite3.connect(state / "clairvoyant.db")
    connection.executescript(
        """
        CREATE TABLE facts (id TEXT, project_id TEXT, description TEXT);
        CREATE TABLE intents (id TEXT, project_id TEXT, target_fact TEXT, description TEXT,
                              creator TEXT);
        CREATE TABLE intent_sources (intent_id TEXT, project_id TEXT, fact_id TEXT);
        CREATE TABLE hints (id TEXT, project_id TEXT, content TEXT);
        """
    )
    connection.executemany(
        "INSERT INTO hints VALUES (?, ?, ?)",
        [(f"h{n:03d}", PROJECT, "hint") for n in range(1, hints + 1)],
    )
    connection.executemany(
        "INSERT INTO facts VALUES (?, ?, ?)",
        [(fact_id, PROJECT, description) for fact_id, description, _ in facts],
    )
    connection.executemany(
        "INSERT INTO intents VALUES (?, ?, ?, ?, ?)",
        [(i, PROJECT, target, desc, creator) for i, desc, target, creator in intents],
    )
    connection.commit()
    connection.close()


def write_registry(state: Path, branches: list[dict], **extra) -> None:
    worker.atomic_json(state / "branches.json", {
        "version": 1,
        "pattern": "seed pattern text",
        "branches": [dict(b, origin="bootstrap", sources=[]) for b in branches],
        **extra,
    })


BASE_FACTS = [("origin", "origin", None), ("goal", "goal", None), ("f001", "profile", None)]
BOOTSTRAP_INTENT = ("i001", "derive profile", "f001", "dispatcher.bootstrap")


def concluded_matrix(snapshots: list[str], branches: list[dict]) -> tuple[list, list]:
    facts = list(BASE_FACTS)
    intents = [BOOTSTRAP_INTENT]
    number = 2
    for branch in branches:
        for snapshot in snapshots:
            fact = f"f{number:03d}"
            facts.append((fact, f"intent=i{number:03d} snapshot={snapshot} "
                                f"branch={branch['name']} status=complete", None))
            intents.append((f"i{number:03d}",
                            worker.intent_description(snapshot, branch["name"]),
                            fact, "linux-variant-reason"))
            number += 1
    return facts, intents


class UnitTests(unittest.TestCase):
    def test_bootstrap_profile_parses_and_validates(self):
        pattern, branches = worker.parse_bootstrap_profile(
            {"event": "done", "pattern": " p ", "branches": BRANCHES})
        self.assertEqual(pattern, "p")
        self.assertEqual([b["name"] for b in branches], ["and-presence-guard", "unchecked-tb-deref"])
        self.assertTrue(all(b["origin"] == "bootstrap" for b in branches))

    def test_bootstrap_profile_rejects_bad_input(self):
        bad = [
            {"pattern": "", "branches": BRANCHES},
            {"pattern": "p", "branches": []},
            {"pattern": "p", "branches": [BRANCHES[0], BRANCHES[0]]},
            {"pattern": "p", "branches": [{"name": "Bad Name", "definition": "x"}]},
            {"pattern": "p", "branches": [{"name": "ok-name", "definition": "  "}]},
            {"pattern": "p", "branches": [{"name": "has;semicolon", "definition": "x"}]},
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                worker.parse_bootstrap_profile(value)

    def test_register_reason_branches_rejects_duplicates_and_filters_sources(self):
        registry = {"version": 1, "pattern": "p",
                    "branches": [dict(b, origin="bootstrap", sources=[]) for b in BRANCHES]}
        accepted, rejected = worker.register_reason_branches([
            {"event": "branch", "name": "and-presence-guard", "definition": "dup"},
            {"event": "branch", "name": "helper-param-null-deref", "definition": "new",
             "sources": ["f002", "f999", "goal", "f002"]},
        ], registry, {"origin", "goal", "f001", "f002"})
        self.assertEqual([b["name"] for b in accepted], ["helper-param-null-deref"])
        self.assertEqual(accepted[0]["sources"], ["f002"])
        self.assertEqual(accepted[0]["origin"], "reason")
        self.assertEqual(len(rejected), 1)
        self.assertIn("duplicate", rejected[0])
        self.assertEqual(len(registry["branches"]), 3)

    def test_register_reason_branches_caps_round(self):
        registry = {"version": 1, "pattern": "p", "branches": []}
        values = [{"event": "branch", "name": f"branch-{n}", "definition": "d"} for n in range(6)]
        accepted, rejected = worker.register_reason_branches(values, registry, set())
        self.assertEqual(len(accepted), worker.MAX_NEW_BRANCHES_PER_ROUND)
        self.assertEqual(len(rejected), 6 - worker.MAX_NEW_BRANCHES_PER_ROUND)

    def test_missing_assignments_skip_existing_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            make_db(state, facts=BASE_FACTS, intents=[
                BOOTSTRAP_INTENT,
                ("i002", worker.intent_description("s01", "and-presence-guard"), None,
                 "linux-variant-reason"),
            ])
            project = worker.read_project_state(state, PROJECT)
            self.assertEqual(project["bootstrap_fact"], "f001")
            self.assertEqual(project["open_count"], 1)
            registry = {"version": 1, "pattern": "p",
                        "branches": [dict(b, origin="bootstrap", sources=[]) for b in BRANCHES]}
            events = worker.missing_assignment_events(registry, ["s01", "s02"], project)
            descriptions = [e["description"] for e in events]
            self.assertEqual(len(events), 3)
            self.assertNotIn(worker.intent_description("s01", "and-presence-guard"), descriptions)
            self.assertTrue(all(e["sources"] == ["f001"] for e in events))
            for description in descriptions:
                self.assertTrue(description.startswith("SNAPSHOT=s0"))


FAKE_LANDLOCK = """\
#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
os.execvp(args[args.index("--") + 1], args[args.index("--") + 1:])
"""

FAKE_CLAUDE = """\
#!/usr/bin/env python3
import json, os, sys
prompt = sys.stdin.read()
marker = os.environ.get("FAKE_CLAUDE_MARKER")
if marker:
    with open(marker, "a") as handle:
        handle.write("called\\n")
log = os.environ.get("FAKE_CLAUDE_STDIN_LOG")
if log:
    with open(log, "w") as handle:
        handle.write(prompt)
print(json.dumps({"type": "system", "subtype": "init", "session_id": "fake"}))
print(json.dumps({"type": "result", "result": os.environ.get("FAKE_CLAUDE_OUTPUT", "")}))
"""


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.public = root / "public"
        self.state = root / "state"
        self.public.mkdir()
        self.state.mkdir()
        (self.public / "snapshot_inventory.json").write_text(
            json.dumps({"snapshots": ["s01", "s02"]}))
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, body in (("landlock", FAKE_LANDLOCK), ("claude", FAKE_CLAUDE)):
            path = self.bin / name
            path.write_text(textwrap.dedent(body))
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        self.marker = root / "claude-called"
        self.stdin_log = root / "claude-stdin"

    def tearDown(self):
        self.tmp.cleanup()

    def run_worker(self, role: str, prompt: str, *, output: str = "",
                   intent: str = "nointent", fact_batch: str = "1") -> list[dict]:
        env = os.environ.copy()
        env.update({
            "VARIANT_PUBLIC_ROOT": str(self.public),
            "VARIANT_STATE_ROOT": str(self.state),
            "CLAUDE_BIN": str(self.bin / "claude"),
            "LANDLOCK_BIN": str(self.bin / "landlock"),
            "CAIRN_PROJECT_ID": PROJECT,
            "CAIRN_INTENT_ID": intent,
            "VARIANT_WORKER_TIMEOUT": "30",
            "VARIANT_EXPLORE_TIMEOUT": "20",
            "FAKE_CLAUDE_OUTPUT": output,
            "FAKE_CLAUDE_MARKER": str(self.marker),
            "FAKE_CLAUDE_STDIN_LOG": str(self.stdin_log),
            "VARIANT_REASON_FACT_BATCH": fact_batch,
        })
        env.pop("VARIANT_API_SMOKE", None)
        result = subprocess.run(
            [sys.executable, str(ROOT / "worker.py"), "--role", role],
            input=prompt, text=True, capture_output=True, env=env, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    def claude_called(self) -> bool:
        return self.marker.exists()

    def test_bootstrap_registers_branches_and_renders_fact(self):
        output = json.dumps({"event": "done", "pattern": "the pattern", "branches": BRANCHES})
        events = self.run_worker("bootstrap", "## Context\ngraph", output=output, intent="i001")
        self.assertEqual([e["event"] for e in events], ["done"])
        self.assertIn("Registered branches:", events[0]["description"])
        self.assertIn("- and-presence-guard: Find && joined", events[0]["description"])
        registry = json.loads((self.state / "branches.json").read_text())
        self.assertEqual(registry["pattern"], "the pattern")
        self.assertEqual([b["name"] for b in registry["branches"]],
                         ["and-presence-guard", "unchecked-tb-deref"])

    def test_bootstrap_rejects_unstructured_profile(self):
        output = json.dumps({"event": "done", "description": "BRANCHES: branch1=x"})
        events = self.run_worker("bootstrap", "## Context\ngraph", output=output, intent="i001")
        self.assertEqual(events[0]["event"], "error")
        self.assertFalse((self.state / "branches.json").exists())

    def test_reason_schedules_matrix_without_model(self):
        write_registry(self.state, BRANCHES)
        make_db(self.state, facts=BASE_FACTS, intents=[BOOTSTRAP_INTENT])
        events = self.run_worker("reason", "## Context\ngraph")
        self.assertFalse(self.claude_called())
        self.assertEqual(len(events), 4)
        self.assertEqual({e["description"] for e in events}, {
            worker.intent_description(s, b["name"]) for s in ("s01", "s02") for b in BRANCHES
        })

    def open_matrix(self, hints: int = 0, **registry_extra) -> None:
        write_registry(self.state, BRANCHES, **registry_extra)
        facts, intents = concluded_matrix(["s01", "s02"], BRANCHES)
        # Reopen one pair: its exploration is still running (3 explore Facts exist).
        intents[-1] = (intents[-1][0], intents[-1][1], None, intents[-1][3])
        make_db(self.state, facts=facts[:-1], intents=intents, hints=hints)

    def test_fact_batch_waits_below_threshold_without_model(self):
        self.open_matrix(reason_fact_count=2)
        events = self.run_worker("reason", "## Context\ngraph", fact_batch="2")
        self.assertFalse(self.claude_called())
        self.assertEqual(events, [{"event": "message", "text":
                                   "waiting for facts: 1/2 new since last Reason call; "
                                   "1 open intents"}])

    def test_fact_batch_calls_model_at_threshold_and_records_count(self):
        self.open_matrix(reason_fact_count=1)
        output = json.dumps({"event": "message", "text": "no new branch: covered"})
        self.run_worker("reason", "## Context\ngraph", output=output, fact_batch="2")
        self.assertTrue(self.claude_called())
        registry = json.loads((self.state / "branches.json").read_text())
        self.assertEqual(registry["reason_fact_count"], 3)

    def test_new_hint_calls_model_below_fact_threshold(self):
        self.open_matrix(hints=1, reason_fact_count=3, reason_hint_count=0)
        output = json.dumps({"event": "message", "text": "no new branch: covered"})
        self.run_worker("reason", "## Context\ngraph", output=output, fact_batch="5")
        self.assertTrue(self.claude_called())

    def test_fact_batch_does_not_block_completion(self):
        write_registry(self.state, BRANCHES, reason_fact_count=4)
        facts, intents = concluded_matrix(["s01", "s02"], BRANCHES)
        make_db(self.state, facts=facts, intents=intents)
        output = json.dumps({"event": "message", "text": "no new branch: covered"})
        events = self.run_worker("reason", "## Context\ngraph", output=output, fact_batch="10")
        self.assertTrue(self.claude_called())
        self.assertEqual([e["event"] for e in events], ["complete"])

    def test_reason_calls_model_while_intents_are_open(self):
        self.open_matrix()
        output = json.dumps({"event": "message", "text": "no new branch: covered"})
        events = self.run_worker("reason", "## Context\ngraph", output=output)
        self.assertTrue(self.claude_called())
        self.assertIn("unchecked-tb-deref: s01=f004, s02=running", self.stdin_log.read_text())
        # No new branch while Intents are open must not complete the project.
        self.assertEqual(events, [{"event": "message",
                                   "text": "no new branch; 1 open intents still running"}])

    def test_reason_schedules_new_branch_while_intents_are_open(self):
        self.open_matrix()
        output = json.dumps({"event": "branch", "name": "helper-param-null-deref",
                             "definition": "Cross-function form.", "sources": ["f002"]})
        events = self.run_worker("reason", "## Context\ngraph", output=output)
        self.assertEqual([e["description"] for e in events], [
            worker.intent_description("s01", "helper-param-null-deref"),
            worker.intent_description("s02", "helper-param-null-deref"),
        ])

    def test_reason_registers_new_branch_and_schedules_it(self):
        write_registry(self.state, BRANCHES)
        facts, intents = concluded_matrix(["s01", "s02"], BRANCHES)
        make_db(self.state, facts=facts, intents=intents)
        output = json.dumps({"event": "branch", "name": "helper-param-null-deref",
                             "definition": "Cross-function form.", "sources": ["f003"]})
        graph = (
            "# Task\ntemplate rules\n\n## Context\n### Graph\n```\n"
            "project:\n  id: proj_001\n  status: active\n"
            "facts:\n- id: origin\n  description: seed title\n"
            "- id: goal\n  description: goal text\n"
            "- id: f001\n  description: |-\n    bootstrap profile\n"
            "- id: f002\n  description: |-\n    worker conclusion two\n"
            "intents:\n- id: i002\n  description: SNAPSHOT=s01; BRANCH=x; text\n"
            "hints:\n- id: h001\n  content: use only the public workspace\n"
            "```\n\n### Valid facts\n```\n[\"origin\", \"f001\", \"f002\"]\n```\n\n"
            "### Open Intents\n```\n[]\n```\n"
        )
        events = self.run_worker("reason", graph, output=output)
        self.assertTrue(self.claude_called())
        prompt = self.stdin_log.read_text()
        # Kept from the original context.
        self.assertTrue(prompt.startswith("Clairvoyant context follows."))
        self.assertIn("- id: origin\n  description: seed title", prompt)
        self.assertIn("- id: f002\n  description: |-\n    worker conclusion two", prompt)
        self.assertIn("hints:\n- id: h001", prompt)
        self.assertIn('### Valid facts\n```\n["origin", "f001", "f002"]\n```', prompt)
        self.assertIn("### Open Intents\n```\n[]\n```", prompt)
        # Removed: header, project, goal, Bootstrap Fact, intents, template rules.
        for removed in ("Public workspace:", "Current worker role", "project:", "goal text",
                        "bootstrap profile", "intents:", "SNAPSHOT=s01; BRANCH=x", "template rules"):
            self.assertNotIn(removed, prompt)
        self.assertLess(prompt.index("### Open Intents"), prompt.index("## Branch registry"))
        self.assertIn("### Registered branches", prompt)
        self.assertIn("### and-presence-guard (origin: bootstrap; sources: none)", prompt)
        self.assertIn("and-presence-guard: s01=f002, s02=f003", prompt)
        self.assertEqual([e["event"] for e in events], ["intent", "intent"])
        self.assertEqual(events[0]["sources"], ["f001", "f003"])
        self.assertEqual(events[0]["description"],
                         worker.intent_description("s01", "helper-param-null-deref"))
        registry = json.loads((self.state / "branches.json").read_text())
        self.assertEqual(registry["branches"][-1]["definition"], "Cross-function form.")
        self.assertEqual(registry["branches"][-1]["origin"], "reason")

    def test_reason_completes_when_no_new_branch(self):
        write_registry(self.state, BRANCHES)
        facts, intents = concluded_matrix(["s01", "s02"], BRANCHES)
        make_db(self.state, facts=facts, intents=intents)
        output = json.dumps({"event": "message", "text": "no new branch: covered"})
        events = self.run_worker("reason", "## Context\ngraph", output=output)
        self.assertEqual([e["event"] for e in events], ["complete"])
        self.assertEqual(events[0]["sources"], ["f001", "f002", "f003", "f004", "f005"])

    def test_reason_does_not_complete_on_rejected_branch(self):
        write_registry(self.state, BRANCHES)
        facts, intents = concluded_matrix(["s01", "s02"], BRANCHES)
        make_db(self.state, facts=facts, intents=intents)
        output = json.dumps({"event": "branch", "name": "and-presence-guard",
                             "definition": "reworded"})
        events = self.run_worker("reason", "## Context\ngraph", output=output)
        self.assertEqual([e["event"] for e in events], ["message"])
        self.assertIn("duplicate branch name", events[0]["text"])

    def test_reason_without_registry_is_a_noop(self):
        events = self.run_worker("reason", "## Context\ngraph")
        self.assertFalse(self.claude_called())
        self.assertEqual(events[0]["event"], "message")

    def test_explore_prompt_uses_registry_definition_verbatim(self):
        write_registry(self.state, BRANCHES)
        make_db(self.state, facts=BASE_FACTS, intents=[
            BOOTSTRAP_INTENT,
            ("i002", worker.intent_description("s01", "and-presence-guard"), None,
             "linux-variant-reason"),
        ])
        dispatcher_prompt = (
            "## Context\n### Graph\n```\nx\n```\n\n### Current Intent\n```\ni002\n```\n\n"
            "### Current Intent Description\n```\n"
            "SNAPSHOT=s01; BRANCH=and-presence-guard; free text that must not appear\n```\n"
        )
        self.run_worker("explore", dispatcher_prompt, intent="i002")
        prompt = self.stdin_log.read_text()
        self.assertIn("## Pattern\nseed pattern text", prompt)
        self.assertIn("## Branch\nName: and-presence-guard\n"
                      "Find && joined negated presence guards.", prompt)
        self.assertIn("## Assignment\nIntent id: i002\n"
                      + worker.intent_description("s01", "and-presence-guard"), prompt)
        self.assertNotIn("free text that must not appear", prompt)


if __name__ == "__main__":
    unittest.main()
