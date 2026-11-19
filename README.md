# Clairvoyant Linux variant search

This adapter keeps the frozen benchmark and Clairvoyant core unchanged. It uses
Clairvoyant for durable `Project → Intent → Fact` scheduling and Claude Code for
each worker's tool loop, served by GLM-5.3.

## Security/evaluation boundary

- The model receives the public seed and opaque source trees only.
- Historical revisions, hidden targets, and the evaluation manifest stay under
  `private/`, outside the Landlock allow-list.
- Snapshot workspaces contain C/header files but no `.git` directory.
- Bootstrap has `Read`, `Grep`, `Glob`, and `Bash`; explore additionally has
  `Write`. Bash can run local compilation, tests, and static analysis. Source
  snapshots remain read-only and generated files go under each worker's
  private temporary directory. Edit, WebFetch, and NotebookEdit are disabled.
- The original frozen evaluator runs after Clairvoyant exits. Model-reported
  completion never counts as a hit.

## Preflight

```bash
cd /mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search
python3 run.py doctor
```

After exporting the key, verify the Claude Code → GLM-5.3 Messages transport
with one small, tool-free request:

```bash
export GLM_API_KEY='...'
python3 run.py api-smoke --model GLM-5.3
```

## Prepare one cluster without API calls

This materializes one C/header tree for each hidden peer snapshot. The initial
TOCTOU cluster has four snapshots and needs several GiB of disk.

```bash
python3 run.py prepare \
  --seed 22ba97ea9cc1 \
  --output runs/seed22_clairvoyant
```

## Run/resume one cluster

Claude Code speaks the Anthropic Messages protocol. The configured gateway root
is `https://llm.shtech.org`, which maps to `/v1/messages`; change `--base-url`
if the deployment uses a different Anthropic-compatible prefix.

```bash
export GLM_API_KEY='...'
python3 run.py run \
  --seed 22ba97ea9cc1 \
  --output runs/seed22_clairvoyant \
  --model GLM-5.3 \
  --effort low \
  --workers 16 \
  --max-intents 16 \
  --worker-max-turns 100 \
  --timeout 7200
```

Re-running the same command resumes the Clairvoyant database and existing
artifacts. Re-evaluate without model calls using:

```bash
python3 run.py evaluate --output runs/seed22_clairvoyant
```

Important outputs:

- `agent-state/clairvoyant.db`: durable fact graph;
- `agent-state/timeline.txt`: intent/fact audit trail;
- `agent-state/worker-logs/`: raw Claude Code stdout/stderr;
- `agent-state/checkpoints/`: incremental per-intent recovery records;
- `agent-state/findings/`: per-intent structured artifacts;
- `findings.json`, `evaluation.json`, `evaluation.csv`: frozen benchmark result;
- `artifact_validation.json`: rejected or accepted source citations.

