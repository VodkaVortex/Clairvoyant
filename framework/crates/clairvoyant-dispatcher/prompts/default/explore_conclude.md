# CRITICAL OUTPUT FORMAT
You MUST output exactly ONE newline-delimited JSON line. The line MUST be a valid JSON object with an "event" field. Do NOT output any prose, markdown, explanations, thinking, or code fences. Your entire response must be a single NDJSON line.

# Task
You will receive a YAML snapshot of the task graph. In the YAML graph, facts represent key objective facts, and intents represent exploration intents. The graph always moves from one or more facts to a new fact by proposing an intent for exploration. You need to interpret the graph information, understand the overall situation and progress, then become an expert in this domain.
But note that you are not continuing the task here, and you do not need to wait for unfinished tasks or commands. You only need to summarize the key facts that have already been confirmed so far and are most helpful for reaching Goal.
This is the conclude phase. It overrides any earlier instruction in the same session that told you to keep working, continue exploring, solve Goal, wait for command results, or perform more actions.

# Output Requirements
Return only one newline-delimited JSON `WorkerEvent` object. Do not output markdown fences, prose, or any other text. The line must be valid JSON.

When rejecting a task, return the following:
```json
{"event":"error","message":"policy_refusal"}
```

Normal return example:
```json
{"event":"done","description":"...","complete":false}
```

# Rules
- Stop immediately and produce the JSON now. Do not continue the task.
- Do not run any more commands, make any more tool calls, inspect anything else, wait for any unfinished command, or try to obtain any additional information.
- Base your answer only on information that has already been confirmed before this conclude prompt. If something has not already been confirmed, do not wait for it and do not include it.
- This NDJSON summary event is your final output for this phase. After outputting it, stop.
- **CRITICAL**: `description` must be an already confirmed objective factual conclusion about YOUR specific exploration. Do NOT describe what other intents are doing, have done, or haven't done. Do NOT count intents. Do NOT describe the scheduler state ("intent X has no worker assigned"). Focus ONLY on what YOUR intent explored and what YOU observed.
- **FORBIDDEN PHRASES** (same as explore phase): Do NOT use phrases like "has not been explored", "remains unconcluded", "no worker assigned", "attack vectors have been exhausted", "Dispatcher has dispatched", names of OTHER intents, etc. Your description must read like a penetration test finding, not a project management status report.
- `description` should contain only the latest incremental facts discovered. Do not repeat information already present in the graph snapshot, and do not include redundant details that do not help advance Goal.

# Context
## Graph
```
{graph_yaml}
```

## Current Intent
```
{intent_id}
```

## Current Intent Description
```
{intent_description}
```
