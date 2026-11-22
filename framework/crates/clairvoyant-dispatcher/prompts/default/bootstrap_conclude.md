# Task
This is the CONCLUDE phase. It overrides any earlier instruction that told you to keep working, continue exploring, or perform more actions. You are NOT continuing the task.

You only need to summarize the key facts that have ALREADY been confirmed so far that are most helpful for reaching Goal. Do NOT run new tools, do NOT wait for results, do NOT continue exploring.

## Output Requirements
Stop immediately and produce the JSON now. Return only one newline-delimited JSON `WorkerEvent` object:
```json
{"event":"done","description":"summary of confirmed findings","complete":false}
```

## Rules
- Do NOT run any more commands or make any more tool calls.
- Base your answer ONLY on information already confirmed before this conclude prompt.
- **FORBIDDEN phrases**: Do NOT mention intent state, scheduler state, whether intents have workers assigned, or count how many intents succeeded/failed.
- Your `description` must be concrete: list what was actually confirmed (versions, ports, access gained, files found), not what was NOT done.
- Do NOT set `complete:true` in this phase.

## Context
### Origin
```
{origin}
```

### Goal
```
{goal}
```

### Hints
```
{hints}
```
