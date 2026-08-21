# LLM Eval Harness (PoC)

Measures the **decision quality** of the LLM stages against a hand-labelled golden set —
the part of the pipeline that governs our true-positive / false-positive rate but that
ordinary unit tests cannot cover (LLM output is non-deterministic and depends on prompt
quality, not fixed logic).

This is **opt-in**: it calls the real Bedrock model, so it needs AWS credentials and costs
tokens. It is NOT collected by the default `uv run pytest` run.

## What it covers

- **planner** (`coordinator._plan`) — given a request/response, does it select the right
  agents? Scored on inclusion (must-have agents present) and exclusion (must-not agents
  absent).
- **red_team** (`red_team.validate`) — given a finding, does it confirm real vulns and
  reject structural false positives? Scored on the `confirmed` boolean.

Injection-resistance cases live here too: a target response that tries to hijack the
decision must NOT change the verdict (validates the `prompt_safety` XML defense end-to-end).
These are marked `injection_probe: true` and scored separately as an
`injection-resistance` percentage. The battery covers multiple vectors an analysed
website could use — forged `</target_response>` fence-escape, non-English overrides
(PT/ES), fake `Assistant:` turns, and injected `emit_result` verdict blocks — against both
force-confirm (talk a non-vuln up) and force-reject (talk a real vuln down). A robust run
scores 100% injection-resistance while still confirming/rejecting on the real evidence.

> Structural counterpart: `tests/unit/test_prompt_safety.py` and
> `tests/unit/test_prompt_injection_pipeline.py` prove the fence holds deterministically
> (no LLM). This eval proves the *model* is not hijacked in practice. Run both.

## Run it

```bash
# Both suites, default temperature=0 (reproducible)
uv run python -m tests.evals.run_evals

# One suite
uv run python -m tests.evals.run_evals --suite planner
uv run python -m tests.evals.run_evals --suite red_team

# Fail the process if accuracy drops below a threshold (for future CI gating)
uv run python -m tests.evals.run_evals --min-accuracy 0.9
```

## Add a case

Append to `planner_cases.yaml` or `red_team_cases.yaml`. Each case is self-documenting;
see the existing entries for the schema. The golden label is set by a human — that is the
whole point of the harness.
