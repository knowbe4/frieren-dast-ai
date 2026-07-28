# AI Layer Improvements — TODO

Living checklist for applying Anthropic architecture best practices to the LLM layer.
Derived from the *Claude Certified Architect – Foundations* domains cross-referenced
against a line-by-line read of our AI code. Plan: `~/.claude/plans/polished-baking-gizmo.md`.

Status legend: `[ ]` to do · `[~]` in progress · `[x]` done

---

## Workstream 1 — Structured output via forced tool-use + repair-retry

- [x] New `dast/ai/schemas.py` with JSON Schemas: planner, baseline, mutator, red-team
- [x] `bedrock_client.invoke_json`: add optional `schema` param (forced tool-use path)
- [x] `bedrock_client`: shared request-body builder used by `invoke` + `invoke_json` (`_build_body`)
- [x] `bedrock_client`: parse structured result from `tool_use` block `input` (`_extract_tool_input`)
- [x] `bedrock_client.invoke_json`: one-shot repair-retry on `JSONDecodeError` (legacy path)
- [x] Migrate `coordinator._plan()` to pass `schema=PLANNER_SCHEMA`
- [x] Migrate `coordinator._baseline_check()` to pass `schema=BASELINE_SCHEMA`
- [x] Migrate `red_team.validate()` to pass `schema=RED_TEAM_SCHEMA`
- [x] Migrate `mutator.next_payload()` to pass `schema=MUTATOR_SCHEMA`

## Workstream 2 — temperature=0 for deterministic decision stages

- [x] `bedrock_client`: add `temperature` param (omitted from body when `None`)
- [x] `coordinator._plan()`: `temperature=0`
- [x] `coordinator._baseline_check()`: `temperature=0`
- [x] `red_team.validate()`: `temperature=0`
- [x] Leave `mutator` at model default (diversity needed) — no temperature passed

## Workstream 3 — Prompt caching on static system prompts

- [x] `bedrock_client`: add `cache_system` param (system as content-block list w/ cache_control)
- [x] Enable cache for planner (`_SYSTEM_PLAN`)
- [x] Enable cache for baseline (`_SYSTEM_BASELINE`)
- [x] Enable cache for red-team (`_SYSTEM`)
- [x] Enable cache for mutator (`_SYSTEM_MUTATOR`)
- [x] Log cache read/creation tokens from response `usage` at debug (`_log_cache_usage`)

## Workstream 4 — Few-shot examples

- [x] `mutator._SYSTEM_MUTATOR`: mutate-example + stop-example
- [x] `red_team._SYSTEM`: confirmed=true + confirmed=false examples
- [x] `coordinator._SYSTEM_BASELINE`: ok / abort / adapt examples

## Verification

- [x] Import sanity + existing coordinator unit tests pass (95 passed)
- [x] Full unit suite green (434 passed)
- [x] Structured-path test (schema forces shape) — unit + live Bedrock smoke
- [x] Repair-retry unit test (mock malformed→valid)
- [x] temperature + cache wiring unit test (mock boto3, assert body)
- [x] Live cache verification: call 1 creates 1443 cache tokens, call 2 reads 1443
- [x] CHANGELOG.md updated

---

## Workstream 5 — Structural prompt-injection defense (XML delimiting)

Rationale: a denylist can't win against a target that writes in any language/encoding.
Fix is structural — fence untrusted content and tell the model it is data, not commands.
Denylist (`_sanitize_for_prompt`) kept as a cheap second layer (defense-in-depth).

- [x] New `dast/ai/prompt_safety.py`: `wrap_untrusted()` + `UNTRUSTED_CONTENT_DIRECTIVE`
- [x] `wrap_untrusted` neutralises forged open/close tags + runs denylist as 2nd layer
- [x] Directive appended to `_SYSTEM_PLAN`, `_SYSTEM_BASELINE`, red-team `_SYSTEM`, `_SYSTEM_MUTATOR`
- [x] `coordinator._baseline_check`: fence request body + response body
- [x] `coordinator._plan`: fence request body + discovery/app/session/code hints
- [x] `red_team.validate`: fence response snippet + discovery/app/threat-model/code hints
- [x] `mutator.next_payload`: fence response snippet
- [x] Unit tests `tests/unit/test_prompt_safety.py` (9 tests: fence escape, 2nd layer, truncation)

## Workstream 6 — LLM eval harness (PoC)

Rationale: planner + red-team decisions govern our TP/FP rate but have zero test coverage.
Opt-in harness (real Bedrock, costs tokens) with a human-labelled golden set.

- [x] `tests/evals/` — golden sets (`planner_cases.yaml`, `red_team_cases.yaml`) + README
- [x] `tests/evals/run_evals.py` — runner scoring accuracy + injection-resistance
- [x] Injection-probe cases in both suites (adversarial response tries to hijack verdict)
- [x] Not collected by default pytest (no `test_` prefix) — verified 0 collected
- [x] First run: planner 100% (5/5), red_team 100% (5/5), injection-resistance 100%

## Future follow-ups (not yet scoped)

- Grow the golden set (more attack types, more FP edge cases) and wire `--min-accuracy`
  into a manual pre-release gate.
- Consider fencing header dicts / param names too (lower risk, currently unfenced).
