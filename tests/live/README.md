# Live Vuln-Detection Benchmark

Measures the scanner's **true-positive / false-positive / false-negative rate**
end to end — through the running proxy and dashboard, against a real vulnerable
app — and reports per-class **recall** and **precision**.

This is the empirical counterpart to [`tests/evals/`](../evals/README.md): the
eval harness scores individual LLM decisions in isolation; this harness scores
the *whole pipeline* (proxy interception -> coordinator -> agents -> validation
-> dashboard) against ground truth. It is the deliverable that answers the
CLAUDE.md bar — "does the tool find real, exploitable vulns with a low false
positive rate" — and makes per-class generalization something you can *measure*
rather than guess at.

**Opt-in.** It needs a running proxy, a configured AI provider, and a live
target, so it is NOT part of `uv run pytest`.

## How it works

1. Configures the proxy scope + AI mode via the dashboard API.
2. Authenticates to the target and drives each ground-truth endpoint **through
   the proxy** (never straight at the target, never by invoking agents directly)
   so the run exercises the exact production path.
3. Scans the intercepted entries via `POST /api/scan` and waits for the queue to
   drain.
4. Pulls `GET /api/findings`, keeps confirmed active findings on scoped
   endpoints, and matches them against each endpoint's `expect` set.
5. Prints TP / FN / FP and recall / precision.

## Run it

```bash
# 1. Start the proxy + dashboard (separate terminal), with an AI provider set.
uv run dast-ai proxy

# 2. Bring up the target.
docker run --rm -it -p 8081:80 vulnerables/web-dvwa   # visit once to create the DB

# 3. Run the benchmark.
uv run python -m tests.live.vuln_bench --spec tests/live/ground_truth/dvwa.yaml

# Optional: fail the run if recall drops below a floor (for CI-style gating).
uv run python -m tests.live.vuln_bench --spec tests/live/ground_truth/dvwa.yaml --min-recall 0.8
```

## Use a fresh proxy

The harness disables auto-scan so the scan queue holds only the entries it
explicitly enqueues (otherwise the proxy auto-scans all intercepted traffic —
including the probe requests the scan itself generates — flooding the queue).
It does NOT drain a queue that already had work in it: a long-running proxy that
has been auto-scanning unrelated traffic will still have that backlog competing
for workers, so the targeted drain can time out. Scoring stays valid (it reads
persisted confirmed findings), but for a clean, fast run start a **fresh
`uv run dast-ai proxy`** just before benchmarking.

## Ground-truth specs

One YAML per target under `ground_truth/`. Each lists the endpoints to drive and
the `expect`ed attack classes per endpoint (see `dvwa.yaml` for the schema, which
is documented inline). Add a spec per app to measure how detection generalizes:
Juice Shop, VAmPI, WebGoat, `testphp.vulnweb.com`, etc. Start lean and expand.

A finding is a **true positive** when its `attack_type` matches an endpoint's
`expect`; a **false negative** when an expected class is not confirmed; a **false
positive** when a confirmed active finding's class was not expected anywhere
(passive/informational classes are excluded via `ignore_attack_types`).
