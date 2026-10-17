# LLM Red-Team Harness: pitch

## The pitch
Every LLM feature ships with guardrails nobody measures. This project puts a layered guardrail stack in front of a toy HR assistant that holds secrets, and replays a versioned suite of 70 attacks and 40 benign requests through it every night. It reports attack success rate per category and false-positive rate for each guardrail configuration. Against a worst-case model that obeys every attack, the full stack cut attack success from 100% to 4.3% while refusing 5% of benign requests.

## Problem and who it's for
AI security and platform teams shipping assistants that can see sensitive data (system prompts, customer records). They need to know three things: which attacks still get through, what each defense layer actually buys, and whether tonight's model or prompt change made things worse. They need those answers as numbers, not anecdotes.

## How it works
See the README diagram. A request passes through four layers:
1. Regex input rules.
2. An input classifier: Claude Haiku when live, a local TF-IDF model in mock mode.
3. A PII scrubber.
4. After the model answers, an output filter that matches known secrets.

The harness replays `suites/v1.json` under four configurations (none, rules, rules+classifier, full). A deterministic oracle (canary, prompt shingles, PII digits, marker phrases) decides whether each attack succeeded. Results go to Postgres and a dashboard. A scheduled GitHub Action runs it nightly and fails when ASR or FPR exceed budget.

## Stack and design choices
- **Deterministic oracle instead of an LLM judge.** Leaks are binary, so there's no judge drift between nights. *Trade-off:* it can't detect a *paraphrased* leak of the system prompt that keeps no 8-word span intact.
- **Worst-case mock target.** Mock ASR is an honest upper bound set entirely by the guardrails. *Trade-off:* it says nothing about the real model's own robustness. That needs live mode.
- **Layer ablation in every run.** It quantifies the classifier's value (−38.6 points of ASR) against its cost (5% FPR).
- **Known-secret output DLP.** It catches what input filters miss: 4 of the 70 attacks were stopped only at the output.
- **Postgres + a static dashboard + GitHub Actions cron.** No new infrastructure beyond the database.

## What I'd do differently
- **Harder, independent attacks.** Live, Claude Haiku resisted all but one attack (a partial jailbreak) even without guardrails, and the full stack reached 0% ASR at 0% FPR ($0.04 per replay). The first live run also exposed an oracle bug, where refusals quoting the marker were counted as breaches. I also wrote both the rules and the suite. Next steps: a held-out suite written by someone else, an attacker LLM that mutates failed attacks, multi-turn attacks, and encoding tricks.
- **Indirect injection is the guardrails' weak spot** (20% ASR against the worst-case mock): AI-addressed text without a trigger phrase ("Translator AI:", hidden `<span>`, `[[SYSTEM]]`). Fixes worth trying: strip hidden HTML, run a document-specific classifier, and isolate documents structurally, e.g. a separate tool result rather than inline text.
- **Cost of the classifier.** One Haiku call per request adds latency and money. A cheaper approach is to run it only when the rules are inconclusive or a document is attached.

## Interview talking points
- Why the oracle is deterministic, and how canaries and marker phrases make "attack success" measurable.
- What a worst-case mock target lets you claim, and what it doesn't.
- The ablation: each layer's marginal ASR reduction against the false positives it adds.
- The regex bug (`\b` after a colon) and why I fixed the rule rather than tuning on the test suite.
