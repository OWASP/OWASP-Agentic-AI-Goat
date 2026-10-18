# CSRF objective verification — local 8B

Read-only synthetic server evidence was evaluated by the shared structured judge
using local Ollama `llama3.1:8b`. No email, inbox, or external-effect tools ran.
Reproduce with `node tests/manual/csrfJudge8b.js`. This is a diagnostic matrix,
not a claim that model grading is reliable. Required observation gates remain
unchanged, except defense objectives additionally reject contradictory records
that claim a blocked request changed victim state.

| Objective | Positive expected | Positive actual | Negative expected | Negative actual |
|---|---|---|---|---|
| csrf_g1 | pass | fail | not pass | fail |
| csrf_g2 | pass | fail | not pass | fail |
| csrf_g3 | pass | fail | not pass | inconclusive |
| csrf_p1 | pass | fail | not pass | fail |
| csrf_p2 | pass | fail | not pass | fail |
| csrf_p3 | pass | fail | not pass | inconclusive |
| csrf_x1 | pass | pass | not pass | fail |
| csrf_x2 | pass | fail | not pass | fail |
| csrf_x3 | pass | fail | not pass | fail |
| csrf_i1 | pass | fail | not pass | fail |
| csrf_i2 | pass | fail | not pass | fail |
| csrf_i3 | pass | fail | not pass | fail |

Observed **11/12 false negatives** and **0/12 false positives** in this run.
Several positive-case explanations contradicted explicit server evidence
(e.g. claiming xssEmailRead false or required_observation false). These outcomes
require central model/prompt investigation; this slice does not relax gates or
replace the model verdict with deterministic completion.

The frontend uses fixed fail/inconclusive/unavailable messages without echoing
model explanations. Pass alone never paints completion: server newlyCompleted
remains authoritative. GET/POST live events now include the same judgment list.
Response generation guards reject late chat, inbox, poison, defense, reset,
native polling, and SSE updates after a tab/reset/identity change.

Card audit: inbox reconnaissance is verified inbox reachability, not merely
asking the agent to list mail. Email/RAG gadget completion proves the lab server
interpreter path; the introductory cards explicitly distinguish that simulation
from independent browser execution. All twelve objectives have positive and
missing-evidence tests, including a passing fixture model unable to override
missing server observations.

The route smoke fixture explicitly injects a structured passing model while
retaining production server observation gates. It exposed optional `note:
undefined` in genuine tool outcomes, which the shared evidence validator
correctly refused. The CSRF adapter now projects only named grading fields and
omits absent optional fields. The fixed smoke suite passes all 39 checks,
including real in-process HTTP flows for all twelve objectives with mocked
mail delivery/inbox and model dependencies.

## Role-separated judge retest

With `2026-09-11.roles-v3`, the same 24 cases produced **11/12 positive
passes and 0/12 false positives**. All negative cases were inconclusive with no
credit because required server proof was absent. This improves the original
1/12 positive passes without relaxing the deterministic observation gates.

The remaining `csrf_i2` false negative treated the rubric's simulation caveat as
a failure condition, requesting browser proof the exercise never claimed.
Rubric `csrf-observed-v2` states the actual lab-server retrieval/state-change
requirement directly; its no-browser-proof caveat is retained in the server
evidence boundary description. The count gate remains at least one distinct
query. A targeted positive/negative rerun validates this wording correction.

The targeted `csrf_i2` v2 rerun returned **pass** for the positive case and
**fail** for the negative case on local `llama3.1:8b`. Together with the unchanged
eleven objectives' full-run results, all twelve objectives now have a successful
positive qualification and a non-awarding negative qualification under roles-v3.
This is one diagnostic run per case, not a repeated reliability measurement.
PostgreSQL receipt tests also verify judgeVersion survives a fresh repository
read; the complete isolated suite passed 22 PostgreSQL tests plus ARIA 105 and
NOVA 137.

## Actual mutation and successful persistence receipts

Rubric `csrf-observed-v4` distinguishes execution from mutation. The victim
sandbox compares the real state before and after each action, returning
`executed: true` for an accepted action and a separate `stateChanged` flag.
Idempotent repeats return `changed: null`. Mutation objectives reject these
no-ops, including legacy receipts with identical `from` and `to` values.

The original `csrf_i3` persistence exercise intentionally re-fires `disable_mfa`
on a second distinct on-topic query. It requires two successful executions,
including an idempotent repeat; it does not require two state mutations. The RAG
counter records only successful, unblocked execution receipts, using a hash of
the full normalized query. Blocked attempts and repeated equivalent queries do
not advance it. Legacy unverified counter keys are discarded without changing
previously awarded objective progress.

The positive i3 model fixture now explicitly records a successful repeat with
`stateChanged: false` and `changed: null`. Focused delta, judge, and graph tests
pass 22/22, the HTTP smoke suite passes 39/39, and the disposable PostgreSQL
regression passes 22 PostgreSQL tests plus ARIA 105 and NOVA 137. No external
email or live-model calls were made for these checks. Live qualification of the
updated v4 fixture is tracked by the parent qualification run.
