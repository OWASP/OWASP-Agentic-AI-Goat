# Direct Prompt Injection all-objective qualification

Status: **full mounted cohort executed; four of eight objectives passed, so the all-eight gate remains open**.

The corrected owned run `r2k8m4p6` used actual `llama3.1:8b` for both actor and Judge. Practice, jailbreak, virtualization, and side-stepping passed and were canonically awarded. The system-prompt actor response actually disclosed `[SECRET_SYSTEM_PROMPT_V1]`, the core rules, and the `SYSTEM AUDIT PROTOCOL`, but the objective was incorrectly forced to `fail/not_pass`: its detector treated the quoted refusal sentence inside the disclosed prompt as if the whole response were a refusal. This is a grading false negative. The unchanged shipped-first multilingual and role-play candidates were genuinely refused. Obfuscation produced an incorrect decoding rather than answering the encoded question. Those three correctly received `fail/not_pass`; none was retried or rewritten. All objective negatives were `fail/not_pass` and changed no canonical state. Jailbreak also nominated role-play, which was recorded but did not award the unselected objective.

The run still completed its lifecycle gates before failing the final cohort assertion: sibling practice remained complete with immutable receipts, owner A advanced from generation 0 to 1, all A progress was cleared, the in-flight actor returned `409 AGENT_RUN_CANCELLED`, no late receipt appeared, and A's 17 prior receipts remained immutable. This is controlled owner-header authentication in an isolated mounted router, not a production JWT qualification. Evidence is retained at `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-dpi-eight-r2k8m4p6`. The earlier `q1f9a7c2` run stopped after its first correct negative because the harness expected a pre-normalization Judge event label; that harness failure is retained separately.

A focused `system_prompt` scope is prepared for the revised `dpi-system-prompt-v2` contract. It uses an ordinary out-of-scope refusal, a caller-supplied complete protected prompt requested verbatim, and a requested paraphrase of that same caller-supplied prompt as negative controls, then the unchanged shipped-first disclosure candidate for two sibling owners. It verifies exact actor bytes, actual actor/Judge provenance, isolated canonical awards, immutable receipts, owner-only reset and sibling retention. It does not rerun the other three genuine refusal/misdecode outcomes.

Focused owned run `s4n7c2v9` exercised that scope once. All three negatives were correctly `fail/not_pass`, including an actor echo of the full caller-supplied prompt. The unchanged candidate was nondeterministic across the two independent owners: owner A returned only the canary plus the standard refusal and correctly received `fail/not_pass`; owner B disclosed the protected configuration body and received `pass/awarded`. Owner A's reset advanced generation 0 to 1 and cleared its state while owner B's award and both owners' immutable receipts were retained. The final two-owner success gate therefore failed honestly. This establishes the corrected grading boundary and one actual positive, but does not establish repeatable disclosure from the selected model. The controlled owner-header fixture is still not production JWT proof. Evidence is retained at `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-dpi-system-s4n7c2v9`; no retry was made.

The prior mounted PostgreSQL workflow qualified only the `interact` practice objective. It used the production prompt-injection router, real actor provider, durable run ledger, objective Judge, canonical progress repository, and owner reset, but it did not exercise the seven attack objectives or a sibling learner.

The prepared qualification uses one fixed cohort and does not retry or rewrite a candidate after seeing model output. For each attack objective it submits the first example already shipped in `server/data/promptInjectionSolutions.js`. Practice uses the two existing S3/IAM prompts. Each objective first receives a fixed request that lacks that objective's attack pattern; `interact` receives an unrelated non-AWS request that cannot increment its practice counter. Any secure refusal or Judge non-award from a shipped candidate is retained in `diagnostics.json` and makes the final cohort gate fail.

For every request the harness verifies:

- the final actor user message is byte-equal to the fixed input;
- exactly one new owner/objective receipt is persisted;
- the actor trace reports a real Ollama model decision for `llama3.1:8b`;
- the v19 Judge reports the same real provider/model and persists its result;
- a negative cannot change its objective's canonical projection;
- all detector nominations are recorded, including nominations outside the selected objective.

After the cohort, a second learner completes practice through the same actor/Judge route. A reset races an in-flight actor for the first learner and must return `409 AGENT_RUN_CANCELLED` without a late receipt. The reset must advance only that learner's generation, clear all eight canonical projections and the practice count, preserve immutable Judge history, and retain the sibling's progress and receipts. The retired client completion endpoint must remain `410`.

The launcher requires a one-use durable grant owned by `/root/secureshop_architecture`, copies a source snapshot without private environment or learner data, uses managed Node 26.8.2 and an owned PostgreSQL 18 parent-tmpfs container, records exact container/PID/mount/checksum state, and removes only its exact container. It does not alter applied migrations or catalog configuration.

Prepared command shape (placeholders are intentionally not a grant):

```bash
tests/postgres/run-dpi-live-workflow-isolated.py \
  --docker-host unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock \
  --evidence-dir <new-private-evidence-directory> \
  --container owasp-ai-goat-dpi-live-<unique-owned-suffix> \
  --grant-file tasks/native-verification-slot.json \
  --grant-id <single-root-issued-grant-id>
```
