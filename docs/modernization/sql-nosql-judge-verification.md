# ARIA and NOVA judge qualification

The disposable PostgreSQL18 harness captures twenty positive and twenty negative
cases through the actual workshop repositories. The negative cases retain the
learner's attack claim while supplying an observed no-match query outcome, so
learner wording alone must not earn credit. This is recorded-tool qualification,
not an agent tool-selection or browser test.

The SQL column-count case includes chronological successful ORDER BY8 and failing
ORDER BY9 query receipts. Database-version and schema cases contain actual
PostgreSQL metadata, not invented MongoDB versions. NOVA remains an operator
simulation, including its MongoServerError-shaped teaching error.

NOVA full results approached the judge's24KB evidence limit. Its grading adapter
now keeps every result row and all fields except abstract, biography, citation
list, and URL, with explicit rowCount/omittedFields. Credential and access-scope
fields remain available. ARIA results are preserved in full.

Qualification exposed two application inconsistencies, both corrected:

- NOVA version/schema objectives4/5 had incompatible base solutions; base and PG
  defaults now use db.version()/Object.keys(this), and native PG seeding uses the
  PG-specific defaults. Saved instructor content is not overwritten.
- NOVA had no restricted-record classification. PG migration0002 and fresh seeds
  now classify two exact training records as restricted. Normal/fixed search
  excludes them; the intentional operator bypass still returns them. The
  retained SQLite engine does not yet support this evidence contract.

Validation:22 PostgreSQL tests, ARIA105, NOVA137, and adapter/projection/default
parity unit tests pass. The isolated cluster is stopped after capture. The live
model runner is `tests/manual/sqlNoSqlJudge8b.js`; its input is the harness-created
`/tmp/owasp-ai-goat-sql-nosql-judge-cases.json` and its result output is
`/tmp/owasp-ai-goat-sql-nosql-judge-results.json`.

The first local8B diagnostic run (roles-v3, policy digest
`1032728f69e094d23f27dd99b7e5d0c90627729602ac2c310205713e57db5cb8`)
passed13/20 positive cases but also passed13/20 negative cases. The adapter had
hardcoded objective_signal_detected=true. It now derives that prerequisite from
actual output shape/content and invocation, including real database errors,
version/schema metadata, restricted rows, and paired ORDER BY history. This is
an independent minimum-evidence gate; semantic model grading still runs and
controls completion for qualifying evidence. An always-passing model fixture
cannot award any of the20 objectives from empty observed results. The corrected
40-case live rerun is in progress; no final reliability claim is made yet.

## Corrected qualification results

After the independent outcome prerequisites, exact marker match evidence, and
compact factual NOVA summaries, every objective has a passing positive case and
a non-awarding negative case. Full returned rows remain present. Real fixed
query comparisons additionally passed all eight targeted checks under grounded-v5.
These are staged qualification runs, not a claim that the entire current-core
40-case suite has already run in one process. The unified serial suite should
run the checked-in capture against its selected frozen judge policy.

| Objective | Positive | Negative | Latest case judge |
|---|---|---|---|
| sqli_1 | pass | fail | 2026-09-11.context-v4 |
| sqli_2 | pass | fail | 2026-09-11.grounded-v5 |
| sqli_3 | pass | fail | 2026-09-11.context-v4 |
| sqli_4 | pass | fail | 2026-09-11.context-v4 |
| sqli_5 | pass | fail | 2026-09-11.context-v4 |
| sqli_6 | pass | fail | 2026-09-11.context-v4 |
| sqli_7 | pass | fail | 2026-09-11.context-v4 |
| sqli_8 | pass | fail | 2026-09-11.context-v4 |
| sqli_9 | pass | fail | 2026-09-11.context-v4 |
| sqli_10 | pass | fail | 2026-09-11.context-v4 |
| nosqli_1 | pass | fail | 2026-09-11.context-v4 |
| nosqli_2 | pass | fail | 2026-09-11.grounded-v5 |
| nosqli_3 | pass | fail | 2026-09-11.grounded-v5 |
| nosqli_4 | pass | fail | 2026-09-11.context-v4 |
| nosqli_5 | pass | fail | 2026-09-11.context-v4 |
| nosqli_6 | pass | fail | 2026-09-11.grounded-v5 |
| nosqli_7 | pass | fail | 2026-09-11.context-v4 |
| nosqli_8 | pass | fail | 2026-09-11.context-v4 |
| nosqli_9 | pass | fail | 2026-09-11.context-v4 |
| nosqli_10 | pass | fail | 2026-09-11.context-v4 |

Reproducible opt-in command:

```sh
RUN_LIVE_JUDGE=1 node --test tests/sqlNoSqlObjectiveJudge.live.test.js
```

Its checked-in, scrubbed real PostgreSQL capture and provenance are in
`tests/fixtures/sqlNoSqlJudgeRecorded.json` and the adjacent Markdown file.
The runner emits case counts, verdicts, judge version, context size, policy
digest, model, and attempt count. Without RUN_LIVE_JUDGE=1 it skips and never
contacts Ollama. It never reads or writes a live application database.

Latest validation:12 focused adapter/fixture tests passed; the disposable suite
passed22 PostgreSQL tests plus ARIA105/NOVA137, including all40 real outcome
prerequisites and durable judge metadata round trips.
