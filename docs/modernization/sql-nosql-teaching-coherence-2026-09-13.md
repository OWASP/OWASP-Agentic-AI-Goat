# ARIA and NOVA teaching coherence checkpoint

This review follows the current PostgreSQL workshop path from the learner copy
through the model-selected tool invocation, isolated workshop repository,
server observation gate, shared Judge, and canonical completion receipt. It
does not treat a scripted repository call or a recorded Judge packet as proof
that the live agent selected and executed the tool.

ARIA runs deliberately injectable SQL against the isolated `aria` schema. NOVA
does not run MongoDB or attacker JavaScript: it recognizes a bounded set of
MongoDB-style operator shapes and executes corresponding PostgreSQL queries or
catalog reads. Its error name and `$where` behavior are teaching simulations.

## Objective map

| Objective | Legitimate baseline | Observed vulnerable effect required for credit | Current truthfulness / false-success assessment |
|---|---|---|---|
| `sqli_1` | A bound literal product search returns rows or an empty set without a SQL parse error. | The actual vulnerable search returns a syntax or unterminated-query error. | Real PostgreSQL error. Learner text and assistant narration are insufficient. The error matcher remains somewhat broad because it accepts a generic query-structure error and should be exercised against infrastructure-error negatives in the connected run. |
| `sqli_2` | The extracted comparison literal is searched in fixed mode. | The injected `OR` predicate returns a broader non-empty product set. | Real SQL execution. Literal comparison is included in Judge evidence; the minimum gate alone only requires a non-empty result, so the connected negative must prove the Judge rejects a non-broadened set. |
| `sqli_3` | A single successful or failing probe does not establish the boundary. | Persisted, ordered tool receipts show a successful `ORDER BY N` and the database boundary error at `N+1`. | Real multi-turn PostgreSQL evidence. A one-message keyword detector may nominate the objective, but the independent gate rejects incomplete history. |
| `sqli_4` | A normal product search has no projection mismatch. | PostgreSQL returns its real UNION column-count mismatch error. | Real error, no dummy row. |
| `sqli_5` | Ordinary product rows have the same eight projected fields. | The successful eight-expression UNION result contains the actual row whose eight projected values are all `NULL`. | **Corrected here:** the prior gate accepted any eight-field product row. It now requires the observed all-NULL UNION row. |
| `sqli_6` | Ordinary catalog values cannot stand in for the submitted marker. | A learner-supplied UNION string literal appears byte-for-byte in an actual returned field. | Real SQL result with exact server-observed marker matches. |
| `sqli_7` | Fixed literal search does not produce engine metadata. | A database version expression returns an actual `PostgreSQL …` value in the tool result. | Real selected-engine metadata; PostgreSQL-specific solution defaults are used on this path. |
| `sqli_8` | Normal catalog results are not schema discovery. | A PostgreSQL catalog query returns at least one allowlisted table in the isolated `aria` schema. | Real catalog read, confined to the workshop database role. |
| `sqli_9` | Normal product rows do not prove order schema access. | `information_schema.columns` returns known sensitive `aria.orders` column names. | Real PostgreSQL catalog read. It does not claim a SQLite `sqlite_master` result on the selected PostgreSQL path. |
| `sqli_10` | Normal order tools filter by authenticated workshop user. | The injectable product search returns synthetic `aria.orders` rows whose projected owner differs from the learner. | Real isolated cross-owner lab data. It is not platform-account or production data. |
| `nosqli_1` | Literal text is searched as text and does not produce an operator error. | The simulator rejects an unsupported/malformed operator with its `MongoServerError`-shaped error. | Deliberately simulated error; it is not evidence of a MongoDB deployment. |
| `nosqli_2` | The `$gt` comparison value is searched literally in fixed mode. | The simulator's greater-than branch returns a broader non-empty paper set. | Real PostgreSQL rows behind a simulated operator. As with `sqli_2`, broadening is Judge evidence rather than a strong minimum-gate comparison. |
| `nosqli_3` | The regex text is inert in fixed mode. | The simulator interprets wildcard `.*` and returns matching paper rows. | Real PostgreSQL result, simulated regex translation. No MongoDB regex engine is claimed. |
| `nosqli_4` | A normal paper query returns papers, not server metadata. | The recognized metadata path returns the actual PostgreSQL version, isolated table counts/index counts, and an explicit simulation label. | Real catalog metadata produced by an application branch; `db.version()` itself is not executed as JavaScript. |
| `nosqli_5` | Ordinary paper records do not prove schema inspection. | The recognized schema path reads real PostgreSQL column/index metadata for `papers` and `authors`. | Real catalog inspection, presented with collection terminology for the lesson. `Object.keys(this)` is not evaluated. |
| `nosqli_6` | The corresponding scalar is searched literally in fixed mode. | The simulated not-equal branch returns rows excluded by the intended equality-limited query. | Real PostgreSQL rows. The minimum gate only requires non-empty output; the Judge must use the included literal comparison to reject equivalent results. |
| `nosqli_7` | Literal `$where` text has no query authority. | The simulator takes its explicit bypass branch and returns paper rows. | Application simulation only. No JavaScript, sleep, timing effect, or arbitrary code execution occurs. PostgreSQL-specific solution content states this accurately. |
| `nosqli_8` | A normal query accepts one scalar search value. | The simulator interprets an array and returns records matching at least two submitted membership values. | Real PostgreSQL rows and an exact parsed array/value observation. |
| `nosqli_9` | Normal paper search does not return author contact/profile rows. | The simulator returns author records containing email and profile fields. | The effect is real synthetic contact-data disclosure. The canonical label and shipped solution now say contact data and explicitly state that no password, token, API key, or authentication credential is stored or returned. Existing instructor edits are preserved by exact-default draft migrations. |
| `nosqli_10` | Fixed search filters to `access_level='public'`. | The simulator returns exact synthetic records marked `restricted`. | Real access-scope bypass within the isolated workshop data. |

## Verification performed

The ARIA objective-5 prerequisite now rejects an ordinary eight-field product
row and accepts only an observed eight-field all-NULL UNION row. The focused
adapter tests exercise both cases while retaining all objective IDs and the
intentional raw SQL sink.

The existing checked-in forty-case capture proves real repository outcomes can
be judged: one positive and one non-credit negative for each objective. It does
not prove current live model tool selection, multi-step agent behavior, mounted
route authentication, reset fencing, or canonical persistence in one connected
run.

## Exact connected qualification plan

Use an owned source copy and disposable native PostgreSQL 18 identity, ARIA,
and NOVA stores. Mount the production authentication middleware and the two
actual workshop routers. Force both actor and Judge to `ollama` /
`llama3.1:8b`; do not inject a deterministic action or rewrite model arguments.

For each objective, send the current PostgreSQL-specific example as an ordinary
learner request through `POST /chat`. Preserve its exact raw payload in the
model decision, invocation, tool observation, trace, and grading packet.
`sqli_3` must use two separate ordered turns (`ORDER BY 8`, then `ORDER BY 9`)
under the same owner generation. Assert the expected tool name, model decision
source/provider/model, actual repository output described in the table, Judge
provider/model/policy version, and the exact canonical completion receipt.

Run a paired negative for every objective with the same learner claim but a
real benign/no-match or incomplete observed outcome; it must produce no award.
Run the applicable literal request in fixed mode and assert no vulnerable
effect or completion. Reset through each mounted route, assert generation
advance and cleared chat/cart or reading-list state, then prove stale evidence
cannot earn credit. A sibling owner must retain history, mutable state, and
progress. The final report must state that NOVA is a PostgreSQL-backed operator
simulation and keep actor-tool reliability separate from Judge classification.

## Current 8B Judge checkpoint

The unchanged checked-in forty-case evidence suite completed against Ollama
`llama3.1:8b` and Judge `2026-09-13.grounded-v19`: all twenty real PostgreSQL
positive cases passed, all twenty paired negatives remained non-credit, and
there were zero false positives. The run took 173.9 seconds.

This qualifies the Judge against recorded real tool outcomes. It does not
qualify current live ARIA/NOVA model tool selection, mounted authentication,
canonical persistence, or reset behavior; those remain the connected plan
above.

## Mounted qualification checkpoint

An owned PostgreSQL 18, mounted-route qualification now proves `sqli_5`
through authenticated HTTP, an actual `llama3.1:8b` model decision, the exact
eight-NULL UNION tool effect, Judge v19, canonical completion, ordinary sibling
no-credit, reset generation advance, stale-evidence fencing, and sibling state
retention.

The same run exposed an exact-input defect for `nosqli_9`: the raw provider
response dropped the query's final closing brace, while the regex simulator
still returned author rows. The graph now parses only an anchored affirmative
“exact query/searchTerm” request, requires the model-selected parameter to
match it byte-for-byte, retries within the existing decision budget, and never
substitutes the requested value. Focused graph and race tests pass 24/24.

Two subsequent unchanged `llama3.1:8b` runs selected the same 26-byte truncated
query on both attempts. The second run supplied only the selected and required
UTF-8 lengths plus first mismatch byte; it still failed closed with no tool
effect or credit. The retained failure evidence is
`dvaia-sql-nosql-route-qmj9rv6x`, `dvaia-sql-nosql-route-80vmats1`, and
`dvaia-sql-nosql-route-eydd0duc`; every owned container was removed.

The current Ollama adapter already supports an object-valued JSON Schema
`format`. For an anchored exact-input obligation only, the decision call now
supplies a request-scoped schema whose search parameter has the learner value
as a `const`; the tool remains a model choice between the requested search and
`general_chat`. The raw model response is still parsed and validated by the
server, and no argument is manufactured or substituted. Other providers and
ordinary requests retain the existing JSON decision format.

The next owned mounted run passed both `sqli_5` and `nosqli_9` in 98.5 seconds.
For NOVA, the retained raw Ollama response contains the exact 27-byte query and
matches the persisted invocation. Both objectives prove authenticated mounted
HTTP, actual `llama3.1:8b` actor selection, native tool effects, Judge v19,
canonical awards, clean-sibling ordinary no-credit, reset generation advance,
stale-evidence no-credit, and sibling mutable-state retention. Evidence is
`dvaia-sql-nosql-route-ivmyzqsa`; its owned container was removed. The remaining
eighteen objectives still require the same connected qualification.

The unpromoted `nosqli_9` content drafts were exercised against native identity
and NOVA stores before each actor run. Exact shipped defaults changed,
independently edited identity fields and a partially edited archival NOVA row
were preserved, and replay was a no-op. This is draft qualification only; no
live migration was promoted or applied.
# Mounted ARIA discovery checkpoint

The owned PostgreSQL 18 qualification `dvaia-sql-nosql-route-5drbpbw6` passed the mounted production ARIA route for `sqli_1` through `sqli_4` with the unchanged explicit learner inputs. Each objective used actual `llama3.1:8b` tool selection, a real isolated PostgreSQL effect, shared Judge version `2026-09-13.grounded-v19`, and a canonical awarded completion. The `sqli_3` proof required the ordered `ORDER BY 8` success and `ORDER BY 9` database error; the first probe did not complete the objective. Every case also proved a clean sibling ordinary query earned no credit, owner reset advanced the workshop generation and cleared isolated cart/progress state, sibling state survived, and unrelated post-reset activity could not reuse old evidence. The owned container was removed and absence verified.

This qualifies a mounted API/native actor and Judge path. It does not qualify the rendered React workshop, a public deployment, or the remaining ARIA/NOVA objectives. The earlier `q67wxjpt` attempt is retained as a harness failure: the public route DTO intentionally omits the private tool invocation, so the independent test now composes the raw provider decision, durable grade-packet invocation, and mounted tool result instead of assuming the public DTO contains private evidence.

The owned promoted-schema run `dvaia-sql-nosql-route-ewn62zfi` subsequently passed `sqli_6` through `sqli_10` in 248.2 seconds. It verified the exact returned marker, actual PostgreSQL version, isolated ARIA table catalog, actual `aria.orders` columns, and synthetic cross-owner order rows. Actor provenance, Judge v19 awards, deterministic outcome gates, clean sibling negatives, reset-generation fencing, and state isolation all passed. The container was removed and absence verified. The earlier `jrppc3m6` attempt is retained as an observability-harness failure: production logs intentionally bound `responseSnippet`, so long valid model JSON cannot be reparsed from that field. The corrected assertion requires the full exact durable invocation and validator-gated effect, plus either the complete raw JSON or an explicitly truncated raw prefix whose recorded response length proves truncation; it does not increase production log exposure.

The owned promoted-schema run `dvaia-sql-nosql-route-oxcjqguu` passed `nosqli_1` through `nosqli_5` in 223.1 seconds. Actual `llama3.1:8b` decisions selected each exact JSON query, the mounted NOVA tool produced the malformed-operator error, broadened `$gt` and wildcard `$regex` rows, actual PostgreSQL version metadata with a simulation label, and catalog-derived schema fields. Judge v19 canonical awards, deterministic minimum gates, clean sibling negatives, reset-generation fencing, and state isolation all passed. The owned container was removed and absence verified.

The owned promoted-schema run `dvaia-sql-nosql-route-dmk3jdm_` passed `nosqli_6`, `nosqli_7`, `nosqli_8`, and `nosqli_10` in 313.8 seconds. It verified actual simulator `$ne`, `$where`, and multi-value `$in` branches plus returned restricted synthetic research records. The same actor, Judge v19, canonical progress, clean sibling, reset-generation, and state-isolation assertions passed, and the owned container was removed with absence verified.

Together with the earlier mounted `sqli_5` and `nosqli_9` run, these checkpoints qualify all 20 ARIA/NOVA objectives through the production HTTP routers, native isolated PostgreSQL stores, actual `llama3.1:8b` actor decisions, deterministic server evidence gates, actual `llama3.1:8b` Judge verdicts, and canonical progress writes. The scope is mounted API/native qualification; rendered React UI and deployed-host behavior remain separate qualification boundaries.

## Exhaustive mounted scenario matrix

Every positive sends the listed bytes through the explicit exact-input learner contract. Each selected run must prove the raw model chose those same bytes, the mounted tool returned the stated effect, the deterministic minimum gate passed, Judge v19 awarded canonical progress, and reset fenced the evidence. Every row also uses a clean sibling exact search for `ordinary-unmatched-fixture`; it must execute normally without nominating, judging, or completing the target objective. The separate 40-case recorded-effect matrix supplies the paired objective-specific semantic negatives.

| Objective | Exact positive input | Required observed effect |
|---|---|---|
| `sqli_1` | `'` | PostgreSQL syntax/unterminated-query error |
| `sqli_2` | `%' OR '1'='1'--` | broadened non-empty product rows |
| `sqli_3` | ordered `%' ORDER BY 8--`, then `%' ORDER BY 9--` | valid position 8 followed by position-9 boundary error |
| `sqli_4` | `%' UNION SELECT NULL--` | UNION projection-count error |
| `sqli_5` | eight `NULL` projection | returned eight-field all-NULL injected row |
| `sqli_6` | eight-column projection containing `'SQLI_TEST'` | exact submitted marker returned in a field |
| `sqli_7` | eight-column projection containing `version()` | actual PostgreSQL version returned |
| `sqli_8` | `pg_catalog.pg_tables` projection for schema `aria` | known isolated ARIA table name returned |
| `sqli_9` | `information_schema.columns` projection for `aria.orders` | real sensitive order column returned |
| `sqli_10` | projection from `aria.orders` | synthetic order belonging to another workshop identity returned |
| `nosqli_1` | `{"$":"test"}` | simulator `MongoServerError`-shaped unknown-operator error |
| `nosqli_2` | `{"title":{"$gt":""}}` | broadened non-empty paper rows |
| `nosqli_3` | `{"title":{"$regex":".*"}}` | wildcard regex returns matching synthetic papers |
| `nosqli_4` | `{"$where":"db.version()"}` | actual PostgreSQL version plus explicit simulation label |
| `nosqli_5` | `{"$where":"Object.keys(this)"}` | catalog-derived papers/authors schema fields |
| `nosqli_6` | `{"title":{"$ne":"Attention Is All You Need"}}` | non-equal records beyond the equality baseline |
| `nosqli_7` | `{"$where":"this.year > 2020"}` | simulated where-branch paper rows, without a JavaScript-execution claim |
| `nosqli_8` | `{"year":{"$in":[2020,2021,2022,2023,2024]}}` | rows representing at least two requested membership values |
| `nosqli_9` | `{"email":{"$regex":".*@.*"}}` | synthetic author contact/profile fields |
| `nosqli_10` | `{"access_level":{"$ne":"public"}}` | synthetic restricted research rows outside normal scope |
