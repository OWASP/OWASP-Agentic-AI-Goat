# Tests and Verification

## Test stacks

The repository uses several independent test styles:

- Node's built-in `node:test` for modern SecureShop tests;
- standalone Node scripts and ad-hoc assertions for legacy/workshop APIs;
- Puppeteer for SecureShop browser smoke/E2E flows;
- verification scripts for schema and intentional-vulnerability coverage;
- isolated PostgreSQL and native/browser qualifiers for supported local operation.

The root `npm test` currently aliases only `test:secureshop`; it is not the full
repository test suite.

## SecureShop test pyramid

| Directory | Scope |
|---|---|
| `tests/secureshop/unit` | providers, sessions, streaming, vector/trace, supervisors, manifests, MCP pool, every task tool |
| `tests/secureshop/integration` | DB schema, auth, routers, Agent Host boot, MCP transport, supervisors, RBAC |
| `tests/secureshop/vuln/web` | classic web vulnerability proofs |
| `tests/secureshop/vuln/llm` | LLM Top 10 behavior proofs |
| `tests/secureshop/vuln/mcp` | MCP supply-chain/transport/credential/SSRF/impersonation proofs |
| `tests/secureshop/vuln/chains` | multi-hop attack chains |
| `tests/secureshop/vuln/parity` | provider-independent exploit parity |
| `tests/secureshop/e2e/vuln-flows` | real HTTP/browser exploit flows |
| `tests/secureshop/e2e/puppeteer-smoke.js` | broad UI navigation smoke |

Fixtures in `tests/secureshop/fixtures` boot temporary isolated stacks, fake
providers and external MCP servers. `_fixture.js` and parity harnesses centralize
vulnerability setup. Preserve their environment-path overrides when changing
DB or singleton construction.

## SecureShop commands

```text
npm run test:secureshop
npm run test:secureshop:unit
npm run test:secureshop:integration
npm run test:secureshop:vuln
npm run test:secureshop:chains
npm run test:secureshop:parity
npm run test:secureshop:e2e
npm run test:secureshop:e2e:smoke
npm run verify:secureshop
```

`verify:secureshop` combines schema and vulnerability-coverage verification.

## Intentional-vulnerability contract

`scripts/generate-vuln-map.js` scans code/test annotations to build the
SecureShop vulnerability map. `verify-secureshop-vuln-coverage.js` ensures
documented vulnerability IDs have implementation and proof coverage. Therefore:

- an annotation is part of runtime curriculum metadata;
- a proof test documents desired insecure behavior;
- failing a vulnerability test may mean a teaching sink was accidentally
  removed, not that the application became “better”;
- a deliberate redesign must update code, tests, and generated documentation
  together.

## Platform/workshop tests

| Test/script group | Coverage |
|---|---|
| `tests/api.test.js`, `comprehensive-test.js` | broad platform API/initialization |
| `tests/adminExploitation.test.js` | admin behavior/security demonstration |
| `tests/frontend.test.js` | frontend build/static expectations |
| `tests/promptInjection*.test.js` | direct PI service/router/CTF behavior |
| `tests/sql*.test.js` | SQL workshop/pipeline/objectives/payloads |
| `tests/nosql*.test.js` | NoSQL workshop/full pipeline |
| `tests/sensitiveInfoWorkshop.test.js` | FinFlow flows |
| `tests/supplyChainWorkshop.test.js` | CodeBot flows |
| `tests/csrfWorkshop.smoke.test.js` | CSRF workshop smoke |
| `tests/mcpWorkshop.smoke.test.js` | MCP route/tool smoke |
| `tests/ctf*.smoke.test.js` | CTF admin/hint/AI behavior |
| `tests/progressAnalytics.smoke.test.js` | normalized admin analytics |
| `tests/solutions.test.js` | visibility/content registry |
| `tests/changeRevisionStore.test.js` | persisted global/workshop/user revision scope and restart isolation |
| `tests/changeRevisionService.test.js` | pre-snapshot global restart signal plus non-blocking bounded retry |
| `tests/changeRevisionsRoute.test.js` | authenticated polling identity and workshop-scope normalization |
| `tests/adminChangeRevision.test.js` | admin scope/alias mapping, legacy and bulk mutation coverage, failure containment, coalesced retry and recovery |
| `tests/revisionPoller.test.js` | initial-race reconciliation, receiver-safe browser timers, change-only reloads, hidden tabs and failure backoff |
| `tests/noVisibilityWebSocket.test.js` | guard that visibility socket runtime/proxy/reconnect files stay removed |
| `tests/legacyWebSocketRetirement.test.js` | ordinary-startup upgrade disables historical socket metadata without deletion |
| `tests/ctfLeaderboardRefreshCoordinator.test.js` | coalescing, failed-run retry, follow-up invalidation and singleton reconciliation |
| `tests/noCtfWebSocket.test.js` | no CTF socket runtime, read-only leaderboard GET and stage-mutation invalidation |
| `tests/workshopModeStore.test.js` | per-attendee/per-workshop mode isolation, atomic private revisions and restart persistence |
| `tests/workshopModeDefaults.test.js` | shipped vulnerable first-use default parity across all interactive labs |
| `tests/workshopModeHandlers.test.js` | authenticated mode identity, validation and vulnerable alias normalization |
| `tests/noGlobalWorkshopMode.test.js` | guards against process/instance/client-selected execution mode |
| `tests/frontendModePersistence.test.js` | persisted endpoints, chat authority, private cross-tab mode, and active-lab hint/solution reconciliation |
| `tests/workshopModeExecution.test.js` | ARIA/NOVA vulnerable payload execution versus fixed-mode literal handling |
| `tests/workshopDurableIdentity.test.js` | FinFlow/CodeBot durable progress and logs reject client-selected ownership |
| `tests/workshopObjectiveVisibilityConsumers.test.js` | canonical objective filtering for CSRF, MCP, Excessive Agency, Sensitive, Supply Chain, and attendee activity; visible-only CSRF payload/prerequisite wiring |
| `tests/excessiveAgencyAttendeeIsolation.test.js` | platform-bound lab sessions, per-attendee five-persona graphs, cross-persona BOLA preservation, destructive target/reset isolation, and bulk progress reset coverage |
| `tests/workshopRouteVisibilityWiring.test.js` | direct SQL, NoSQL, and Sensitive route exercise guards |
| `tests/sqlInjectionObjectives.test.js` | 36 explicit-mode checks spanning all ten ARIA objectives plus fixed blocking |
| `tests/sqlInjectionPayloads.test.js` | isolated seeded payload verification for all ten ARIA objectives |
| `tests/path_traversal_real.test.js`, `ssrfWorkshop.test.js` | legacy/real exploit flows |
| `tests/sensitiveInfoStateIsolation.test.js`, `sensitiveInfoResetRace.test.js` | attendee-scoped simulator state and same-user chat/reset ordering |
| `tests/xssWorkshopIdentity.test.js` | JWT-first XSS identity, MemoryStore recovery, anonymous compatibility |
| `client/src/components/VisibilityProtectedRoute*.test.js` | confirmed-hidden versus request-error behavior, retry and visibility races |
| `client/src/pages/challenges/IndirectPromptInjectionChallenge.polling.test.js` | live solution disable and stale-response modal ordering |
| `client/src/pages/workshops/SQLNoSQLProgressCache.test.js` | attendee-scoped fallback, storage failures and identity-transition races |

The consolidated Workshop reliability change list, verification evidence,
accepted recoverable conditions, and repeated blind-review release threshold
are recorded in
[18-workshop-reliability-change-ledger.md](18-workshop-reliability-change-ledger.md).

Many are executable files rather than one unified runner. Inspect the file
header/package script before assuming `npm test` includes it.

Current branch verification note: the existing ARIA suite completes 105 enabled
assertions. The existing NOVA suite's isolated database setup currently stops
inside its baseline seed because `nosql_injection_solution_visibility` is not
created before the seed writes to it; the new mode execution test creates the
fixture explicitly and verifies both NOVA paths without changing that unrelated
initializer.

The WebSocket-retirement change gate currently passes 61 focused Node tests,
36 ARIA objective assertions, 10 isolated ARIA payload checks, all server
JavaScript syntax checks, `git diff --check`, and the React production build.
The repository-wide `npm test` SecureShop gate requires dependencies absent
from this checkout; with those supplied from an isolated temporary runtime it
reaches application tests but encounters existing fixture omissions for
`mcp_tool_cache`, `agent_trace`, and `agent_sessions`. The customer-route test
then leaves its runner waiting after the fixture failure, so that unrelated
gate is not recorded as green for this branch.

## Verification and evaluation scripts

| Script | Purpose |
|---|---|
| `verify-secureshop-schema.js` | compare expected SecureShop schema |
| `verify-secureshop-vuln-coverage.js` | annotation/test/map parity |
| `generate-vuln-map.js` | regenerate SecureShop vulnerability documentation |
| `verify-prompt-injection-solutions.js` | PI solution integrity |
| `validate-direct-prompt-injection.js` | direct PI objective validation |
| `validate-rag-injection.js` | RAG objective validation |
| `verify-pr6-indirect-prompt-visibility.js` | Retired mutating SQLite repair; current visibility is managed in `/admin/exercises` |
| `csrf-verify-e2e.js`, `gen-csrf-payloads.js` | CSRF payload/end-to-end verification |
| `mcp-lab-e2e.js`, `mcp-authenticity-probe.js` | real MCP lab execution/provenance |
| `ctf-adversarial-eval.js` | CTF defense/attack evaluation |
| `lab-intent-robustness.js` | deterministic intent recognition regression |
| `db/verify-schema.js` | initialized DB schema checks |

## Infrastructure verification

Disposable PostgreSQL, browser and actual-model qualification are separate
from ordinary unit checks. Use their isolated launchers; never target an
application or learner database for disposable tests.

## Change-to-test matrix

| Change | Minimum verification |
|---|---|
| workshop UI/API | targeted workshop test + auth/progress/solutions checks |
| objective/key rename | targeted lab + progress analytics + solutions/hints + DB fresh init |
| auth/session/admin | API/admin tests, locked/session flows, frontend auth smoke |
| DB schema/seed | fresh DB in temp dir, `db/verify-schema.js`, affected integration tests |
| SecureShop REST/page | relevant unit/integration plus Puppeteer smoke |
| task tool/supervisor | tool unit, RBAC, integration, vuln proof, parity/chain if relevant |
| provider normalization | all provider units + supervisor and parity tests |
| startup/preflight | clean temporary checkout/data path plus health probes |

## 2026-08-07 higher-bar live verification

The local stack was started through `start_all.sh`, and every reversible
configuration mutation was restored to its original value:

- a non-PI admin Solutions master toggle changed the canonical solution gate
  while every objective-availability flag remained unchanged;
- IPI produced canonical Hint-only and Solution-only states, denied the
  opposite endpoint in each state, and returned zero Hint-owned entries in the
  enabled Solution response;
- two seeded platform attendees logged into the same EA persona, a lab token
  replayed with the other attendee's JWT returned `401`, and resetting attendee
  A changed the live completion counts from `1/1` to `0/1`.

The production client build succeeded. Focused and cross-module suites passed.
The broad `tests/*.test.js` sweep reached 376 tests (363 passed); 13 unrelated
environment-dependent cases could not bind local sockets, read system uptime,
or intentionally required an explicitly configured live-server environment.
Three independent post-implementation blind reviews found no deterministic
major normal-workshop regression.

## Documentation-only verification

For this code-map package, verify:

- every Markdown link resolves;
- every referenced source path exists;
- baseline commit and working tree are recorded;
- docs do not expose values from `.env` or fake/real credential files;
- source files remain unmodified.
