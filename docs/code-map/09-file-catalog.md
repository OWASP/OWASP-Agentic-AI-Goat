# File Catalog

This catalog assigns ownership to behavior-bearing files and classifies large
generated/repeated/data areas. It is optimized for locating change context,
not for duplicating each source line.

## Root

| Path | Purpose |
|---|---|
| `package.json` | backend entry, dev/build/test/DB/verification scripts and dependencies |
| `client/package.json` | CRA application dependencies and scripts |
| `start_all.sh`, `stop_all.sh` | local lifecycle |
| `docker-compose.yml` | MCP sidecars and optional full app |
| `nodemon.json` | backend development reload behavior |
| `.env.example` | configuration key reference; local `.env*` values are not documentation |
| `README.md`, `docs/*` | operator, workshop, SecureShop, security, architecture documentation |
| `CLAUDE.md` | assistant/project guidance and standing change-rule summary |
| `instructions.md` | canonical minimal-change, TDD, documentation and adversarial-review workflow |

`package-lock.json` and `client/package-lock.json` are generated dependency
resolution artifacts. Review diffs mechanically; do not load them as app logic.

## Backend composition and cross-cutting

| Path | Purpose |
|---|---|
| `server/index.js` | default Express/HTTP composition root; no application WebSocket endpoints |
| `server/secureServer.js` | alternate unreferenced secure/isolation server |
| `server/middleware/adminAuth.js` | auth, roles, permissions, lockout, audit |
| `server/middleware/eventGate.js` | live-event shared-password gate |
| `server/middleware/llmLogger.js` | LLM request ledger |
| `server/middleware/performanceMonitor.js` | runtime metrics |
| `server/middleware/rateLimiter.js` | DB-configured limiters |
| `server/middleware/requestLogger.js` | request IDs and HTTP logging |
| `server/middleware/sessionManager.js` | session/JWT lifecycle |
| `server/middleware/workshopMode.js` | legacy vulnerability enablement |
| `server/utils/logger.js` | Winston configuration |
| `server/utils/requestContext.js` | AsyncLocalStorage context |
| `server/utils/contextLogger.js` | contextual log wrapper |
| `server/utils/progressSync.js` | central workshop progress adapter |
| `server/services/changeRevisionStore.js` | persisted global/workshop/user change revision repository |
| `server/services/changeRevisionService.js` | runtime `users_auth.db` revision-store singleton |
| `server/services/changeRevisionServiceFactory.js` | initialization, global restart signal and bounded retry policy |
| `server/services/adminChangeRevision.js` | maps admin changes to global/workshop/user revision scope |
| `server/services/workshopModeStore.js` | per-attendee/per-workshop mode repository with atomic revision triggers |
| `server/services/workshopModeService.js` | runtime `users_auth.db` workshop-mode singleton |
| `server/services/workshopModeHandlers.js` | authenticated reusable mode GET/POST handlers |
| `server/database/legacyWebSocketRetirement.js` | non-destructive retirement migration for historical socket configuration |
| `server/views/monitoringHealthPage.js` | HTML monitoring view |

## Backend routers

| File | Responsibility |
|---|---|
| `routes/auth.js` | default workshop authentication/account API |
| `routes/admin.js` | all platform admin domains |
| `routes/changeRevisions.js` | authenticated lightweight polling snapshot API |
| `routes/workshop.js` | student catalog/progress/activity/time and instructor compatibility |
| `routes/solutions.js` | solution registry and layered visibility |
| `routes/hints.js` | hint registry and layered visibility |
| `routes/monitoring.js` | health/performance/LLM/log monitoring |
| `routes/ctf.js` | complete staged CTF, mutation signals and read-only leaderboard API |
| `routes/promptInjectionWorkshop.js` | direct PI workshop |
| `routes/ragInjection.js` | indirect RAG injection |
| `routes/emailAgent.js` | indirect email injection |
| `routes/xssWorkshop.js` | modern XSS workshop |
| `routes/csrfWorkshop.js` | CSRF via AI workshop |
| `routes/mcpWorkshop.js` | MCP workshop |
| `routes/excessiveAgencyLab.js` | excessive agency/BOLA workshop |
| `routes/sqlWorkshop.js` | ARIA SQL workshop |
| `routes/nosqlWorkshop.js` | NOVA NoSQL workshop |
| `routes/sensitiveInfoWorkshop.js` | FinFlow sensitive-info workshop |
| `routes/supplyChainWorkshop.js` | CodeBot supply-chain workshop |
| `routes/ai.js` | legacy AI vulnerability demos |
| `routes/ecommerce.js` | legacy vulnerable commerce API |

| `routes/challenges.js` | legacy XSS/Ollama/solution endpoints |
| `routes/vulnerabilities.js` | classic vulnerable web endpoints |
| `routes/sensitiveInfo.js` | legacy file/template/document disclosure |
| `routes/mysqlSensitiveInfo.js` | optional MySQL disclosure variant |
| `routes/xssEmail.js` | legacy XSS email-template builder |
| `routes/secureAuth.js`, `secureChallenges.js` | alternate `secureServer.js` only |
| `routes/secureshop/auth.js` | SecureShop clean v2 account/auth API |
| `routes/secureshop/_ssAuthMiddleware.js` | SecureShop JWT/role middleware |
| `routes/secureshop/customer.js` | customer REST + agent API |
| `routes/secureshop/merchant.js` | merchant REST + agent API |
| `routes/secureshop/admin.js` | admin REST + agent/ACL/system API |
| `routes/secureshop/uploads.js` | upload/download/static API |
| `routes/secureshop/email.js` | email/thread API |

The application has no WebSocket endpoint or direct `ws` dependency. `ws`
may still appear transitively in lockfiles for development tooling or SDKs;
those packages do not provide application refresh transport.

## Backend services

| File/group | Responsibility |
|---|---|
| `services/ollamaService.js` | large Ollama-specific generation/chat/tool/concurrency facade |
| `services/multiProviderAIService.js` | provider selection, fallback, health, generation and logging |
| `services/promptInjectionWorkshop.js` | direct PI messages, detectors and judging |
| `services/promptInjectionCTF.js` | payload normalization/technique/duplication logic |
| `services/ctfDefenseLayers.js` | composable CTF input/output defenses |
| `services/ctfLeaderboardRefreshCoordinator.js` | coalesced write-triggered ranking refresh plus singleton reconciliation |
| `services/ragVectorStore.js` | Xenova in-memory RAG store |
| `services/gmailEmailAgentService.js` | SMTP/Gmail send and readiness |
| `services/sharkLasersScraper.js` | temporary-email polling/scraping |
| `services/csrfVictimSandbox.js` | persistent simulated victim state |
| `services/csrfWorkshopAgent.js` | CSRF intent/action/objective agent |
| `services/excessiveAgencyToolRouter.js` | vulnerable/fixed lab tools |
| `services/ariaAgentService.js` | SQL lab conversational tool router |
| `services/novaAgentService.js` | NoSQL lab conversational tool router |
| `services/sensitiveInfoWorkshopAgent.js` | FinFlow/VaultCorp agent and fake-file tools |
| `services/supplyChainWorkshopAgent.js` | CodeBot tools/objective detection |
| `services/mcp/config.js` | MCP sidecar endpoints |
| `services/mcp/_probes.js` | health probe primitive |
| `services/mcp/ecsMetadata.js` | ECS/local target discovery |
| `services/mcp/mailClient.js` | Mailpit SMTP/API client |
| `services/mcp/mcpSidecarSupervisor.js` | Docker sidecar lifecycle |
| `services/mcp/sandboxRunnerClient.js` | sandbox HTTP client |
| `services/mcp/sandboxShell.js` | MCP lab tool/session/exfil implementation |
| `services/mcp/targets.js` | SSRF/rogue-target adapter |
| `services/mcp/workshopAgent.js` | MCP conversational agent |
| `services/mcp/sdk/*` | vulnerable MCP SDK server/session transport |
| `services/secureshop/index.js` | SecureShop boot/composition |
| `services/secureshop/agentHostSupervisor.js` | Agent Host child lifecycle |
| `services/secureshop/mcpClientPool.js`, `mcpTransport.js` | MCP client transport/pool |
| `services/secureshop/providerRouter.js`, `providers/*` | SecureShop provider abstraction/adapters |
| `services/secureshop/sessionStore.js` | agent conversation/token persistence |
| `services/secureshop/streaming.js` | SSE writer |
| `services/secureshop/toolManifest.js` | tool discovery/cache/role/external prompt block |
| `services/secureshop/toolAcl.js` | Layer-B role/tool ACL |
| `services/secureshop/trace.js` | supervisor trace writer |
| `services/secureshop/vectorStore.js` | persistent multi-provider vector index |
| `services/secureshop/supervisors/*` | customer/merchant/admin LLM-tool loops, base prompt and policies |

Sensitive Information simulator state is attendee-scoped and process-local;
load `12-sensitive-info-state-isolation.md` before changing its tool execution
or reset boundaries. XSS identity precedence and restart recovery are mapped in
`13-xss-workshop-identity.md`.

Custom objective consumers (CSRF, MCP, Excessive Agency, Sensitive
Information, and Supply Chain) use the shared Workshop configuration snapshot
instead of treating their static curriculum arrays as attendee-visible state.
`tests/workshopObjectiveVisibilityConsumers.test.js` guards those boundaries
and the visibility-filtered attendee activity feed.

## Database runtime modules

| File | Responsibility |
|---|---|
| `database/sqliteTuning.js` | global sqlite3 WAL/busy-timeout patch |
| `database/authDb.js` | users_auth connection, schema/migration/default/security utilities |
| `database/init.js` | legacy owasp-ai-goat DB |
| `database/adminSchema.js`, `initAdmin.js` | legacy/admin schema/default init |
| `database/ctfDb.js` | CTF schema/migrations/seeds |
| `database/secureshop.js` | baseline SecureShop tables |
| `database/sensitiveInfoDb.js` | disclosure DB and fixture creation |
| `database/sensitiveInfoWorkshopDb.js` | FinFlow DB |
| `database/mysqlSensitiveInfoDb.js` | optional MySQL DB |
| `database/xssWorkshopDb.js`, `xssEmailDb.js` | XSS stores |
| `database/csrfWorkshopDb.js` | CSRF store |
| `database/mcpWorkshopDb.js` | MCP store |
| `database/excessiveAgencyLabDb.js` | excessive agency store/action API |
| `database/sqlWorkshopDb.js` | ARIA data operations |
| `database/nosqlWorkshopDb.js`, `nosqlWorkshopData.js` | NOVA data/operators and fixtures |
| `database/supplyChainWorkshopDb.js` | supply-chain store |
| `database/platformDb.js`, `challengeDb.js`, `secureDbManager.js` | alternate secure-server DB isolation |
| `database/deploymentInit.js`, `freshDeployment.js`, `comprehensiveInit.js` | legacy deployment/reset orchestration |
| `database/seedWorkshopUsers.js`, `bsides_users.json` | event/team account seeding |

Runtime `.db`, `-wal`, and `-shm` files are mutable/generated state, even when
fixtures are tracked. Do not treat their binary contents as source.

## Server data and fixtures

`server/data/*.js` is curriculum content: per-workshop solutions, hints, CSRF
payloads, and CTF solutions. `server/assets/*`, `server/workshop_data/*`, and
`server/sensitive_files/*` are controlled fake documents/credentials/payloads
consumed by labs. `server/platform_secrets.json` and `server/config/secrets.env`
are teaching fixtures/config; never substitute real credentials.

## Workshop frontend files

| File/group | Responsibility |
|---|---|
| `client/src/index.js`, `App.js`, `setupProxy.js` | render, route composition, dev proxy |
| `context/AuthContext.js` | workshop identity |
| `context/ShopAuthContext.js` | legacy shop identity wrapper |
| `components/ErrorBoundary.js` | render failure boundary |
| `components/WorkshopNavbar.js` | platform navigation |
| `components/VisibilityProtectedRoute.js` | challenge visibility guard |
| `components/VulnerabilityTemplate.js` | common lab page shell/objectives |
| `components/HintPanel.js`, `SolutionPanel.js` | content disclosure panels |
| `hooks/useChangePolling.js` | authenticated scoped polling with mandatory baseline reconciliation |
| `services/revisionPoller.js` | framework-independent polling cadence/comparison/backoff engine |
| `hooks/useWorkshopHeartbeat.js` | active time heartbeat |
| `pages/LandingPage.js` | platform landing |
| `pages/WorkshopLogin.js`, `WorkshopSignup.js` | workshop auth UI |
| `pages/WorkshopDashboard.js`, `WorkshopChallenges.js` | overview/detail |
| `pages/UserProfile.js`, `EditProfile.js`, `UserActivity.js` | account/activity |
| `pages/ComprehensiveAdminDashboard.js` | platform admin integration shell |
| `components/admin/*`, `pages/admin/*` | provider/log/student, CTF and analytics admin modules |
| `pages/challenges/*` | direct PI, indirect PI, XSS, CSRF, MCP, excessive agency |
| `pages/workshops/*` | SQL, NoSQL, FinFlow, supply chain |
| `pages/CTF*.js`, `ctfObjectives.js` | CTF student UI/static objective copy |
| `pages/labs/AIAssistant.js` | legacy commerce AI lab |
| `index.css`, `styles/WorkshopAuth.css` | global/workshop auth styling |

For visibility request ownership and nested-template behavior, load
`14-visibility-route-state.md`. For SQL/NoSQL progress fallback and
cross-identity disclosure ownership, load `15-sql-nosql-progress-cache.md`.
For revision timeout backoff and the intentionally unoptimized initial polling
wave, load `16-polling-load-safeguards.md`.
For authoritative dashboard reset ownership, load
`17-student-dashboard-reset-ownership.md`. For the consolidated change list,
verification baseline, accepted recoverable conditions, and major-issue release
gate, load `18-workshop-reliability-change-ledger.md`.

## SecureShop frontend files

| Group | Responsibility |
|---|---|
| `pages/secureshop/context/*` | current auth, cart and toast state |
| `pages/secureshop/hooks/useAgentStream.js` | agent chat/SSE/trace state |
| `pages/secureshop/components/Shell.jsx`, `TopNav.jsx`, `Footer.jsx` | application chrome |
| `components/AgentAssist.jsx`, `AgentLane*` | assistant and trace visualizations |
| remaining `components/*.jsx` | UI primitives, cards, forms, dialogs, auth guard, upload |
| customer `pages/*.jsx` | landing/home/catalog/product/cart/checkout/orders/account/inbox/auth/404 |
| `pages/merchant/*.jsx` | overview/listings/reviews/pricing/analytics/inbox |
| `pages/admin/*.jsx` | overview/users/audit/policies/MCP/system/access control |
| `pages/secureshop/theme.css` | subsystem design tokens/styles |

## Agent Host files

| Group | Responsibility |
|---|---|
| `agent-host/index.js`, `package.json`, `config/*` | Agent Host process and defaults |
| `shared/db.js`, `callerContext.js`, `trace.js`, `vectorStore.js` | DB, caller policy, trace, vector sharing |
| `agents/_template/server.js` | new-agent skeleton |
| `agents/*/server.js` | MCP registration/metadata/context wrapper |
| `agents/product-search/tools/*` | search/similar/feed |
| `agents/summarizer/tools/*` | product/review/file/policy summaries |
| `agents/price-advisor/tools/index.js` | price/deals/competitor tools |
| `agents/cart/tools/index.js` | cart/coupon tools |
| `agents/support/tools/index.js` | ticket/order/refund tools |
| `agents/listing/tools/*` | CRUD/rewrite/template/import/image optimization |
| `agents/inventory/tools/index.js` | stock tools |
| `agents/pricing-strategy/tools/index.js` | suggestion/experiment tools |
| `agents/review-moderator/tools/index.js` | review moderation |
| `agents/analytics/tools/index.js` | NL query/revenue/product analytics |
| `agents/user-management/tools/index.js` | user admin and audit writes |
| `agents/audit/tools/index.js` | audit search/summary |
| `agents/system/tools/index.js` | health/config/process diagnostics |
| `agents/policy/tools/index.js` | policy read/update/apply |
| `agents/mcp-registry/tools/index.js` | external MCP registry/import/history |
| `agents/uploads/tools/index.js` | upload/download/text/vector operations |
| `agents/email/tools/index.js` | email rendering/send/inbox/summary/reply |

## DB source tree

`db/initialize-db/run-all.js` is the coordinator. `schemas/01..21` define the
16 DBs and additive SecureShop migrations. `seeds/01..22` provide identities,
workshop metadata/content, CTF stages, lab fixtures, SecureShop bulk business
data, agent state, vectors/ACL prerequisites. `db/verify-schema.js` verifies the
result. See the data-model file for exact ownership.

## Scripts

| Group | Responsibility |
|---|---|
| `scripts/lib/preflight.sh` | self-healing launch prerequisites |
| `scripts/install/*` | OS-specific setup/start |
| `scripts/admin/*` | account/config repair |
| `scripts/deploy-fresh.js` | legacy init/reset CLI |
| `scripts/seed-*`, `sync-*` | data/vector/content synchronization |
| `scripts/generate-*` | vulnerability map, workshop PDF, payloads |
| `scripts/verify-*`, `validate-*`, `*-e2e.js`, `*-probe.js`, `*-eval.js` | focused regression/evaluation tools |
| `scripts/demo-screenshots/*` | static documentation/demo images |

## Sidecars

- `sidecars/sandbox-runner`: Express execution service, entrypoint, Dockerfile,
  isolation test, and fake `labfs` tree.
- `sidecars/ssrf-target`: controlled SSRF service and image.
- `sidecars/rogue-mcp`: controlled malicious MCP service and image.

## GitHub workflows

`.github/workflows` retains schema and SecureShop verification workflows. The
former AWS deployment and S3 backup workflows have been removed.

## Tests

`tests/secureshop` is the structured modern pyramid; root `tests/*.js` are
platform/workshop/legacy suites. See `08-testing-and-verification.md` for the
complete ownership and command map.
