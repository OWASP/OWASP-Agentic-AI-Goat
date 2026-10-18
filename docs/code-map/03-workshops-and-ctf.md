# Workshops, Challenge Labs, and CTF

## Shared workshop contract

Every modern workshop spans at least five concerns:

```text
React page
  → Express workshop router
    → lab service/tool router
      → lab DB and/or external AI/infrastructure
    → lab-specific progress/audit
    → progressSync → central workshop progress
  → solutions.js / hints.js → admin-controlled content
```

The challenge key shown in the catalog, workshop key stored in central
progress, objective IDs stored by the lab, and solution/hint IDs must match.
Every attendee lab that renders admin-controlled hints or solutions subscribes
to that same workshop key through `useChangePolling`; a matching revision
refetches only the visibility status while unrelated attendee revisions remain
isolated. Direct and Indirect PI visibility mutations publish a scoped app
revision from both the canonical exercise routes and compatibility routes, but
only after the configuration mutation reports a change. No-op and rejected
mutations publish nothing; revision-recording failures use the recorder's retry
path without changing the successful admin response. This lets an already-open
IPI page refetch effective solution status and content, and close a solution
that was just disabled. IPI solution disclosure keeps one current owner across
both loading and open states. Reconciliation checks that owner when refreshed
visibility commits, so a request started after polling began is still
invalidated if its objective has become hidden and its late response cannot
reopen the modal. The IPI reconciler settles solution visibility, RAG progress,
and email progress independently: a successful hidden solution status closes
its pending or open disclosure even when either unrelated progress read fails.
A failed progress domain retains its last rendered state, while the callback
still rejects after successful domains commit so the shared revision poller
retries rather than absorbing the changed baseline. Abort ownership is checked
both after solution status and after any optional solution-detail refresh, so
neither a late status nor late detail response can commit visibility or modal
content after reconciliation has been cancelled.
Dedicated per-lab bulk solution actions record the same workshop revision as
individual objective changes. The revision service canonicalizes the catalog
aliases `reflected_xss_llm`, `csrf_prompt_injection`, and `mcp_server_rce` to
the workshop keys used by open attendee tabs; legacy challenge update/reset
actions signal the global scope.
The platform system reset follows the same post-mutation rule for challenge
settings: it records that global challenge-visibility revision only when the
canonical reset reports `changed: true`; an already-reset configuration remains
a successful no-op without waking attendee pollers.

## Workshop relationship map

| Lab | Frontend | API router | Core service | DB/state | Content |
|---|---|---|---|---|---|
| Direct prompt injection | `DirectPromptInjectionChallenge.js` | `promptInjectionWorkshop.js` | `promptInjectionWorkshop.js`, multi-provider AI | `users_auth.db`: `prompt_injection_progress` + central progress | `data/promptInjectionSolutions.js`, hints |
| Indirect PI: RAG | half of `IndirectPromptInjectionChallenge.js` | `ragInjection.js` | `ragVectorStore.js`, multi-provider AI | in-memory vector sessions + `rag_injection_progress` | `data/indirectPromptInjectionSolutions.js`, RAG samples |
| Indirect PI: email | other half of same page | `emailAgent.js` | Gmail agent, SharkLasers scraper, multi-provider AI | `email_agent_progress`, sent-email log | scenarios plus indirect PI solutions |
| XSS workshop | `XSSWorkshop.js` | `xssWorkshop.js` | multi-provider AI, Gmail, SharkLasers | `xss_challenge.db` plus auth progress | `data/xssWorkshopSolutions.js`, hints |
| CSRF via AI | `CSRFWorkshop.js` | `csrfWorkshop.js` | `csrfWorkshopAgent.js`, `csrfVictimSandbox.js`, Gmail/RAG | `csrf_workshop.db` and persistent victim state in auth DB | CSRF payload/data modules and samples |
| MCP server lab | `MCPWorkshop.js` | `mcpWorkshop.js` | `services/mcp/*` | `mcp_workshop.db`, per-session sandbox/listener state | `data/mcpWorkshopSolutions.js`, hints |
| Excessive agency/BOLA | `ExcessiveAgencyBolaLab.js` | `excessiveAgencyLab.js` | `excessiveAgencyToolRouter.js` | `excessive_agency.db` | `data/excessiveAgencySolutions.js` |
| SQL injection (ARIA) | `SQLWorkshop.js` | `sqlWorkshop.js` | `ariaAgentService.js` | `sql_workshop.db` | SQL workshop solution data |
| NoSQL injection (NOVA) | `NoSQLWorkshop.js` | `nosqlWorkshop.js` | `novaAgentService.js` | `nosql_workshop.db` | NoSQL workshop solution/data modules |
| Sensitive info (FinFlow) | `SensitiveInfoWorkshop.js` | `sensitiveInfoWorkshop.js` | `sensitiveInfoWorkshopAgent.js` | `sensitive_info_workshop.db`, fake sensitive files | `data/sensitiveInfoSolutions.js` |
| Supply chain (CodeBot) | `SupplyChainWorkshop.js` | `supplyChainWorkshop.js` | `supplyChainWorkshopAgent.js` | `supply_chain_workshop.db` | `data/supplyChainSolutions.js`, hints |
| Prompt-injection CTF | three CTF pages | `ctf.js` | `ctfDefenseLayers.js`, `promptInjectionCTF.js`, multi-provider AI | `ctf.db` | `data/ctfSolutions.js`, DB-seeded stages |

## Direct prompt injection

The router exposes health/provider status, chat, progress, interaction credit,
completion, and reset. The service builds objective-aware conversations,
filters rejected exchanges, detects seven attack styles, and can use an LLM
judge to validate success. Progress is isolated by a user key and synchronized
to the central tables. The page controls objective selection, examples,
conversation history, hints, solutions, and reset.

## Indirect prompt injection

The attendee page derives both its RAG and Email Agent objective lists from the
`indirect_prompt_injection` entry in `WorkshopConfigContext`. RAG IDs map
directly to the canonical catalog; the email page's numeric progress keys map to
the canonical `email_*` configuration IDs. Snapshot revisions remove disabled
objectives without a browser refresh, exclude them from progress totals, move a
hidden active RAG objective to the first visible objective (or none), and close
any pending or open solution owned by an objective that became hidden. An
all-hidden objective set remains a usable shared lab workflow with a neutral
`0 of 0` objective summary and no false completion state.

RAG objective help is split into independent disclosure planes. Canonical
`hintVisible` renders the shared `HintPanel`, which reads
`/api/hints/indirect_prompt_injection/:objectiveId` and invalidates pending or
open content on revision changes. The IPI solution API and modal no longer own
progressive hint content, so all four Hint/Solution combinations remain valid.
Email objectives have no authored canonical hint content and therefore render
no inactive Hint control.

### RAG path

`ragInjection.js` accepts uploads, chunks/embeds them into an in-memory session,
queries retrieved context, detects injection/bypass objectives, and provides
session cleanup/health/progress. `ragVectorStore.js` lazily loads Xenova
embeddings and performs similarity retrieval. Initialization is backgrounded at
server boot, so endpoints can return 503 while the model is unavailable.

### Email path

`emailAgent.js` initializes Gmail when configured, saves/sends/fetches messages,
scrapes SharkLasers, summarizes untrusted email content, detects injected
instructions in the response, and tracks five objectives. Gmail is optional;
the health/retry surface lets the page degrade visibly.

## XSS workshop

The page presents four tabs and intentionally renders/propagates unsafe data in
specific places. The router provides profile state, chat/tool execution,
email delivery, progress, per-tab/all resets, and LLM status. It parses tool
calls from model text, executes XSS-related actions, detects payloads, records
email/profile/progress rows, and synchronizes central objectives.

The page derives each tab's attendee-visible objectives and all progress
denominators from the canonical `xss_workshop` configuration snapshot. A
snapshot revision removes a disabled objective without refresh, excludes its
stored completion from tab/overall totals, unmounts its hint, and invalidates
any pending or open solution disclosure it owned. A tab or workshop with no
enabled objectives displays neutral `0/0` progress and never reports false
completion. The underlying intentionally vulnerable exercise workflows remain
available for any objectives the instructor leaves enabled.

Do not confuse it with `xssEmail.js` (legacy email-template builder) or
`vulnerabilities.js` (classic reflected/stored XSS endpoints).

## CSRF via AI

The CSRF lab has four vector/state domains: direct agent actions, HTML payloads,
email, and poisoned RAG. `csrfVictimSandbox.js` persists a per-session simulated
wallet/profile/security state. `csrfWorkshopAgent.js` combines deterministic
intent/action detection with optional LLM phrasing. The router coordinates
payload templates, event streams, victim state, Gmail/RAG actions, defense and
chat toggles, objective classification, progress, and activity.

The attendee page derives each tab's objective list, badges, progress totals,
payload selection, hints, and solution disclosure from the canonical
`csrf_workshop` snapshot. When an objective is disabled, disclosures and loaded
payloads it owns are invalidated. The payload endpoint rejects hidden
objectives, and server prerequisites use the same visible order, so hiding an
earlier objective cannot strand a later visible one.
Working payload solutions use effective master/per-objective solution
visibility, and tab reset removes both local and canonical completion rows.

`server/assets/csrf_samples/*` contains skeleton and solution HTML. These are
curriculum fixtures, not production templates.

## MCP workshop and sidecars

`mcpWorkshop.js` exposes:

- infrastructure health/discovery;
- a tool catalog;
- vulnerable JSON-RPC/MCP session dispatch;
- guided chat;
- progress/activity reset;
- exfil and listener endpoints.

`services/mcp/` divides responsibility:

| File/group | Responsibility |
|---|---|
| `config.js` | sidecar URLs/timeouts |
| `mcpSidecarSupervisor.js` | local Docker auto-start/status/stop |
| `sandboxRunnerClient.js` | remote command/reset/health client |
| `sandboxShell.js` | session state, tool catalog/handlers, exfil/listener logic |
| `sdk/*` | per-session vulnerable MCP SDK server/transport |
| `mailClient.js` | SMTP/Mailpit sending and message retrieval |
| `targets.js` | SSRF and rogue MCP target routing |
| `workshopAgent.js` | intent/objective detection and tool dispatch |

Docker Compose supplies `mcp-sandbox`, `mailpit`, `ssrf-target`, and
`rogue-mcp`; their implementation is in `sidecars/` or the upstream Mailpit
image.

The MCP page filters cards, focus, completion totals, hints, and solutions by
the canonical `mcp_workshop` snapshot. Losing visibility moves focus to the
first visible objective (or none) and removes hidden-objective disclosures.
The API applies the same effective set before scoring, returning progress, or
accepting the recon completion endpoint, so hidden objectives cannot be
completed or announced by normal chat.

## Excessive agency/BOLA

The lab keeps its five selectable demo personas, but the complete mutable lab
graph is partitioned by the authenticated platform attendee. A partition owns
its own seeded users, notes, orders, refunds, audit, progress, conversations,
and database-bound tool router. Cross-persona BOLA remains intentionally
possible inside that partition; destructive actions and resets cannot consume
another attendee's exercise targets or progress.

Lab-session tokens are bound to the platform attendee that created them and
every session-backed route validates both identities. `excessiveAgencyLab.js`
owns login/logout/me, reset, welcome/chat, direct data inspection, progress,
conversation state, stats, and tool catalog. The shared
`excessiveAgencyAttendeeLabStore.js` owns attendee partitions and session
bindings. `excessiveAgencyToolRouter.js` receives its partition database and
changes validation/authorization according to the request's stored mode.

The attendee objective panels and progress response use the canonical
`excessive_agency` gates. Hidden curriculum metadata and completion keys are
not returned by the normal progress request.

## ARIA SQL and NOVA NoSQL

Both labs share the same outer shape: mode, LLM status, chat, progress,
completion, reset, history, and solution status/content.

- ARIA detects shopping intents and calls methods in `sqlWorkshopDb.js`. The
  vulnerable mode constructs exploitable SQL while the fixed mode uses safer
  behavior. Tables cover products, cart, orders, receipts, and chat history.
- NOVA detects research-library intents and calls `nosqlWorkshopDb.js`, which
  parses Mongo-like operators over SQLite-backed documents. The vulnerable
  path accepts unsafe operators; fixed mode constrains them. Tables cover
  papers, authors, reading lists, and chat history.

Both services use deterministic fallbacks when provider output is missing or
cannot be parsed, which is important for reliable objective demonstrations.
Their mode endpoints use `workshopModeStore`; ARIA/NOVA execution receives the
stored mode explicitly instead of reading process-global environment state.

## Sensitive information workshop (FinFlow)

`sensitiveInfoWorkshopAgent.js` is a large stateful tool simulator. It builds
objective-specific system prompts, detects/judges objectives, implements fake
FinFlow/VaultCorp tools, resolves paths into curated sensitive fixtures,
generates fake PDFs, and exposes provider/tool metadata as curriculum.
The route initializes users, chats, returns progress, and resets state. The DB
stores file registry/extractions, tool logs, chat history, progress,
achievements, and solution content/visibility.
The page filters objective cards, target selection, progress totals, solution
modal, suggestion payloads, and objective-specific OOB guidance through the
canonical `sensitive_info_disclosure` snapshot.
Independent hint visibility renders `HintPanel` without requiring solutions;
solution-modal hint material is suppressed when that objective's hint gate is
off. Category placeholders are owned by one visible, solution-enabled
objective so they cannot reveal a hidden neighbor's working prompt.
FinFlow and the Supply Chain/CodeBot lab both load and save per-attendee mode
through `/mode`. Chat ignores any client-supplied mode and derives execution
mode from the authenticated attendee's persisted setting. Their init, chat,
progress, tool-log, completion, and reset ownership also comes from that
authenticated identity; compatibility-shaped client user IDs are ignored.
ARIA, NOVA, Excessive Agency, FinFlow, and CodeBot open tabs poll their scoped
revision snapshot and reconcile displayed mode plus solution visibility;
CodeBot also reconciles separately controlled hints. Chat responses reconcile
the displayed mode from server authority as an additional safeguard.

There are separate legacy disclosure APIs in `sensitiveInfo.js` and an optional
MySQL variant in `mysqlSensitiveInfo.js`; they are not the FinFlow workshop.

## Supply-chain workshop

The route initializes objective rows, returns/resets progress, checks LLM
health, and handles chat/tool selection. `supplyChainWorkshopAgent.js` detects
objectives and executes a controlled CodeBot tool catalog. The DB stores
progress and solution visibility/content.
The page filters objectives, selection/auto-advance, progress, hints, and
solutions through the canonical `supply_chain_rce` snapshot. Progressive hints
inside an enabled solution modal still follow the independent per-objective
hint gate, so enabling solutions does not disclose disabled hints.

The attendee activity endpoint joins effective objective and exercise
visibility before returning completion labels. Its reverse mapping includes
`mcp_workshop` → `mcp_server_rce`, preserving visible MCP activity while
omitting disabled curriculum.

## CTF subsystem

The CTF is intentionally outside the standard workshop objective catalog.
`ctf.js` owns:

- public config/stage definitions;
- participant registration/status;
- atomic stage start/attempt/hint accounting;
- rate limiting, visibility and enabled checks;
- AI response generation plus stage-specific input/output defenses;
- scoring, technique/payload blocklists and near-duplicate detection;
- read-only leaderboard polling and events;
- admin analytics, stage CRUD/preview, attempts, participant controls, reset;
- mutation-triggered materialized leaderboard maintenance.

`ctfDefenseLayers.js` composes blocklists, persona/instruction/transformation
guards, decoding, meta-LLM judging, and output stripping. `promptInjectionCTF.js`
normalizes/hashes payloads, classifies techniques, and detects near duplicates.
`ctfDb.js` creates/migrates all CTF tables and seeds stages/config.
`ctfLeaderboardRefreshCoordinator.js` is the singleton ranking-maintenance
boundary. Every attempt increment (including blocked and failed early returns),
registration, completion, reset, participant mutation, and admin stage CRUD
requests a refresh. Signals are coalesced, mutations arriving during
recomputation receive one follow-up, failed runs retry after five seconds, and
a 60-second server reconciliation is the safety net. The
attendee `GET /leaderboard` path never recomputes or writes.

## Legacy challenge surfaces

These are mounted and may still be used by demos/tests, but are not the modern
workshop pages:

| Route | Purpose |
|---|---|
| `ai.js` | prompt/model poisoning, adversarial, bias, membership inference, CoT, stuffing, jailbreak demos |
| `ecommerce.js` | products/reviews/cart/checkout/profile plus SQL/NoSQL AI query demos |
| `challenges.js` | XSS processing/logging, Ollama status, generic solutions |
| `vulnerabilities.js` | SQLi, XSS, CSRF, upload, traversal, command, XXE, IDOR, SSRF, session/admin bypass |
| `sensitiveInfo.js` | file read, template render, document processing, AI payload/chat, logs/stats |
| `mysqlSensitiveInfo.js` | MySQL path/SSI/combined/AI variants with SQLite fallback |
| `xssEmail.js` | legacy profile/template/preview/progress XSS builder |

Removing a legacy route requires searching frontend, scripts, and tests; lack
of a modern navigation link does not mean it has no consumers.
