# Workshop Reliability Change Ledger

## Release scope

This is the consolidated change list for the Workshop reliability work on
`cc-no-websocket`. Secure Shop is intentionally excluded.

A **major** finding is one that stops or materially corrupts an ordinary
instructor-led demo and cannot be recovered with a page refresh, a normal
retry, or a simple administrator toggle. Minor warnings, explicitly guided
manual recovery, infrastructure/provider outages, and conditions requiring
more than four hours are not release blockers for this change set.

## Changes delivered

### Polling instead of Workshop WebSockets

- Persisted global, workshop, and attendee revision scopes in SQLite.
- Published revisions after successful state-changing admin commits.
- Covered exercise/objective visibility, hints, solutions, progress resets,
  and attendee-owned vulnerable/fixed mode state.
- Kept polling lightweight: the full configuration is reconciled only after a
  relevant revision changes.
- Paused hidden tabs, prevented overlapping checks, retained last confirmed
  state through transient failures, and backed off repeated reconciliation
  timeouts.

### Admin visibility and disclosure behavior

- Decoupled the non-prompt-injection **Solutions** master control from
  `workshop_objective_visibility`. It continues to update the master and
  workshop-specific solution gates and publish their existing revision, but it
  no longer calls the objective bulk-toggle endpoint or rewrites **Manage
  Objectives** state. Hiding solutions therefore leaves curriculum cards,
  totals, navigation, and explicit objective administration unchanged.
- Added explicit loading, visible, hidden, and retryable-error route states.
- Prevented stale route/template responses from undoing newer visibility.
- Made Indirect Prompt Injection solution disable independent of unrelated
  progress failures or delays and guarded late detail responses after abort.
- Made the Indirect Prompt Injection page consume canonical objective
  visibility for both RAG and Email Agent lists. Disabled objectives no longer
  render or count, a hidden active objective moves to the first visible one,
  and a hidden objective's pending/open solution is closed.
- Made XSS tab lists, tab/overall progress, hints, and solution disclosures
  consume the same canonical objective snapshot, including neutral all-hidden
  behavior.
- Applied canonical visibility guards to the SQL, NoSQL, and primary Sensitive
  Information routes so refresh/direct navigation cannot bypass an admin
  exercise disable.
- Made SQL and NoSQL objective lists, visible completion totals, and solution
  modals consume their canonical configuration snapshots.
- Made CSRF, MCP, Excessive Agency, Sensitive Information, and Supply Chain
  objective cards, selection, completion totals, and disclosures consume
  canonical effective visibility. CSRF payloads and prerequisites now use the
  same visible set on both client and server.
- Filtered Excessive Agency progress metadata and the attendee activity timeline
  by effective visibility while preserving visible MCP activity through its
  challenge-key alias.
- Made zero-objective exercises non-navigable on the dashboard and omitted them
  from the navbar menu while preserving their canonical Locked card.
- Made CSRF tab reset clear canonical completions and working payload solutions
  honor the effective master solution gate. MCP scoring, progress, and manual
  recon completion now exclude hidden objectives server-side.
- Made Sensitive Information hints independently controllable from solutions,
  and associated each exact category placeholder with its owning objective.
- Made Supply Chain solution-modal hints follow their independent objective
  hint gate instead of inheriting solution visibility.

### Attendee isolation

- Scoped SQL/NoSQL fallback caches, completion state, chat, drafts, message
  IDs, loading, and solution modals to the authenticated attendee generation.
- Made XSS Workshop use one JWT-first durable attendee identity, with session
  self-healing and local-only anonymous compatibility.
- Replaced shared Sensitive Information simulator state with attendee-owned
  data, backups, deletion state, and logs.
- Serialized same-attendee Sensitive chat and reset operations while allowing
  different attendees to proceed concurrently.
- Partitioned the complete Excessive Agency five-persona graph by authenticated
  platform attendee while preserving intentional cross-persona BOLA inside each
  partition; lab tokens, conversations, progress, destructive targets, and
  resets now remain attendee-owned.

### Truthful student reset

- Replaced dashboard reset's partial per-lab cleanup with the authoritative
  shared reset service used by targeted administration.
- Supply Chain dashboard reset now clears `sc_progress` and central progress.
- Sensitive Information reset clears FinFlow progress, per-user tool logs,
  auxiliary rows, central progress, and simulator state under the attendee
  queue.
- MCP reset clears per-user progress, activity, central progress, and the
  canonical `mcp_<userId>` sandbox/listener state while preserving every other
  attendee.
- Indirect Prompt Injection reset also clears the selected attendee's current
  in-memory RAG document session and truthfully reports post-commit failure.
- Preserved CSRF wallet/tool-log reset behavior and Direct Prompt Injection's
  dedicated middleware.
- The generic Excessive Agency dashboard reset retains an explicit manual-reset
  response; the attendee-owned in-lab **Reset Progress** control authoritatively
  reseeds that attendee's graph instead of reporting partial success.

### Documentation and regression protection

- Added focused RED-to-GREEN coverage for revision publishing, timeout
  recovery, route error/retry behavior, disclosure races, route wiring,
  cross-attendee state, identity recovery, and authoritative resets.
- Added load-on-demand module documents for Sensitive state, XSS identity,
  route visibility, SQL/NoSQL cache ownership, polling load, and student reset
  ownership.
- Preserved intentional curriculum vulnerabilities and excluded runtime
  SQLite/WAL/SHM files from source commits.

## Logical commits before the final major-review cycle

| Commit | Change |
|---|---|
| `4e628dd` | Admin visibility propagation, disclosure reconciliation, and polling resilience |
| `f73e086` | Sensitive Information attendee isolation and reset ordering |
| `c76b641` | XSS Workshop durable identity |
| `4d23f69` | SQL/NoSQL attendee-scoped cache, chat, and modal ownership |

The final direct-route and dashboard-reset fixes are committed after the
repeated blind-review gate passes.

## Verification baseline

Across the pre-final and final blind-review cycles, the branch passed:

- combined frontend behavior: 180/180;
- sequential backend Workshop reliability group: 145/145;
- XSS identity HTTP integration: 9/9;
- SQL/NoSQL real-component identity behavior: 38/38;
- focused Indirect Prompt Injection reconciliation: 7/7;
- final combined frontend behavior: 180/180;
- final XSS objective-visibility component behavior: 3/3 after a 3/3 RED
  reproduction;
- final sequential backend reliability group: 145/145;
- authoritative reset and workshop-owner group: 95/95, with the loopback MCP
  smoke rerun separately outside the sandbox and passing;
- final loopback MCP/XSS integration: 10/10 (MCP sidecar-dependent checks were
  honestly skipped while sidecars were offline);
- final custom objective-consumer contract: 10/10 after focused RED
  contradictions covering CSRF reset/payload ownership, activity aliasing,
  Excessive Agency response filtering, and Sensitive OOB guidance;
- final sequential Workshop backend regression group: 242/242, with its one
  sandbox-restricted system probe rerun outside the sandbox and passing;
- final full frontend regression: 180/180;
- final XSS durable-identity HTTP integration: 9/9 outside the loopback-
  restricted sandbox;
- post-fix CSRF HTTP smoke: 39/39;
- post-fix MCP smoke: 9/9, with sidecar-dependent real-effect checks explicitly
  skipped while the optional sidecars were offline;
- production React build, server syntax, and `git diff --check`;
- normal `start_all.sh` startup, `admin/admin123` login, admin Exercise
  Management, attendee dashboard, and SQL/NoSQL/Sensitive/Indirect PI route
  navigation, with frontend and backend health returning HTTP 200.

The first combined backend invocation ran DB-owning test files concurrently and
produced SQLite lock noise. The same group passed 145/145 with
`--test-concurrency=1`, and the mutation test passed alone. This is runner
contention rather than an application failure.

Final route, objective-visibility, reset, and repeated blind-review outcomes are
recorded in this file before merge. The closing independent reviews of the
CSRF/MCP, Excessive Agency/navigation/activity, and Sensitive/Supply paths each
reported no remaining deterministic major ordinary-demo issue.

## Accepted recoverable conditions

- A transient poll/reconciliation failure retains the last confirmed UI and is
  recoverable by refresh or the next successful poll.
- The initial visible polling wave is randomized but not server-coalesced;
  further load changes require production measurement.
- Sensitive simulator queues are process-local. Durable cross-process global
  reset ordering is outside this minimal single-process demo fix.
- Existing React development warnings, stale Browserslist metadata, and
  provider/infrastructure availability are not application-behavior blockers.

## Major-issue release gate

Independent blind reviews cover admin propagation, attendee identity/reset
ownership, and the ordinary Workshop journey. An accepted major finding must
receive a failing test first, a minimal fix, updated module documentation, and
another blind review. Merge is allowed only when the repeated review produces
no remaining major finding.
