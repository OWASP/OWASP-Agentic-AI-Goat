# Remaining bound admin operations

## Current reconciliation — September 20

The planning ledger below is historical; its claims that Users lookup/password reset and Access Control lack bound routes are superseded. Current source mounts `boundUserAdministration`, `boundAccessControl`, `boundPromptPolicies`, System config/diagnostic/rebuild and optional Analytics/Pricing handlers through the closed gateway. Unavailable optional services still fail closed.

| Group | Current evidence and remaining work |
|---|---|
| Users | Current full-index/browser40497 verifies role/ban, password reset with credential/session retirement and acknowledgment, synthetic owned lookup, and exact operation readbacks. All four original operations now have source/runtime/browser support. Installed activation and broader lifecycle evidence remain separate. |
| Access Control | Current full-index/browser40497 verifies four policy mutations, receipt reads, refreshed state and restoration. Earlier actual Audit actor/Judge evidence is retained in `tasks/secureshop-bound-acl-audit-actual-recovery-2026-09-20.json`. New task agents must join the same authoritative policy registry and execution boundary. |
| Policies | Canonical0027 and composed real-browser/renderer evidence exist. Task consumption, actual-model contrast and installed activation have distinct scopes; do not infer new objective credit from an intentionally unavailable Judge. System policy-corpus0019 integration is still underway. |
| System | Config, diagnostic and rebuild have owned implementations. Real first-index0018 proof exists. Restart has an isolated Linux effect/process proof; candidate0020 persistence/composition and release are still underway. |
| MCP management | Persisted discovery tools GET is now mounted with scoped admin fences; native full-index/query/HTTP and settled browser43611 pass, including contained horizontal scrolling and schema metadata (`tasks/secureshop-mcp-tools-rendered-current-2026-09-20.json`). Register/import/delete remain absent from the bound gateway. Existing MCP trust discovery/rotation and registry/history observations do not implement these operations. Preserve the four-operation gap until owned registry effects, graph consumption and lifecycle are delivered. |
| Generic admin chat | Purpose-specific Audit workflows do not close the generic supervisor gap. |

Primary current Users evidence: `tasks/secureshop-users-enabled-rendered-2026-09-20.json` (2054 independently verified frozen files, actual login and opaque App frame, no model calls, exact cleanup). The final screenshot shows Access Control; other controls are supported by DOM/HTTP assertions, not separate screenshots.

## Historical planning ledger (superseded where noted above)

Current source inventory after the four operational Overview reads. The table
retains the original 24-operation planning baseline so that partial delivery of
one operation group does not erase its still-open operations. Current evidence
may qualify a subset in an owned disposable topology without establishing
installed activation or closing the whole baseline group. Authority:
`client/src/pages/secureshop/bridge/operations.mjs` and
`server/routes/secureshop/boundGateway.js`. When no optional bound handler owns
an operation, the gateway's terminal handler returns 503; it never falls
through to the shared legacy admin router. This is an implementation gap, not
permission to expose global users, host processes, files, registry or
configuration.

| Page / bridge operations | Exact unsupported paths | Required owned implementation |
|---|---|---|
| Users: lookup, setRole, ban, resetPassword | POST `/admin/users/lookup`, `/admin/users/:id/role`, `/admin/users/:id/ban`, `/admin/users/:id/reset-password` | Listing, exact role changes, bans and operation receipt reads are now mounted in the source-qualified enabled full-index composition. Owned disposable evidence covers authenticated HTTP mutations, exact replay/conflict handling, effective role/ban projection, credential retirement, sibling isolation, fresh/populated/no-op migrations, fail-closed runtime ACL readiness and rendered role/ban controls through the real platform login and opaque full App frame. This does not implement lookup or reset-password, activate an installed deployment, or close the original four-operation baseline group. Broader lifecycle acceptance remains separately tracked. Preserve deliberate lookup injection in a separate owned synthetic target if teaching it. Never mutate platform accounts. |
| Policies: list, upsert, saveMarkdown, render, delete | GET/POST `/admin/policies`; POST `/admin/policies/:name`; POST `/admin/policies/:name/render`; DELETE `/admin/policies/:name` | Persist launch-owned policies, exact revision/decision provenance and reset/deletion. Preserve teaching render/injection sink inside owned data. Existing false-success UI repairs do not implement the backend. |
| MCP management: tools, register, importManifest, delete | GET `/admin/mcp/servers/:name/tools`; POST `/admin/mcp/register`; POST `/admin/mcp/import-manifest`; DELETE `/admin/mcp/:name` | Owned connector descriptors, actual bounded discovery/import effects and durable provenance/lifecycle. Existing `/v2/mcp-trust` rogue/rotation exercise and new persisted registry/history reads are separate supported scopes; do not rebuild or mislabel them as general registry management. |
| System: health, readConfig, diagnostic, restartService, rebuildIndex | GET `/admin/system/health`; POST `/admin/system/read-config`, `/admin/system/diagnostic`, `/admin/system/restart-service`, `/admin/system/rebuild-index?corpus=...` | Synthetic owned system/config/command target with real effects and cleanup; no host authority. Reindex needs the existing safe revision service scoped to an allowed corpus, not wholesale deletion. New `/admin/agent-host/health` is scoped service/readiness metadata and does not implement these five operations. |
| Access Control: get, setPermission, setEnforcement | GET `/admin/access-control`; POST `/admin/access-control/permission`, `/admin/access-control/enforcement` | Current-launch policy overlays, versioned enforcement and immutable decision receipts. Preserve intentional advisory/enforced distinction; never change global RBAC. |
| Generic admin agent session/chat | POST `/agents/admin/session`, `/agents/admin/chat` | A real bound purpose-specific graph and owned tools. Existing bound audit-summary and audit-SQL agent routes are supported separate workflows, not a complete general admin supervisor. |
| Legacy audit summarize alias | POST `/admin/audit/summarize-anomalies` | Remains unsupported; current Audit page uses bound-session/bound-summary. Do not create fake graph identity to make the legacy alias look available. |

The supported reads now include Overview KPIs, provider observations, exact admin
trace, Users listing, audit pagination, and the four new operational endpoints.
A mounted feature may remain deliberately unavailable when its actual owned
service/configuration is absent. Source support is not installed activation.

System/MCP initial health, registry and tool reads now check HTTP and response
contracts, distinguish unavailable/loading/empty, and retain explicit stale
state on partial failure. Their mutation handlers reject unconfirmed responses
without success messages or discarded input. Six current admin component suites
pass73 checks, including Access Control, Overview and Audit. Evidence:
`tasks/secureshop-system-mcp-ui-errors-2026-09-19.json`. This qualifies component
error handling, not the missing backend operations or installed activation.

Access Control source review: bound purpose-specific execution configurations
currently supply fixed `checkToolAcl` callbacks and empty `buildPolicyBlock`
callbacks, while the legacy supervisors consume shared policy/permission tables.
Mounting the legacy admin handlers would therefore neither configure those bound
graphs correctly nor preserve launch isolation. Future owned policy/ACL work must
connect versioned launch overlays to the actual decision/tool boundary, preserve
the intentional advisory teaching behavior in its owned target, and test effect
receipts in both modes. A working settings editor alone is not acceptance.

The Access Control UI now treats missing/malformed reads and unconfirmed writes
as unavailable, requires exact mutation acknowledgements, and reconciles lost
acknowledgements through an explicit read without replaying writes. Controlled
component evidence: `tasks/secureshop-access-control-ui-errors-2026-09-19.json`.
This error-state repair does not supply the three missing bound ACL endpoints.

## Freshness checkpoint: source-qualified user administration subset

`server/routes/secureshop/boundGateway.js` mounts the prepared
`userAdministration` dependency, and
`server/routes/secureshop/boundUserAdministration.js` defines bound listing,
operation-receipt, role and ban handlers. The current source also carries the
forward-only schema and scoped runtime-privilege readiness checks. Retained
owned evidence is split by what it proves:

- `tasks/secureshop-user-administration-mounted-native-2026-09-20.json` covers
  authenticated mounted role/ban operations, durable receipt reads and replay,
  conflict handling, effective directory projection and sibling isolation.
- `tasks/secureshop-user-administration-readiness-native-2026-09-20.json`
  separately proves that missing table/function privileges fail readiness and
  that restoring the exact grants succeeds.
- `tasks/secureshop-user-administration-enabled-startup-2026-09-20.json` covers
  the source-qualified enabled full-index composition with the canonical stores
  and protected Users path. Its controlled provider does not add actual-model
  evidence, and it is not an installed activation claim.
- `tasks/secureshop-user-administration-rendered-2026-09-20.json` covers the
  current enabled full-index browser path through real platform form login, the
  opaque full App iframe, two mounted mutations, exact receipt readbacks and
  settled role/ban rendering. It is controlled UI evidence, not model credit.

These receipts supersede the earlier candidate-only wording for listing,
setRole and ban. The router still does not implement raw lookup or password
reset; the UI intentionally reports password reset unavailable. Installed
activation, reset/deletion behavior and broader lifecycle acceptance remain
distinct gates. Retain the original Users group in
the 24-operation ledger until those two unsupported operations and the required
release gates are completed.

## Next bounded slice: Access Control

The three Access Control operations remain an exact current gap:

- `GET /api/secureshop/admin/access-control`
- `POST /api/secureshop/admin/access-control/permission`
- `POST /api/secureshop/admin/access-control/enforcement`

The callers already exist in
`client/src/pages/secureshop/pages/admin/AccessControl.jsx`, and the closed
bridge registers the same operations at
`client/src/pages/secureshop/bridge/operations.mjs:157-159`. The bound gateway
has no corresponding handlers, so each request reaches the terminal 503 in
`server/routes/secureshop/boundGateway.js`. The component correctly treats that
response as unavailable; its error and lost-acknowledgement behavior is covered
by `AccessControl.errors.test.jsx`. These tests prove truthful UI failure
handling, not an ACL backend.

The similarly named handlers in `server/routes/secureshop/admin.js` and
`server/routes/secureshop/postgres/admin.js` use the shared
`server/services/secureshop/toolAcl.js` state. That state is not launch-owned.
Mounting those handlers would let one learner change other launches and would
not configure current bound graphs, whose execution configurations presently
return fixed ACL decisions and empty policy blocks. The shared implementation
also contains the documented intentional LLM06 advisory sink and must remain
unchanged.

### Phased implementation

The first phase should be a target-local pilot around one already supported
graph and tool, such as the bound MCP `weather-lab.forecast_lookup` operation
for an administrator persona. This is deliberately partial. It proves the
storage, authority and runtime decision seam without claiming that the full
matrix works or hiding rows for the other visible workflows.

The pilot requires a forward-only `secureshop_agents` migration with:

- a target ACL configuration row keyed by the complete launch target and a
  monotonically increasing policy version;
- target, tool and role permission rows with a default derived from the bounded
  execution catalog;
- idempotent mutation records carrying an operation ID, expected version,
  resulting version and bounded acknowledgement; and
- reset/deletion bookkeeping that restores the target defaults while retaining
  an immutable cleanup receipt.

A bound repository and service must fence reads and writes with the current
admin persona, serialize them in the established launch/target lock order and
reject stale versions, sibling coordinates, revoked sessions and operation-ID
scope changes. The bridge and UI mutation contracts need `operationId` and
`expectedVersion`; a lost acknowledgement is reconciled by reading the exact
operation or current version without automatically replaying the write.

The selected graph's execution configuration must read the same policy version
at the actual `checkToolAcl` boundary. With a denied permission and enforcement
off, the existing supervisor graph must dispatch the tool and retain
`policyViolation: denied-by-acl`. With enforcement on, it must record a blocked
decision and make no remote call. The admin editor and graph cannot use separate
copies of policy state. Reset must restore defaults for that target, preserve
sibling policy rows byte-for-byte and leave the legacy global ACL untouched.

Later phases must extend this mechanism to every tool and role displayed by the
full Access Control matrix and connect each supported bound execution
configuration to the same target policy source. Until those phases pass, the UI
must clearly mark unsupported workflow rows unavailable rather than omit them
or imply that a successful pilot controls all supervisors.

### Acceptance evidence

The pilot is acceptable only when controlled and disposable tests establish:

1. all three bound routes require a current admin persona and return exact,
   versioned DTOs and mutation acknowledgements;
2. exact replay is stable, stale-version and operation-scope conflicts fail,
   revoked and sibling requests perform no write, and lost acknowledgement is
   reconciled without a second mutation;
3. the same selected tool produces a completed remote effect plus a
   `denied-by-acl` trace with enforcement off, then a blocked trace and zero
   remote effect with enforcement on;
4. reset restores the seeded target policy, preserves sibling state and emits
   the bounded cleanup receipt; and
5. the rendered page reflects confirmed state and retains its existing
   unavailable behavior for missing, malformed or unconfirmed responses.

`tests/secureshopGraphRuntime.test.js` already covers the supervisor's generic
log-versus-block mechanics, and
`tests/secureshop/integration/rbac-tool-permissions.test.js` documents the
legacy semantics. Neither is target-local acceptance. New repository, HTTP,
runtime-policy and rendered tests are required. Controlled policy tests do not
qualify an actual-model decision, installed activation or the remaining Access
Control matrix.
