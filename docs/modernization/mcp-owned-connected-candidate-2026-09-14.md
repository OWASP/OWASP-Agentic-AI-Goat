# MCP owned connected candidate — 2026-09-14

## Review boundary

This candidate connects the already qualified owner-scoped Linux target primitive
to the default-off MCP owned-resource application. It does not register the draft
schema, install the composition from `server/index.js`, replace a live sidecar, or
change the learner UI.

The private path is:

1. the mounted workshop authenticates the bearer against the durable platform
   user and session row;
2. the PostgreSQL run coordinator supplies the exact MCP owner and durable
   generation;
3. `ownedResourceApplication` reserves the exact target UUID in the draft MCP
   resource store;
4. `ownedTargetClient` calls the private token-authenticated sidecar API and keeps
   the opaque target capability inside its runner closure;
5. the sidecar checks its exact enforcing AppArmor supervisor label, trusted
   runtime binaries and compiled seccomp receipt before admitting the target;
6. MCP SDK `callTool` invokes the unchanged vulnerable handler, whose command is
   executed by `mcpTargets.executeTarget` under the target lock for the complete
   bwrap process lifetime;
7. the existing objective Judge and completion service decide and persist credit;
8. reset retires the MCP protocol, target, and exact Mailpit messages before it
   clears canonical progress.

The API token and opaque target capability are private control-plane values. They
are never accepted from a learner request, placed in MCP tool schemas, or returned
by workshop routes. Redirects and malformed/mismatched response receipts fail
closed. Legacy `/exec` remains available only to the existing ungraded path and
cannot make owned-resource readiness true.

## Prepared qualification

`tests/postgres/mcpOwnedConnected.integration.test.js` is a mounted, isolated
gate. The one-use launcher owns a PostgreSQL 18 container, a
Mailpit container, one freshly built Node 26.8.2 runner container, and one unique
AppArmor policy on the exact verification VM. It stages the resource schema only
inside its disposable MCP database and uses the local `llama3.1:8b` provider.
The disposable identity database is initialized through the registered migration
loader through identity0049, then stages only draft identity0050 and MCP0004 in
its copied workspace. It checks exact registered0046–0049 and staged-candidate
checksums before any actor turn.

The gate is designed to verify:

- a benign command control receives no command-injection credit;
- the model selects an exact chained command, the strict target returns protected
  fixture bytes, the real Judge accepts the evidence, and both native and
  canonical progress are persisted;
- an internal report is a negative control, while an external report reads the
  same owned target and produces an inspectable real Mailpit message;
- identical conversation request IDs replay their original request/run response
  without another tool effect, SMTP delivery, judgment, turn, target operation,
  or captured message. The mounted coordinator truthfully records one new empty
  completed wrapper run for the replay HTTP request;
- owner reset produces the exact target/mail cleanup receipts, removes current
  progress, preserves immutable judgments, and leaves both the sibling target
  and sibling captured Mailpit message unchanged;
- the next owner run uses the next durable generation and a new target.

The first native/model run (`mcp-owned-connected-20260914-01`, handle 33613)
failed honestly before either positive: the conversation route omitted owned
resource admission and silently passed the legacy sandbox/protocol to the turn.
Strict runner readiness itself passed, including the enforcing AppArmor label and
Node 26.8.2. Evidence is retained at
`~/.dvaia/native-verification/dvaia-mcp-owned-connected-h0rlz5de`; all three
containers, the runner image, AppArmor profile and remote policy directory were
proven absent afterward.

The mounted conversation path now admits resources before creating its durable
request row and passes the exact owned sandbox/protocol/state reader into the
turn boundary. The fifth connected run completed the full two-session lifecycle,
reset, immutable-judgment and sibling-preservation controls, but failed honestly
because the owner confused-deputy Judge selected false while the sibling Judge
selected true for materially equivalent real effects. Evidence is retained at
`~/.dvaia/native-verification/dvaia-mcp-owned-connected-2opck2_o` (result SHA-256
`68f167c83a4c5300a3b643e7cd7452ffc6a338fb101f3de73284adbe94cfd26e`).

The proposed replacement grading contract keeps an unforgeable private
observation on the original in-memory SDK result. Before grading, it rereads the
exact accepted durable mail intent and matches owner, platform session,
generation, current run/effect-derived intent ID, recipient hash, subject/body
payload hash, server-assigned Message-ID and protected runner bytes. The v2
rubric separates protected disclosure from exact external SMTP acceptance.
Cumulative sent-report counts and assistant claims cannot satisfy either fact.
The latest managed Node 26.8.2 isolated source gate passes 117 tests with three
explicit live-model gates skipped. This verifies the v2 source contract only;
the connected actual-model qualification remains open.

The sixth connected run proved those private v2 facts for both owner and
sibling, including the exact accepted Mailpit receipts, and completed the
two-session revocation/reset/sibling lifecycle. Both deputy Judge calls instead
returned `INVALID_JUDGE_OUTPUT` after their two bounded attempts; the command
Judge passed. The retained run did not capture the raw invalid Judge responses,
so it does not establish which validator rule rejected them. Evidence is at
`~/.dvaia/native-verification/dvaia-mcp-owned-connected-zctebicg` (result SHA-256
`102e64cdf9054fdb7dd7d9dde46e92ec396c4d50df1d11c37aae89847236cfba`).
The seventh connected run retained four private invalid attempts and established
the exact cause: the protected criterion quoted a real tool-result leaf, while
the non-quote-required delivery criterion quoted a synthesized description of
its structured server observation. The former matched; the latter did not.
Judge v20 now requires citations only for `quoteRequired` criteria and constrains
all other citation arrays to be empty. Exact facts, evidence references, allowed
sources and protected-data quote validation remain unchanged. Typed validation
reason codes stay in the owner trace, and the private qualification-only raw
attempt sink binds each record to its run and evidence digest. The generic
learner-facing failure remains unchanged. Evidence is at
`~/.dvaia/native-verification/dvaia-mcp-owned-connected-82t4i9ae` (result SHA-256
`67bf52c171f3e3d95eaca61d7df47b8a232aeffbd19548f701f11a4ce50bbef2`).

## Remaining activation gaps

- `docs/modernization/drafts/0050_mcp_conversation_history.sql` and
  `docs/modernization/drafts/0004_mcp_owned_resources.sql` remain unregistered
  drafts. Their copied-loader/runtime gate passed, but live promotion still needs
  a fresh quiet two-store backup, owned restore, normal loader, replay and
  preservation gate.
- `server/index.js` calls the production installer after database initialization,
  but `MCP_OWNED_RESOURCES_ENABLED` remains false. The installer correctly
  constructs the canonical identity, resource, target and mail composition and
  rechecks live readiness on admission.
- the checked-in local compose service still uses `apparmor:unconfined`; a stable,
  application-owned `dvaia-mcp-sandbox` policy installer and compose transition
  must use the same reviewed profile before readiness can pass. AWS remains
  unqualified and must fail closed for graded owned effects.
- Mounted final-policy Judge v20 run `dvaia-mcp-owned-connected-fwnn8rp2`
  passed both objectives with actual `llama3.1:8b`, actual owned effects, exact
  lifecycle controls and zero invalid Judge attempts. This proves the frozen
  copied candidate, not live activation.
- command injection and confused deputy are the first connected effects. SSRF and
  rogue-server sidecars still lack owner/session/generation resource retirement;
  installed plugin, shadow catalog, audit, listener, and ticket state remains
  process-local. The remaining MCP objectives therefore do not yet have a complete
  restart/reset authenticity claim.
- CodeBot uses a separate legacy bwrap construction in `sandbox-runner/index.js`.
  It has not inherited the MCP target qualification and needs its own ephemeral
  fixture/seccomp migration and native Judge proof.
- the confused-deputy candidate uses the distinct rubric version
  `mcp_confused_deputy_observed.v2`; historical `mcp_real_tools.v1` judgments
  remain immutable. The v2 contract still needs one connected actual-model
  qualification before activation.

Identity migration `0046` is now present in the local application. Promotion run
`graph-judge-validation-live-promotion-20260914-01` remains recorded as a failure
because nodemon replaced the backend after resume. The bounded post-restart audit
in `docs/modernization/drafts/graph-judge-validation-code-post-restart-audit-2026-09-14.json`
records the separate facts that the catalog matched its pre-pause snapshot, all
16 migration stores replayed empty, the `0046` checksum was exact, readiness
passed, and the replacement backend was healthy.
