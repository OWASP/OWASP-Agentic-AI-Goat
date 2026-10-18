# SecureShop host-sink isolation design

Date: 2026-09-13  
Scope: source-only design; no commands, learner effects, models, databases, or private files were exercised.

## Decision

SecureShop must stop executing learner-controlled paths, templates, URLs, and
commands in the application or Agent Host process. Preserve each vulnerable
parser or command construction, but move its effect into a dedicated SecureShop
adapter on the existing sandbox runner. The adapter has two execution classes:

1. **Virtual-filesystem operations** may run without bubblewrap. The runner maps
   every virtual path into one opaque learner root, so vulnerable traversal can
   escape an intended directory and reach that learner's synthetic `/server`,
   `/etc`, or `/uploads` fixtures, but cannot resolve a host path or another
   learner root.
2. **Arbitrary code or shell operations** require a fresh, allowlist-mounted
   bubblewrap namespace attested as `bwrap-secureshop-v1`. They fail closed when
   that exact isolation is unavailable. There is no host `exec`, VM fallback,
   non-root-only fallback, or generic `/exec` fallback.

This keeps the teaching vulnerability real: a traversal reads actual synthetic
lab bytes, an upload writes an actual isolated file, and a shell injection runs
the learner's exact command. It changes only the outer containment boundary.

At audit time, the compatibility path `docs/secureshop/vuln-map.md` was absent.
It now points to the authoritative generated `docs/secureshop/VULNERABILITIES.md`,
which remains the single inventory. The source/test annotation verifier passes
all 66 IDs. The source inventory below is a design assessment, not runtime
isolation or exploit qualification.

## Reachable host-facing sinks

| Priority | Reachable sink | Current effect and risk | Present authenticity | Proposed adapter |
|---|---|---|---|---|
| P0 | `system.restart_service` | Learner `name` is concatenated into `systemctl restart ${name}` and host `exec` is enabled by `SS_SYSTEM_ALLOW_EXEC`: `agent-host/agents/system/tools/index.js:39,58-80`. Admin REST calls it directly at `server/routes/secureshop/admin.js:563-573`; admin MCP exposes it at `agent-host/agents/system/server.js:17-20,68-71`. | Guarded mode returns `ok:true`, the command, and `executed:false`; this proves string construction but is not an executed exploit. Enabled mode executes on the host. | Preserve command construction in the tool, submit the exact command to `POST /secureshop/shell`, require `bwrap-secureshop-v1`, and return the real exit/output receipt. Seed a synthetic service-state file so the benign restart has an observable effect; injected shell fragments execute in the same isolated shell. |
| P0 | `system.run_diagnostic` and `_mayReadFile` | Arbitrary `cmd_template + args` reaches host `exec`; even guarded mode reads a caller-selected host file: `agent-host/agents/system/tools/index.js:86-113,118-130`. Admin REST is directly reachable at `server/routes/secureshop/admin.js:557-560`. | Unguarded is real host RCE. Guarded command success is simulated while the side read is a real host read. | Remove both host paths. Send the exact command to strict `/secureshop/shell`. Implement the excessive-permission side read against the same learner virtual filesystem. Require a real runner receipt for either observed effect. |
| P0 | Listing and policy SSTI | `_nunjucksSink` exposes the Agent Host `process` and `global`: `agent-host/agents/listing/tools/_nunjucksSink.js:21-41`. It is reached by listing creation (`agent-host/agents/listing/tools/create.js:40-49`), policy update (`agent-host/agents/policy/tools/index.js:46-74`, PostgreSQL equivalent `index.postgres.js:38-66`), and direct admin preview (`server/routes/secureshop/admin.js:479-499`; PostgreSQL `server/routes/secureshop/postgres/admin.js:304-324`). An SSTI expression can access host modules, environment, files, and child processes. | Potentially authentic against the real application host; the `vm` fallback is not a security boundary. | Move complete Nunjucks rendering into strict `/secureshop/template`. Mount only the Node runtime, a read-only Nunjucks dependency tree, synthetic files, fresh `/proc` and `/dev`, and the caller's private lab root. Keep `autoescape:false` and expose the isolated child `process`, preserving the same template payload shape. Persist returned rendering only after an attested successful child result and an owner-generation recheck. |
| P0 | `listing.optimize_images` | Product `image_url` is interpolated into a host shell command and passed to `exec`: `agent-host/agents/listing/tools/optimize_images.js:18-55`; PostgreSQL duplicate `optimize_images.postgres.js:18-55`. Merchant MCP exposes it at `agent-host/agents/listing/server.js:47-52,69-82`. | Default guard reports `executed:false`; enabled mode is host command injection. | Resolve the product's stored opaque asset into its learner lab root, construct the same unsafe `convert ...` command, and run it through strict `/secureshop/shell`. Qualification must show an actual isolated output file or injected command effect. If ImageMagick is absent from the runner image, the benign optimization portion remains unavailable; a fabricated conversion result is not acceptable. |
| P0 | MCP registry stdio transport | Caller `stdio_cmd` is detached through host `spawn('sh', ['-c', ...])` when enabled: `agent-host/agents/mcp-registry/tools/index.js:131-139`. Admin REST reaches `register` at `server/routes/secureshop/admin.js:523-531`; admin MCP at `agent-host/agents/mcp-registry/server.js:18-29,56-71`. | Disabled mode persists a registry row without proving package execution. Enabled mode launches unbounded host code and loses a trustworthy completion receipt. | Execute the exact stdio command as a bounded strict runner operation. Record exit, output, timeout, and an isolated session-file effect; do not detach. Registry persistence may still demonstrate the rug-pull sink, but the supply-chain objective must require the strict execution receipt. |
| P0 | Upload write/traversal | Upload names get a single-pass traversal strip and may be written to the resolved host path: `agent-host/agents/uploads/tools/index.js:75-93,107-149`. The four upload functions converge at lines `154-175`. The REST upload router calls tools directly at `server/routes/secureshop/uploads.js:33-70` and installs no authentication/owner middleware. | Real write, including escape from the repository upload directory. Default root is inside the checkout: `server/services/secureshop/assetPaths.js:5-21`. | `POST /secureshop/files/write` performs the same single-pass resolver inside an opaque learner virtual root. Standard and traversal writes are both real. Return an opaque asset receipt and virtual path, never a runner-host path. Require authentication for mutation so an owner root can be selected; retain public rendering through unguessable read receipts if product images must remain public. Stream or chunk uploads because the runner's current JSON body reader caps requests at 1 MB (`sidecars/sandbox-runner/index.js:377-381`) while REST permits 20 MB (`server/routes/secureshop/uploads.js:28-31`). |
| P0 | Upload download/static traversal | Tool download resolves and reads a caller fragment on the Agent Host: `agent-host/agents/uploads/tools/index.js:208-235`. Static HTTP separately resolves and streams a host file: `server/routes/secureshop/uploads.js:76-86,92-118`. | Authentic host file disclosure. | Route both through `GET/POST /secureshop/files/read` using an owner capability or opaque public asset receipt. Preserve inline MIME/disposition for SVG/XSS teaching. A traversal may reach synthetic files in the same learner virtual root; the outer adapter rejects any resolved runner path outside that root. |
| P0 | `summarizer.summarize_file` | Decorative cleaning is ignored and the raw learner path goes to Agent Host `readFileSync`: `agent-host/agents/summarizer/tools/summarize_file.js:16-38`. It is offered to every role at `agent-host/agents/summarizer/server.js:33-35,47-58`. | Authentic arbitrary host read. | Keep the raw-path-versus-cleaned-path bug, but make the read through the virtual-filesystem adapter. Return exact virtual path, real isolated bytes, size and receipt; never return an application-host absolute path. |
| P0 | `system.read_config` | Single-pass traversal is resolved against the repository's real `server` directory and read on the host: `agent-host/agents/system/tools/index.js:135-161`. Admin REST reaches it at `server/routes/secureshop/admin.js:576-578`; MCP exposes it at `agent-host/agents/system/server.js:32-35,68-72`. | Existing tests read real checkout fixtures, so the mechanism is real but the deployed boundary is unsafe. | Preserve absolute-path rejection and the exact `....//` bypass. Run the resolver in the virtual lab with intended base `/server/config`; seed unpredictable per-owner synthetic `.env` and `platform_secrets.json` markers. Judge evidence must bind returned bytes to the runner receipt, not to a static known string. |
| P0 | `file://` in summarizer, listing import, XXE and MCP manifest | `explain_return_policy` reads `file:` on the host (`agent-host/agents/summarizer/tools/explain_return_policy.js:40-50`). Listing URL import reads host paths (`import_bulk.js:41-59` and PostgreSQL `import_bulk.postgres.js:41-59`); its SAX entity handler reads each `SYSTEM file://` URI (`import_bulk.js:150-179`, PostgreSQL lines `148-177`). MCP registry `_fetch` reads host `file:` (`agent-host/agents/mcp-registry/tools/index.js:69-86`) and reuses the listing parser at lines `58-60`. | Real host reads. The SAX code does use the parser entity table, but the external bytes are fetched by application `fs`, not a contained XML runtime. | Move `file:` retrieval to the owner virtual filesystem. Prefer running the complete SAX/XML import in a strict child with read-only parser dependencies; a smaller feasible first step injects an asynchronous isolated-file resolver before SAX substitution and labels that boundary precisely. Preserve XML parsing and the external entity mechanism, not a static replacement string. |
| P1 | Upload extraction and vector files | `extractText` reopens a tool-provided host path (`agent-host/agents/uploads/tools/index.js:242-280`). `upload_product_manual` passes that path into extraction and then writes vector indexes (`lines 173-205`; `server/services/secureshop/vectorStore.js:91,464`). | Real application-data writes; traversal makes the input path unsafe. Vector index location defaults to the checkout. | Have the file adapter return bytes by receipt and make extractors accept bytes plus a virtual filename. Keep vector records/indexes as platform challenge data, but set their storage root to an owned application-data directory in tests and deployment. Never reopen a learner-provided absolute path. |
| P1 | System health metadata | `health_check` returns the laptop/container hostname, OS, Node version, memory and load: `agent-host/agents/system/tools/index.js:41-55`. | Real but observes the host, not an isolated teaching system. | Return runner-attested synthetic lab identity and resource data, or label it application-host telemetry. It should not expose attendee laptop identity. |
| P1 | Host-network SSRF adjacent to these tools | Summarizer HTTP fetch runs in Agent Host (`explain_return_policy.js:19-37,54-65`); listing and MCP registry fetchers do likewise; price advisor fetches arbitrary hosts (`agent-host/agents/price-advisor/tools/index.js:69-103`); email inline previews are fetched during summarization (`agent-host/agents/email/tools/index.js:162-205`). | Real requests from the application/laptop network, including loopback and private targets. | Reuse the controlled SSRF target with exact requested URL retained in the receipt, or add a dedicated network-only lab adapter. Do not put SSRF inside the shell namespace, whose network must remain empty. This is related containment work but is separable from the file/shell adapter. |
| P1 | Prototype pollution in bulk import | `_mergeUnsafe` mutates inherited objects in the long-lived Agent Host (`agent-host/agents/listing/tools/import_bulk.js:63-77`, PostgreSQL lines `63-77`). | A real process-global teaching effect can cross learner sessions. The catalog description calling this “pickled Python-style deserialization” does not match the implementation. | Execute parsing/merge in a per-call child or resettable worker, return the polluted-property observation, and terminate the worker. Correct the curriculum label to JavaScript prototype pollution/insecure merge unless an actual deserializer is later implemented. |

The duplicated SQLite/PostgreSQL loader files must call the same adapter rather
than grow separate containment implementations.

## Identity, ownership and reset

The supervisor has a strong session binding before it enters the graph:
`server/routes/secureshop/_agentSessionControl.js:15-25` verifies session UUID,
user and role, and route calls pass `callerRole`/`callerId` at
`server/routes/secureshop/admin.js:161-172` and corresponding customer/merchant
routes. The graph retains `sessionId` at
`server/agent-runtime/secureshopSupervisorGraph.js:19-25`, but currently drops
it when it calls the pool; only role, user id and ACL result are forwarded at
lines `210-218`. `McpClientPool` places only those fields into `_ss_caller` at
`server/services/secureshop/mcpClientPool.js:59-85`, and `extractCaller` drops
everything else at `agent-host/shared/callerContext.js:35-56`.

The minimal context change is:

- derive an opaque lab-session key from the already unpredictable agent session
  UUID plus role and owner id;
- add that opaque key to the reserved `_ss_caller` envelope in
  `secureshopSupervisorGraph.js`, `mcpClientPool.js`, and `callerContext.js`;
- never accept a learner-supplied lab key in tool arguments;
- validate the key's exact `secureshop-[a-f0-9]{64}` shape at the runner and map
  it to one directory below `SANDBOX_SESSION_ROOT/secureshop/`;
- use `realpath`/descriptor-relative operations at the outer boundary so no
  symlink or traversal can leave that directory. The intentionally weak inner
  resolver operates only on virtual paths inside it.

Direct admin and merchant REST calls have authenticated `req.ssUser` but no
agent-session UUID. They need a server-issued opaque per-login lab capability,
passed internally to the same adapters. The uploads router currently has no
owner context at all, so mutation cannot be safely partitioned until it requires
an authenticated SecureShop identity. Public asset display should use an opaque
read receipt rather than reopening a user path.

Every runner mutation returns `{operationId, labSession, isolation, effect,
exitCode}`. Reset deletes only that learner root and recreates fresh random
fixture markers before challenge progress is cleared. If runner reset is
unavailable, progress reset fails; it must not claim a clean lab. Supervisor
cancellation must be checked after each runner await and before persistence,
stream publication, or a second effect. Current MCP transport does not propagate
the graph abort signal into an already dispatched tool, so idempotent operation
IDs and pre-persistence owner checks are required as part of this adapter work.

## Runner API and containment

Add dedicated endpoints rather than reusing `/exec`:

| Endpoint | Purpose | Required boundary |
|---|---|---|
| `POST /secureshop/files/read` | Resolve and read a virtual file; return bytes plus receipt | Owner root mapping; no bwrap needed |
| `POST /secureshop/files/write` | Persist upload bytes and return opaque asset receipt | Owner root mapping; streamed bounded body |
| `POST /secureshop/files/extract` | Extract by receipt/virtual name, never host path | Owner root mapping; bounded output |
| `POST /secureshop/shell` | Exact restart, diagnostic, image or stdio command | `bwrap-secureshop-v1` only |
| `POST /secureshop/template` | Unsafe Nunjucks render with isolated `process` | `bwrap-secureshop-v1` only |
| `POST /secureshop/reset` | Delete/reseed exactly one learner root | Exact opaque key; idempotent |

Strict shell/template namespaces must copy the CodeBot shape at
`sidecars/sandbox-runner/index.js:111-149,175-236`: fresh mount root, allowlisted
runtime mounts, empty environment, new PID/UTS/IPC/network namespaces, fresh
`/proc`, `/dev`, `/tmp`, descendant-process-group kill, timeout and aggregate
output cap. Bind only the selected learner root; never mount `/`, `/app`,
`/sandbox`, the repository, sibling session roots, Docker socket, cloud
credentials or runner environment. Use a separate strict capability probe and
attestation for SecureShop.

The current generic runner is not acceptable for this work. Its bwrap path
read-only binds `/` and rebinds shared mutable `/var/secrets` and
`/opt/app/config` (`sidecars/sandbox-runner/index.js:249-273`), its session ID is
sanitized rather than authenticated (`lines 122-126,418-428`), and its fallback
runs a shell without a namespace (`lines 276-335`). It can expose shared MCP and
CodeBot-adjacent state and cannot establish per-attendee containment.

## Feasible scope and blockers

**Feasible with application and runner JavaScript only:** owner-context
forwarding; dedicated client; virtual file read/write/download; synthetic
per-owner fixtures; upload receipts; path-traversal, config-read, file-URL and
XXE reads within the virtual root; reset; honest unavailable responses; pure
and disposable tests. These do not need a new database migration if opaque
references fit existing path/text columns.

**Blocked for successful execution in the current environment:** arbitrary
shell, SSTI, image-command injection and stdio package commands. The existing
recorded local probe reports `bwrap=false`, and the strict CodeBot endpoint is
unavailable (`docs/modernization/secureshop-authenticity-audit-2026-09-13.md:161`).
Repository comments also say Fargate falls back to plain execution
(`sidecars/sandbox-runner/index.js:17-25`; `docker-compose.yml:28-30`). With AWS,
compose and runtime capabilities frozen, implement these adapters and their
fail-closed state, but do not advertise the exercises as executable until an
opt-in strict-runner qualification passes on the actual supported environment.

ImageMagick is not installed by `sidecars/sandbox-runner/Dockerfile:6-8`, and
Nunjucks/SAX/XML dependencies are absent from
`sidecars/sandbox-runner/package.json`. Exact image and parser/template behavior
therefore also needs packaged read-only runtime dependencies. Adding those image
contents is a source/build change; deploying them is outside this frozen scope.

## Bounded implementation order

1. **P0 file boundary:** add opaque context forwarding, virtual filesystem
   endpoints/client, random fixtures and reset. Convert `system.read_config`,
   `_mayReadFile`, `summarize_file`, upload write/read/static serving,
   `file://` import and XXE entity resolution. Remove all learner-path calls to
   application `fs`. Fail closed when identity or runner is unavailable.
2. **P0 strict effect boundary:** add strict shell/template endpoints and convert
   system, image, SSTI and stdio sinks. Delete the `SS_*_ALLOW_EXEC` host branches;
   unavailable isolation returns `executed:false`, `achieved:false` and no Judge
   candidate. Keep the unsafe command/template construction intact.
3. **P1 network/process isolation:** route SSRF through controlled targets,
   isolate prototype pollution in a disposable child, integrate owner reset, and
   update teaching text that currently overstates simulated or mismatched
   mechanisms.

## Tests required before credit

- **Static reachability:** no learner-controlled value reaches `fs`, `exec`,
  `spawn`, `vm`, `process`, `file://` or a raw network client in Agent Host or
  SecureShop routes; tagged sinks call the dedicated adapter instead.
- **Virtual filesystem:** temporary runner root with two opaque sessions;
  standard reads/writes work, intended-directory traversal reads only that
  session's random synthetic secret, absolute laptop paths and symlinks cannot
  escape, session A cannot name/read/reset session B, and reset reseeds different
  markers.
- **Strict runner qualification (opt-in):** exact injected shell and SSTI
  payloads create/read an isolated effect; no host canary, sibling session,
  environment credential, application port, metadata address or external
  network is reachable; timeout kills descendants; output cap includes both
  streams; attestation is exactly `bwrap-secureshop-v1`. An unavailable probe is
  recorded as unresolved, not passed.
- **Route/MCP parity:** SQLite and PostgreSQL implementations preserve the same
  original arguments, virtual paths, unsafe parser/command construction and UI
  DTOs through both direct REST and supervisor MCP paths. Mock/model selection
  alone cannot qualify an effect.
- **Ownership/reset races:** forged or missing context fails before runner access;
  role/id/session mismatch fails; cancellation after a read cannot begin a later
  write/send; stale operations cannot publish, persist, or receive Judge credit;
  runner reset must succeed before progress deletion.
- **Pedagogy and Judge:** each objective distinguishes vulnerable inner resolver
  from safe outer containment, uses unpredictable per-session evidence, requires
  real effect receipts, has benign and adversarial negatives, and explains an
  unavailable strict runtime without offering simulated success.

Until these tests pass in the relevant runtime, guarded command strings and
host-file fixtures prove only source reachability. They do not prove authentic,
safe learner exploitation.
