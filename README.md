# OWASP Agentic AI Goat

**An educational cybersecurity platform for learning AI security, web vulnerabilities, and ethical hacking.**

![DVAIA](https://img.shields.io/badge/DVAIA-Educational%20Security%20Platform-red?style=for-the-badge&logo=shield&logoColor=white)
![Security](https://img.shields.io/badge/Security-Database%20Isolation%20Enforced-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Prompt%20Injection%20Challenges-blue?style=for-the-badge)

> ⚠️ **For local educational use only. Never expose this application to the internet.**

---

## What is Agentic AI Goat?

Agentic AI Goat originates from [DVAIA](https://github.com/hackerabhinavverma/Damn-Vulnerable-AI-Application). Existing application identifiers, teaching content and attribution are preserved.

The application combines an authenticated workshop platform with intentionally vulnerable lab environments for hands-on security learning. Exercises use seeded lab data and separate application stores. Platform isolation and exercise behavior are verified separately; see the [current release status](docs/modernization/current-release-status.md) for completed checks and remaining qualification gaps.

- **Platform layer** — Secure auth, session management, audit logging
- **Challenge layer** — Isolated vulnerable databases, safe to exploit

For historical AI conversation data, use the explicit [private archive operator workflow](docs/modernization/legacy-ai-history-operator.md). Startup never imports or deletes that history automatically.

---

## Installation

Generated Legacy Sensitive teaching files support an optional external root; see [teaching-file initialization](docs/modernization/legacy-sensitive-file-root.md).

Fresh installations use PostgreSQL18 for all application stores. Download or clone this repository, open a terminal in its directory, then run the installer for your OS:

```bash
# macOS
bash scripts/install/Mac/install-macos.sh

# Ubuntu / Debian Linux
bash scripts/install/Linux/install-linux.sh

# Start the application after setup succeeds
./start_all.sh
```

```powershell
# Windows 10/11 x64 Pro, Education, or Enterprise with Hyper-V
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/install-windows.ps1

# Start after setup succeeds; stop only the process tree it owns
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1 -Stop
```

These are the supported local setup entry points. Recorded current-machine and
disposable-component checks do not constitute an independent clean-host
qualification across every listed OS and architecture; that qualification is
deferred. See the [native Windows requirements and recovery commands](docs/install/INSTALLATION.md#native-windows) before using the Windows wrapper. This repository no longer ships the former AWS deployment assets.

The macOS/Linux installers install missing Node/npm, Git, native build tools, Ollama and a Docker runtime. They require Node26.10.0 and npm12.1.0 or newer, retaining a newer installed version. macOS uses Homebrew and starts the explicit Colima profile used by the owned runner even when another Docker context already works; Ubuntu/Debian uses apt and a checksum-verified official Node binary when needed. System package installation may request your administrator password. The installers start Ollama and install `llama3.1:8b` if missing. Fresh setup then requires a completed local generation with the expected model identity before provisioning databases; model catalog presence alone is insufficient. Run either command with `--plan` for a non-mutating preview that works even without Node. See [macOS/Linux setup details](docs/install/INSTALLATION.md) for supported systems and service recovery.

If you already have the system prerequisites and Ollama running, `npm run setup` performs application setup directly. `--no-install` skips only npm dependency installation; it still verifies the frameworks, browser and local model.

With `SS_ENABLE=true`, ordinary startup composes the standalone SecureShop core:
its independent shop authentication, public catalog and customer, merchant and
shop-administrator routes. It requires all 16 configured and migrated PostgreSQL
stores, including `secureshop_review`. The full six-panel bound application
remains an explicit opt-in through `SS_BOUND_REVIEWS_ENABLED=true`; that flag
controls bound-surface exposure, not the review-store schema requirement.
This startup split has controlled coverage, but ordinary native installation
and startup qualification remains pending.

For an existing local PostgreSQL installation that needs missing or outdated local components repaired, stop the app and run the matching OS installer with `--repair` (or add `--plan --repair` to preview). Repair preserves the existing `.env`, administrator credentials and learner data. It prepares the qualified Node/npm and OS tools, reinstalls the locked application/client dependencies, verifies the browser and local models, then runs the supported additive database upgrade. Keep the installation's recorded Docker daemon running: macOS repair will not start another Colima profile or switch Docker context. Plain `--upgrade` keeps its database-only behavior and does not install packages or models. Direct `npm run setup -- --repair` assumes Node/npm and OS prerequisites are already available; use the OS installer to repair those prerequisites.

The explicit ARM64 combined opt-in `npm run setup -- --qualified-secureshop --owned-system`
prepares the bound SecureShop baseline, MCP registry service and owned System listeners. It requires the
reviewed local Docker authority and enforced sandbox profile already present;
AMD64 and cold-host profile installation remain unqualified. Optional nonsecret
listener ports can avoid existing local services:

```bash
DVAIA_SYSTEM_CONFIG_PORT=19090 DVAIA_SYSTEM_DIAGNOSTIC_PORT=19091 DVAIA_SYSTEM_RESTART_PORT=19092 \
  npm run setup -- --qualified-secureshop --owned-system
```

Ports must be distinct canonical decimal values from 1024 through 65535. Fresh
defaults are 8090, 8091 and 8092. A managed installation preserves its recorded ports;
an explicitly different requested port is rejected before setup changes anything.
See the [fresh combined setup scope](docs/modernization/drafts/secureshop-bound-system-diagnostic/fresh-combined-setup.md)
for prerequisites and qualification limits.

For an existing bound SecureShop installation, preview registry preparation with
`npm run setup -- --plan --owned-mcp-registry`, then run
`npm run setup -- --upgrade --owned-mcp-registry`. Setup builds or reuses the
pinned ARM64 service and checks database isolation, persona authority and
authenticated service readiness before enabling a new installation. Existing
disabled settings are preserved; use `--enable-owned-mcp-registry` deliberately
to enable them, then restart with `./stop_all.sh` and `./start_all.sh`.
Its token is generated privately under `~/.dvaia/<workspace-id>/`; no external
MCP credentials are required. Registry registration/import, tools/history and
retirement are qualified on ARM64. Generic supervisor invocation of registered
tools and Linux AMD64 qualification remain incomplete.

The owned strict policy renderer is a separate explicit opt-in. Preview an
enabled installation with
`npm run setup -- --plan --owned-policy-renderer --enable-owned-policy-renderer`.
For a fresh installation, remove `--plan`; for an existing installation, add
`--upgrade`. The enable flag is rejected unless `--owned-policy-renderer` is
also present. Using only `--owned-policy-renderer` prepares or verifies the
managed service while preserving a disabled preference. Setup publishes the
private loopback origin only after readiness succeeds. This path is limited to
ARM64 macOS and Linux with the installation's recorded local Docker authority
and enforced workspace AppArmor profile; Windows and x86-64 are rejected. The
listener defaults to loopback port 8098 and preserves its recorded managed
port. Current controlled checks do not establish cold-host or native-platform
qualification.

The `--owned-listings` setup flag automatically prepares the qualified ARM64 shared Listings manager and workspace profile using checked-in package authority and private configuration. It preserves existing application data and stages disabled capability until the separate production release gates pass. Preview with `npm run setup -- --plan --owned-listings`. See [Owned Listings installation](docs/install/owned-listings.md) for qualification limits and activation requirements.

The separate Listings template executor is under qualification. Preview its
optional setup with `npm run setup -- --plan --owned-listing-template`.
That option stages the component disabled; activation additionally requires
`--enable-owned-listing-template` and successful isolated readiness checks.
For an existing installation, include `--upgrade`. This component uses a
private loopback port in 8109–8118 and the recorded local Docker authority on
ARM64 macOS/Linux. It does not enable the Listings manager or replace the
policy renderer. Native execution, startup integration and the complete
model/Judge/browser workflow remain unqualified; these flags are not a claim
that the template exercise is release-ready.

The optional `--owned-analytics` setup flag provisions a separate private
PostgreSQL cluster for SecureShop Analytics. It requires enabled bound SecureShop
and current application migrations, then checks the private cluster and request
schema before activation. Existing disabled preferences and credentials are
preserved. `npm run setup -- --plan --owned-analytics` previews this path without
changes. The isolated ARM installer has passed fresh, repeat, restart, real SQL,
and cleanup checks. The real setup helper also passes application-schema drift,
activation-recovery and no-op checks using a separate application database.
Authenticated workflow and fixed real8B cases have separate evidence; full
cold-host qualification remains open.
If a first installation stopped at Analytics readiness, repair its reported
prerequisite and use `npm run setup -- --upgrade --enable-owned-analytics` to
explicitly enable the staged feature. The same flag re-enables an intentionally
disabled installation after readiness checks; ordinary `--owned-analytics`
preserves that preference.

Qualified local SecureShop fresh setup and an additive upgrade of an existing
bound installation prepare the owned coupon bundle by default when Analytics
and coupon preferences have not been disabled. For an explicit existing-install
preview or repair, use `npm run setup -- --plan --owned-coupons`, then
`npm run setup -- --upgrade --owned-coupons`. The bundle prepares the owned
Analytics database, applies additive coupon migrations, and checks runtime
permissions and reset hooks before recording private activation. It requires
`SS_ENABLE=true`, `SS_BOUND_REVIEWS_ENABLED=true`, and the configured PostgreSQL
stores. Existing disabled Analytics or coupon preferences are preserved; no
external service credentials are needed.
Installer and isolated SQL/checkout/reset checks are qualified on the local
ARM64 environment. Full rendered coupon workflow and cold-host Linux
qualification remain separate checks. See [coupon installation details](docs/install/owned-coupons.md).

Fresh setup also builds and verifies the five SecureShop renderer artifacts
(review, product description, mail, ticket and search echo) before provisioning
databases. This step runs with `--no-install` too. Normal `npm run build`
includes all five renderer builds; existing installations can rebuild the
artifacts with `npm --prefix client run build` without resetting data.
Additive database-only upgrades do not rebuild application artifacts.

Supported setup also creates a private `secureshop-reset-key.json` in `~/.dvaia/<workspace-id>/` and records its path as `SS_PASSWORD_RESET_KEY_PATH`. Additive setup preserves an existing key. Keep it with private installation backups; losing it makes outstanding password-reset recovery unavailable. Runtime never generates a replacement key. This key alone does not enable reset controls: the owned reset repository and readiness checks must also be installed.

Fresh setup also downloads and verifies the real `Xenova/all-MiniLM-L6-v2` q8 embedding model used by document-retrieval exercises. Its cache is stored under the workspace's private `~/.dvaia/<workspace-id>/models` directory and recorded as `XENOVA_CACHE` in the generated configuration. An existing absolute `XENOVA_CACHE` can be supplied before setup. Verification performs a real 384-dimensional embedding before database provisioning; unavailable model files or invalid output stop setup. Downloads use Node's trusted system certificates with TLS verification enabled.

For an existing installation, prepare or verify a cache without resetting application data with `node --use-system-ca scripts/verify-embedding-runtime.js --cache-dir /absolute/path/to/model-cache`, then set `XENOVA_CACHE` to that directory in your private configuration. With the cache prepared, `HF_HUB_OFFLINE=1` or `TRANSFORMERS_OFFLINE=1` disables remote model loading. Additive database upgrades preserve existing configuration and do not implicitly download models.

`setup` installs the locked backend and frontend dependencies, verifies LangChain/LangGraph and a sandboxed browser, verifies/downloads the local model, starts a dedicated loopback-only PostgreSQL container, provisions16 isolated databases with separate runtime/migration roles, applies migrations and seeds, and creates a private `.env`. Before local PostgreSQL or ordinary MCP sidecars can mutate Docker, setup resolves Docker Desktop's or Colima's selected local Unix socket (the local Docker named pipe on Windows), records that socket and the daemon identity in the private `~/.dvaia/<workspace-id>/local-docker.json`, and binds later commands to it. A remote Docker endpoint is refused. Setting both `DOCKER_HOST` and `DOCKER_CONTEXT` is ambiguous and fails closed; setting either one selects it only when it resolves to a local socket, while setting neither uses the active local context.

Fresh setup now retains its generated environment in an owner-only `fresh-environment.pending.json` inside the installation’s private directory before initialization uses its secrets. Treat it as credential material alongside the generated administrator file; retain it if setup is interrupted. This journal preserves exact values for recovery but does not yet enable recovery of a dirty maintenance phase.

After provisioning, the supported initializer, `./start_all.sh --init-db`, setup upgrade and deployment compatibility aliases use the journal-bound canonical16 maintenance path. It requires the complete owned PostgreSQL installation and matching private configuration; failed admission does not fall back to ordinary initialization. The explicit `--maintenance-profile=canonical16-ctf-inprocess-v1` flag selects the same path. The ordinary profile is no longer a supported fallback, and startup never clears a dirty marker.

Interrupted maintenance leaves a durable `APPLICATION_MAINTENANCE_DIRTY` marker. Inspect its state with:

```bash
node scripts/application-maintenance-recovery.js --plan
```

Guarded recovery execution is available through `node scripts/application-maintenance-recovery.js --execute`. A disposable 16-store PostgreSQL qualification verified two interrupted recovery attempts followed by successful recovery, preserving store identity, sibling state and private artifacts. It accepts only a recorded, compatible post-provision canonical16 operation, matching private configuration and recovery code, and verified absence of every recorded original/recovery process ancestor. A still-running original terminal, npm parent or application launcher can therefore prevent recovery even after its worker exits; same-shell recovery is not qualified. Do not kill unrelated processes or reboot to bypass these checks: recovery also binds the original boot identity.

Fresh provisioning interruptions, historical ordinary/legacy dirty operations and incompatible recovery code remain outside executable recovery. Preserve the PostgreSQL databases, private credentials and pending journals. Do not delete the marker, edit journal versions, regenerate credentials or reset learner data to bypass admission. See the [local maintenance recovery guide](docs/install/local-recovery-contract.md) for the required ownership checks.

The CTF delivery extension adds a separate generated `CTF_DELIVERY_DATABASE_URL` credential for the existing CTF database; it does not add another database. Setup stores its private ownership record at `~/.dvaia/<workspace-id>/ctf-delivery.json` and adds the URL to private configuration. Keep both that record and its `.pending` journal: an incomplete provision is refused rather than silently recreated or assigned a new password. A retained `.pending` journal alongside a completed record is expected. Provisioning this role does not activate the staged delivery worker; activation and mounted-route qualification remain pending.

The owned MCP/CodeBot runner retains its separate authority selection and private managed configuration at `~/.dvaia/<workspace-id>/mcp-owned.env`; application PostgreSQL or sidecar binding does not rebind it. Linux uses the runner's local Docker/AppArmor path. macOS uses the explicit `DVAIA_MCP_OWNED_COLIMA_PROFILE` value, or `colima-default` when unset. Default local setup requests observed-action, indirect-injection and supply-chain capabilities and enables them only after the runner reports their required capability versions. If provisioning fails, setup exits with an error and retains the staged disabled configuration for repair. Explicit configurations that disable local sidecars or use external services retain optional-runner status reporting. The PostgreSQL container uses a persistent volume and restarts with Docker. Fresh platform setup installs the public training accounts documented in the [installation guide](docs/install/INSTALLATION.md#initial-accounts); its administrator record remains in the private file whose path setup prints. Open `http://localhost:3000` after starting the application.

For an existing provisioned installation whose base MCP runner and CodeBot are already enabled, enable the additional lesson capabilities without rebuilding services or resetting learner data:

```bash
node scripts/install/mcp-owned-activate.js --observed-action --indirect-injection --supply-chain
```

This command checks the existing PostgreSQL schemas, runner capability versions, isolation, CodeBot, conversation store and mail readiness before updating the private managed configuration. It preserves the existing token and unrequested flags. Restart the application with its normal stop/start commands, then check the MCP infrastructure panel for the running process's readiness. Activation does not establish model reliability or award objective credit. HTTP and shadow MCP services have their separate setup/recovery stages below.

If the base runner itself needs provisioning or repair, use `npm run setup:mcp-owned -- --activate-qualified --activate-observed-action --activate-indirect-injection --activate-supply-chain`. On macOS, also pass `--colima-profile` with the installation's `DVAIA_MCP_OWNED_COLIMA_PROFILE` value (normally `colima-default`); retain its Docker authority configuration. This provisions/rebuilds the runner and stages its flags disabled until checks pass; use the activation-only command above when the existing services are already healthy.

To use your own PostgreSQL18 server, set `PG_ADMIN_DATABASE_URL` before setup. The macOS and Linux installers still ensure Docker and Docker Compose are available for the local mail and MCP exercise sidecars; an external database does not replace those services. Setup therefore records the same local Docker authority for those sidecars even when PostgreSQL is external. It skips this local binding when `MCP_SIDECARS_AUTOSTART` is `0`/`false`, when `TEAM_ID` or `ECS_CONTAINER_METADATA_URI_V4` identifies an externally managed task, or when `SANDBOX_RUNNER_URL` names a non-loopback service. Remote PostgreSQL additionally requires `PG_TLS=require` and a server certificate trusted by the Node runtime’s configured certificate authorities; setup does not provide a separate PostgreSQL CA-file setting. Provisioning refuses existing conflicting database/role names and does not overwrite an existing `.env`. A repeated completed provision verifies its private ownership manifest; partial provisioning requires explicit remediation rather than deleting resources.

For an existing installation created by this setup system, preview and apply a suffix-only database upgrade with `npm run setup -- --upgrade --plan` and `npm run setup -- --upgrade`. Supply the original cluster's `PG_ADMIN_DATABASE_URL`, or leave it unset to reuse the existing owned local PostgreSQL state. Upgrade records the local sidecar authority for an external-PostgreSQL installation. For a legacy owned local PostgreSQL installation, it adopts the daemon only after the private state, workspace label, persistent volume, exact container mount and loopback port binding agree; a retained owned volume may recreate a missing container. Upgrade preserves `.env`, application secrets, administrator credentials, existing database credentials and data; it appends and initializes missing store pairs and provisions the separate CTF delivery credential without rotating existing credentials.

An interrupted run safely reuses a matching `local-docker.json` when PostgreSQL state has not yet been written. Do not delete `local-docker.json` or `local-postgres.json` to select a different daemon or recover an installation. A socket that now identifies a different daemon fails closed; restore the selected daemon or perform a reviewed ownership-preserving repair. If a private `local-docker.json.pending`, `local-postgres.json.upgrade`, `provisioning.json.upgrade` or `.env.upgrade` remains after an interruption, inspect it and the corresponding committed state before removing only a confirmed stale staging file and retrying. See the [session-lab upgrade evidence and recovery boundaries](docs/modernization/session-lab-provisioning-upgrade-2026-09-13.md).

The application supports PostgreSQL only. Existing PostgreSQL installations without this setup system's private manifest require reviewed configuration before setup adoption. SQLite archive/import commands are retired from the new repository; preserve any historical data separately before migration or removal. Fresh setup and additive upgrades never import or reset SQLite data.

The macOS and Ubuntu/Debian installer wrappers delegate to `npm run setup`. Native Windows setup, startup and stop are implemented for qualifying x64 Windows Pro, Education and Enterprise hosts with Hyper-V; see the [Windows installation guide](docs/install/INSTALLATION.md#native-windows) for prerequisites and PowerShell commands. Source and isolated checks do not establish fresh-host Windows qualification. The former AWS deployment assets have been removed; optional Bedrock model access remains available through configured provider credentials.

The macOS/Linux installers set up Ollama automatically. Plain `npm ci` installs JavaScript dependencies only; `npm run setup` additionally verifies or downloads `llama3.1:8b` from an already running local Ollama service. Model downloads require internet access, several gigabytes of disk space and sufficient RAM for inference.

### Agent framework and model configuration

LangChain JS and LangGraph JS are application dependencies. The normal root
`npm install` (or `npm ci` from the committed lockfile) installs them; users do
not need a separate Python environment or a global LangChain installation.

LangChain and LangGraph themselves do **not** require accounts or API keys.
Local Ollama inference does not require cloud credentials. Configure your local
`.env` file with:

```dotenv
AI_PROVIDER=ollama
OLLAMA_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://localhost:11434
JUDGE_PROVIDER=ollama
JUDGE_MODEL=llama3.1:8b
AI_OLLAMA_CONCURRENCY=2
AI_OLLAMA_QUEUE_LIMIT=256
```

Workshop attendance and model capacity are separate. The design targets 200 attendees using bounded, queued inference. A [historical 200-attendee PostgreSQL test](docs/modernization/native-workshop-capacity-2026-09-11.md) passed with mock inference; current full-workshop capacity and real-model throughput remain unqualified. The settings above allow two active requests and 256 waiting requests per application process and endpoint; actor and Judge calls share that budget. A full queue returns `AI_QUEUE_FULL` so callers can retry. Ollama monitoring exposes `max_concurrent`, `queue_limit`, and current usage. Size concurrency for the model server, and account for each application process when running multiple replicas. Supporting 200 simultaneous model generations is an infrastructure sizing task, not a laptop requirement.

Start Ollama, then download the model if it is not already installed:

```bash
ollama serve
# In a separate terminal:
ollama pull llama3.1:8b
ollama list
```

The 8B model requires additional disk space and memory beyond the application
itself; model speed depends on your machine. Framework installation does not
automatically download model weights or create provider accounts.

Supported actor `AI_PROVIDER` values are `ollama`, `lmstudio`, `claude`
(`anthropic` is an alias), `chatgpt`/`openai`, and `bedrock`. Optional cloud
providers use your own credentials: `OPENAI_API_KEY` with `OPENAI_MODEL`,
`ANTHROPIC_API_KEY`, or AWS SDK credentials with `AWS_REGION` and
`BEDROCK_MODEL_ID`. Consult the provider configuration supported by the selected
exercise. Keep real credentials in local environment configuration, never in
this README or committed files.

LM Studio is a credential-free local actor provider. Start its OpenAI-compatible
local server, then configure the private `.env` with the exact model identifier
served by your installed LM Studio:

```dotenv
AI_PROVIDER=lmstudio
LMSTUDIO_BASE_URL=http://localhost:1234/v1
LMSTUDIO_MODEL=<your-loaded-model-id>
```

LangSmith tracing is optional and is not needed for local learning or LangGraph
execution.

For optional LangSmith observability, create a key in your own LangSmith account
and add the following to your private `.env`, then restart the application:

```dotenv
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=<your-own-langsmith-key>
LANGSMITH_PROJECT=dvaia-local
# Optional: endpoint for your LangSmith region or self-hosted installation
# LANGSMITH_ENDPOINT=
```

These settings enable the SDK's LangChain tracing integration. Hosted tracing
sends model inputs, outputs and trace metadata to your configured LangSmith
service; use synthetic lab data and keep the key private. Leave tracing unset
or set `LANGSMITH_TRACING=false` for local-only operation. The application's
local run/evidence records remain the authority for objective credit; a hosted
trace is not proof of a completed objective. See the
[official JavaScript SDK configuration](https://github.com/langchain-ai/langsmith-sdk/blob/main/js/README.md).
Hosted tracing has not been qualified with a live account in this audit.

The objective judge is configured independently, so grading and interactive
agents can use different providers or models. Supported `JUDGE_PROVIDER` values
are `ollama`, `claude`/`anthropic`, `chatgpt`/`openai`, and `bedrock`.
`JUDGE_PROVIDER` defaults to `ollama`, and `JUDGE_MODEL` defaults to the
installed `llama3.1:8b`. Those defaults need no credentials and do not download
another model. LM Studio is not supported as a Judge provider; an LM Studio
actor therefore requires a separate supported Judge provider and model. A cloud
Judge uses the corresponding provider credentials from your local environment;
never commit those values.

Model availability does not establish grading accuracy. The current local 8B
configuration failed several DPI, RAG and SecureShop pricing semantic qualification
cohorts; it is not qualified for reliable automatic grading of those unresolved objectives.
The DPI baseline-practice and system-prompt disclosure objectives have separate
scoped qualification on their recorded local-8B paths. Multilingual and
side-stepping have retained scoped evidence from exact local-70B contracts, but
this installation requires `llama3.1:8b` for both actor and Judge. No current
mounted 8B proof exists for those two objectives, so their 70B results do not
qualify the installed profile. These results do not qualify the remaining DPI
objectives or either model as a general-purpose Judge.

The previous DPI multilingual v3 path awarded credit for a Spanish refusal, and
the later local-8B v12/rubric-v15 calibration matched only 2 of 8 expected
outcomes. Those historical paths remain unqualified and their receipts remain
unchanged. The active mounted multilingual path uses the versioned v16 task
integration with the v13 assessment contract. Its retained frozen eight-case local-70B
calibration passed, and a real-JWT browser flow correctly denied an English
AWS-only refusal and awarded the substantive Spanish Paris answer. The scoped
verification includes learner, dashboard and admin parity, reset isolation,
sibling preservation and immutable receipts. Unsupported model and contract
paths remain contained without credit. These receipts do not establish the same
semantics or completion flow with the required local 8B actor/Judge, so current
8B qualification remains open. No cloud Judge is qualified for this objective.

Their unavailable or inconclusive outcomes must not count as completion. See
[current qualification results](docs/modernization/current-release-status.md).
Changing the Judge model requires fresh objective-specific qualification; no
alternative model is assumed to pass.

The fixed-set direct-witness runs that scored 0 of 15 with `llama3.1:8b`, 5 of
15 with `llama3.3:70b`, and 1 of 9 in the compact diagnostic remain historical,
unmounted experiments. They are not evidence for the active path. The mounted
side-stepping v16 successor binds server-generated source IDs and uses a
one-call conjunction Judge. Its retained 70B six-label reducer matched the fixed labels using
five retained real-response replays plus one bounded recovery, and its genuine
local-70B browser flow correctly rejected the AWS-only negative and awarded the
substantive competitor-platform answer. That profile-specific evidence does not
qualify the required current local-8B actor/Judge; no mounted 8B proof is
recorded. Whole-task obfuscation and virtualization grading also remains
unqualified, and the interactive agent model remains independently configured.

Objective credit requires observed evidence and a valid judge verdict. A timeout,
malformed response or missing proof leaves the objective incomplete and reports
unavailable or inconclusive. The local judge uses schema-constrained output and
an explicit 32,768-token context; benchmark receipts record separate judge-policy,
rubric and model versions. See [judge architecture](docs/modernization/judge-architecture.md)
for qualification status and the distinction between live outcomes and teaching simulations.

The XSS workshop uses the production Puppeteer dependency pinned in `package-lock.json` to verify
browser execution in a fresh headless Chrome context. Supported setup performs
strict locked installs and provisions Puppeteer's compatible Chrome when it is
missing on macOS and Linux x86-64. Linux ARM64 has no matching Puppeteer Chrome
download, so the Ubuntu/Debian installer supplies a system Chromium executable.
If your installation sets `PUPPETEER_SKIP_DOWNLOAD`, provide a compatible browser
with `PUPPETEER_EXECUTABLE_PATH` and the operating-system libraries required by
headless Chrome. Downloads use Node's system certificate trust. The verifier keeps Chrome's sandbox enabled, uses synthetic
fixture cookies, and blocks external requests. If Chrome cannot start or the
bounded verification times out, the judge reports missing evidence and awards
no objective credit; the application process remains available.

CSRF GET/POST objectives use **Execute observed payload** to submit the editor's
unchanged HTML to a fresh managed Chrome context. Its attacker and victim URLs
are separate same-site `.invalid` origins intercepted inside the lab, with a
synthetic victim cookie and the learner's isolated victim state. Exported HTML
is for inspection; those URLs do not resolve outside managed execution. A manual
request or a claimed success cannot award these objectives: grading requires the
private observed-browser receipt, current run scope and actual action/defense
evidence. The endpoint requires the learner's validated bearer session and is
limited to 12 attempts per minute per learner and four concurrent browsers per
application process. This is a resource bound, not proof of capacity for a
200-person workshop. This browser path has no containerized deployment
qualification.

Optional LangSmith export is off by default. If you explicitly enable it, use
your own `LANGSMITH_API_KEY`, `LANGSMITH_PROJECT`, and optional
`LANGSMITH_ENDPOINT`. Local graph execution, judging, and the Agent Run
Inspector do not depend on LangSmith.

Run `npm run test:ollama:8b` to exercise the ARIA/NOVA graph paths against
local Ollama with in-memory fixtures. Run `npm run test:modernization` for
focused offline regression tests, and `npm run verify:learning-dependencies`
to check the preserved learning dependency versions.

### Optional: Gmail SMTP

The **Email Agent** challenge needs Gmail App Password credentials only when `IPI_EMAIL_PROVIDER=gmail`. The **XSS Workshop email tab** needs them only when `XSS_MAIL_PROVIDER=gmail`. See **[docs/install/SMTP_SETUP.md](docs/install/SMTP_SETUP.md)**
for setup steps. Configure these optional credentials in your private `.env` after installation.

The XSS email exercise defaults to the local Mailpit sidecar (`XSS_MAIL_PROVIDER=mailpit`), with a separate server-assigned inbox for each signed-in student. It does not require Gmail credentials. Fresh setup provisions the same owned loopback Mailpit service for the Email Agent and writes `IPI_EMAIL_PROVIDER=mailpit` with a private HMAC secret; setup verifies the API and SMTP listener before provisioning application databases. Set `IPI_EMAIL_PROVIDER=gmail` explicitly for the external Gmail/temporary-inbox workflow. Existing `.env` files keep their selected provider. External providers may filter HTML, so that workflow is not yet qualified for exact exploit-body preservation. Local Mailpit capture proves owned local delivery/readback, not external Gmail delivery.

---

## Quick Start

After setup, use the supported launcher from the repository root:

```bash
./start_all.sh          # macOS / Linux: backend (:8081) + frontend (:3000)
```

On qualifying x64 Windows Pro, Education or Enterprise hosts with Hyper-V, use `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1` for foreground startup, add `-Stop` for owned shutdown, or add `-Plan` for a no-changes preview. See the [Windows installation guide](docs/install/INSTALLATION.md#native-windows). Fresh-host Windows execution has not been qualified. On supported local systems, keep PostgreSQL and Ollama available; run `ollama serve` separately if needed. The application launcher does not install prerequisites or start Ollama.

Stop with Ctrl+C in the launcher terminal, or `./stop_all.sh` on macOS/Linux. `./start_all.sh --init-db` applies pending migrations and idempotent seeds first; it does not erase data. Use authenticated exercise controls for resets.

`npm run dev` is a developer-only file-watching command. It bypasses the supported launcher's preflight and workspace stop controller.

`npm start`, `npm run server` and `npm run dev` also require both `PLATFORM_DATABASE_ENGINE=postgres` and `WORKSHOP_DATABASE_ENGINE=postgres`. Missing configuration stops startup before database imports instead of opening legacy SQLite files. The test marker does not enable a SQLite application mode; database qualification must use owned disposable PostgreSQL stores.

To clear an account's failed-login lock, run `node scripts/admin/unlock-accounts.js --username student` from your installation. Use `--all` only to clear locks for every account. This maintenance command uses the configured PostgreSQL identity database; it does not reset passwords or reactivate disabled accounts. With no arguments it prints help and makes no changes. Use your installation’s current credentials; repair and upgrade do not reset passwords.

For password recovery, use `node scripts/admin/reset-auth-defaults.js --username <username> --password-stdin < /path/to/private-password-file`. Despite its legacy filename, this command uses no default password: it reads the new password from stdin, updates only the selected account, clears its login lock, and revokes its active sessions. Keep the password file private or pipe the value from your password manager. Account roles, activation and learner progress are preserved. The real command-line process and PostgreSQL transaction path have passed isolated tests, including disabled-account preservation and rollback when session revocation or audit logging fails.

For a main-only platform unit check without copying the repository, run `node scripts/test-main-platform.js` (or add `--plan` for a non-mutating preview). This bounded profile runs five suites covering audit metadata, session validity, authentication session handlers, instructor/student handlers and administrator role updates. It uses private evidence directories and denies database, network, model and subprocess activity inside the tests. The current stack passed all 13 selected tests with owned-child cleanup verified. This is a focused check, not the full `npm test`, SecureShop, frontend or native qualification suite.

For a focused unit regression, use `node scripts/test-isolated.js unit tests/mcpOwnedResourceRoute.test.js` (additional test paths may follow). This runs the main checkout behind the private-configuration/database boundary, with disposable test data and disabled live services; it does not copy application source. Avoid invoking route tests directly in the working tree: legacy module imports can initialize database files before assertions run. Tests requiring a running server need their separate owned integration harness.

On macOS, run `npm run test:native-operator` for the owned synthetic process-inspector tests. This is separate from the unit profile and does not qualify an installed application or Linux runtime.

The verifier process tests require native process inspection: `node --test --test-timeout=15000 tests/transformers43QualificationRunner.test.js`. They use owned synthetic fixtures and verify child/grandchild cleanup; they do not download models or qualify embedding behavior. This explicit check is separate from the sandboxed unit aggregate.

`npm run test:native-browser` runs the closed macOS browser suite with owned profiles and process cleanup. It is separate from unit tests and does not qualify actual-model behavior or the complete installed application. Set `PUPPETEER_EXECUTABLE_PATH` to an installed supported Chrome executable when needed.

`npm run test:admin-bundle` builds the application into owned temporary output behind the private-data fence, then renders its admin route in Chrome. API responses are controlled; this does not qualify the full authenticated installation.

Native PostgreSQL checks use scenario-specific owned launchers under `tests/postgres/`, with disposable stores and explicit runtime/resource configuration. The legacy `npm run test:postgres` alias currently refuses execution; it is not a supported aggregate qualification command. Use the exact launcher and prerequisites recorded for the scenario being verified, and never supply application or learner database URLs. Native database checks and real-model Judge qualification are separate; see the [current release status](docs/modernization/current-release-status.md) for verified scopes and remaining gates.

---

## Access Points

| URL | Purpose |
|-----|---------|
| `http://localhost:3000` | Main frontend |
| `http://localhost:3000/workshop-login` | Student / instructor login |
| `http://localhost:3000/admin` | Admin dashboard |
| `http://localhost:3000/ctf` | CTF platform |
| `http://localhost:8081` | Backend API |
| `http://localhost:8081/api/monitoring/health` | Health check |

---

## Default Credentials

See [Initial accounts](docs/install/INSTALLATION.md#initial-accounts) in the installation guide for fresh platform and SecureShop logins. Existing installations retain their current credentials.

---

## Challenges

### AI Security
| Challenge | Description |
|-----------|-------------|
| **CTF Prompt Injection** | 10-level Gandalf-style prompt-injection CTF with adaptive defenses |
| **Direct Prompt Injection** | Manipulate AI assistants directly — 8 objectives |
| **Indirect Prompt Injection (RAG)** | Inject via RAG documents and external data |
| **Agentic AI Tool Extraction** | Extract tools and data from AI agents |
| **File Reading Agent** | Exploit an AI agent with file system access |
| **Email Agent (SSRF/Injection)** | Abuse an AI email agent |
| **Excessive Agency / BOLA Lab** | Exploit over-privileged AI actions |

### Web Security
| Challenge | Description |
|-----------|-------------|
| **SQL Injection** | Classic SQLi on an isolated vulnerable database |
| **XSS Workshop** | Reflected, stored, LLM-generated, email-based XSS |
| **SQL + NoSQL Workshop** | Combined injection workshop |
| **Sensitive Info Disclosure** | Data exfiltration practice |
| **Order Query Challenge** | Business logic and injection |
| **Remote Code Execution** | RCE challenge environment |

### SecureShop v2
An end-to-end LLM-driven e-commerce app that ties LLM, MCP, and Web Top 10
categories together. Three role personas (customer, merchant, admin), an
Agent Host of 17 MCP servers, and 70+ intentional vulnerabilities. See
[`docs/secureshop/README.md`](docs/secureshop/README.md).

---

## Architecture

```
React/Vite (port 3000) → Express (port 8081) → PostgreSQL platform + migrated workshops
                                             → LangGraph + LangChain → Ollama (port 11434)
                                             → Agent Host (port 8082, SecureShop MCP)
```

The PostgreSQL-selected application supports16 repositories and17 SecureShop agents without loading SQLite or MySQL drivers. The session-disclosure lab and the owner-bound SecureShop review store each use a dedicated database and restricted roles; neither may reuse an identity or intentionally injectable commerce connection. Existing installations add these stores through the explicit additive provisioning/configuration upgrade. The bound review route remains disabled by default pending coherent catalog/runtime activation. Earlier owned review-store and reset checks cover limited configurations; current assembled browser qualification remains pending. Legacy SQLite import is outside the supported application. Complete exploit parity remains a tracked release gate. Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

**AI Engine** — Local Ollama with `llama3.1:8b` is the default. Migrated
LangGraph workflows require an available configured model; mock responses do
not qualify actor or Judge evidence. Some legacy provider paths can try other
configured providers when one is unavailable. Optional AWS Bedrock, OpenAI,
and Anthropic credentials belong in private environment configuration.

**Agent runtime** — LangGraph owns model-decision, validation, conditional
tool, response, persistence, and judge branches for migrated agent families.
LangChain supplies provider messages and typed model/tool calls. Coverage is
still being expanded across every objective; see
[`docs/modernization/judge-coverage.md`](docs/modernization/judge-coverage.md).

Document RAG is still being migrated: the active query path uses a fixed
retrieval/generation graph, and its uploaded corpus remains process-local.
The staged model-selected search loop and PostgreSQL source/revision storage
are not yet the default. Do not restart an existing workshop assuming its
uploaded documents are included in database backups. See the
[RAG durability status](docs/modernization/workshop-rag-durability.md) and
[decision-loop qualification](docs/modernization/rag-agent-decision-loop.md).

---

## Admin Dashboard

Access at `http://localhost:3000/admin` (requires admin login).

- **Student Management** — create, edit, delete accounts
- **Exercise Management** — toggle individual challenges or bulk enable/disable
- **Locked Users** — view and unlock rate-limited accounts
- **Solutions Management** — control solution visibility per challenge
- **Activity Logs** — real-time monitoring of user actions
- **LLM Health** — AI service status
- **Progress Analytics** — student completion rates

Student password recovery is instructor-managed: use **Student Management** to
change the student's password; existing platform sessions are revoked. Use
**Locked Users** separately if the account is locked. The public
`/api/auth/reset-password` endpoint reports `PASSWORD_RESET_INSTRUCTOR_MANAGED`
and does not send email. Self-service email recovery is not configured.

---

## Environment Variables (`.env`)

```
PORT=8081
OLLAMA_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://localhost:11434
JUDGE_PROVIDER=ollama          # ollama | claude/anthropic | chatgpt/openai | bedrock
JUDGE_MODEL=llama3.1:8b       # defaults to the installed 8B model
JUDGE_CONTEXT_TOKENS=32768   # bounded context for full structured grading evidence
SS_AUDIT_RUN_TIMEOUT_MS=120000    # Audit summary whole run; supported 10100–290000
SS_AUDIT_JUDGE_TIMEOUT_MS=90000   # Audit-only aggregate Judge; supported 100–240000
SECURITY_TESTING_MODE=true
LAB_MODE=vuln                 # "vuln" or "fixed"
NODE_ENV=development
AI_PROVIDER=ollama            # ollama | lmstudio | claude/anthropic | chatgpt/openai | bedrock
```

When the actor and Judge share one Ollama model, different context sizes can
force model reloads between their calls. For the local `llama3.3:70b` workload,
set both `OLLAMA_CONTEXT_WINDOW=32768` and `JUDGE_CONTEXT_TOKENS=32768` in the
private `.env`, then restart the application. This keeps the complete grading
evidence and existing timeouts; it uses more memory than an 8192-token actor
context. The shared-context configuration still requires qualification on the
host hardware and does not establish that every objective passes.

DPI runs have a five-minute server deadline covering the actor, decoder when
needed, and Judge. The chat client and local proxies wait slightly longer so
they can receive that bounded run's result. Reset and session invalidation
still cancel or fence work; longer transport waits do not permit stale credit.

Judge qualification (local Ollama8B, recorded/synthetic evidence, no email delivery):

```bash
npm run test:judge:8b
npm run test:judge:8b -- IPI CSRF  # selected families
npm run test:judge:8b -- LegacyEmail  # separate legacy email levels
```

At the recorded definition-coverage checkpoint, the catalog control checked 136 canonical workshop objectives across 12 families: 130 have adapter definitions and six SecureShop objectives have explicit pending dispositions. The five legacy sensitive-file objectives are included in that catalog; the ten-stage CTF and four legacy email-builder levels are separate. Current membership and aliases are documented in the [matrix namespace explanation](docs/modernization/current-exercise-authenticity-matrix-2026-09-15.json); see [local release limitations](docs/LOCAL_RELEASE.md) for the current release boundary. Definition coverage and source eligibility do not establish actual-model, rendered or installed qualification. The qualification command requires every known positive to pass and every known negative to explicitly fail. Unavailable, inconclusive, missing and duplicate assessments fail benchmark qualification, while safety tests separately verify that they award no credit. These tests supplement application integration and intentional-vulnerability checks. To summarize a saved qualification log, run `node scripts/summarize-judge-log.js <log-path>`. The report separates explicit pass/fail results, inconclusive/unavailable results, repairs and latency, and flags missing diagnostic metrics. See [adding a judged objective](docs/modernization/judge-objective-authoring.md) for the implementation and verification contract.

A judge `pass` becomes completion only after the server accepts the evaluation receipt for the current user, objective, mode and reset generation. `Fail` means the observed attempt did not meet the rubric; `inconclusive` means the evidence could not establish it; `unavailable` means evaluation could not finish reliably. When retained evidence permits recovery, use **Retry evaluation** or find the evaluation in the run inspector after refreshing. Recovery grades the saved evidence without repeating the exercise tools. Reset invalidates older pending evaluations.

Defense objectives distinguish resisting an injection from successfully executing an attack. The IPI email-defense objective additionally compares the email content supplied to the actors with every part of the actual response through an independent, tool-free Judge step. A valid summary followed by execution of the injected instruction is a failed defense. Both grading stages appear in local run traces; missing or oversized evidence cannot silently bypass verification.

MCP configuration-disclosure credit uses verified bytes from the current lab configuration, bound to the invoking run. A secret-looking answer alone is insufficient. Required server facts are checked again before completion is saved, including when retrying evaluation. See the [configuration evidence checkpoint](docs/modernization/mcp-config-evidence-gap-2026-09-13.md) for verification and remaining isolation limits.

Local LangChain, LangGraph and Ollama judging require no API credentials. Cloud judge providers use the corresponding optional provider credentials documented above; LangSmith tracing is optional and disabled by default. Never place real API keys in this README.

SecureShop supports an optional absolute `SECURESHOP_UPLOAD_ROOT` shared by the backend and agent host. Leave it unset for the existing upload location. Before changing it, preserve and verify the owned synthetic asset tree with both processes stopped; configuring a path does not migrate assets.

`SS_ENABLE=true` boots the independent SecureShop core and its standalone shop
session; it does not require a platform login, but it does require all 16
configured and migrated PostgreSQL stores, including `secureshop_review`.
Platform launch preparation is a separate optional integration controlled by
`SS_LAUNCH_PREPARATION_ENABLED`. The full six-panel bound application is also
off by default and requires `SS_BOUND_REVIEWS_ENABLED=true`; that flag controls
bound-surface exposure, not the review-store schema requirement. Startup refuses
incomplete requested configuration, and each requested policy, System, Pricing,
Analytics, Listings or MCP service retains its own readiness gate. These flags
do not enable curriculum entries or establish broad workflow qualification. See the [current release status](docs/modernization/current-release-status.md)
for remaining native, rendered and model gates.


See [`.env.example`](.env.example) for the full list including cloud LLM
fallback and live-event gate settings.

---

## Documentation

- [Quick start](docs/QUICK_START.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security policy](docs/SECURITY.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Workshops index](docs/workshops/README.md) — includes the [95-minute workshop outline](docs/workshops/WORKSHOP_OUTLINE.md)
- [SecureShop v2](docs/secureshop/README.md)

---

## Troubleshooting

**Port already in use:**
Stop the application process you previously started, or choose another configured port. The PostgreSQL launcher does not kill unrelated processes.

**Apply database migrations:**
```bash
npm run db:initialize-all    # PostgreSQL migrations and idempotent seeds
```

Use authenticated workshop reset controls to reset learning progress. Startup does not delete database files. Legacy SQLite initialization is not a supported setup or reset command.

The compatibility commands `npm run deploy:fresh` and `npm run deploy:full` also apply PostgreSQL migrations and idempotent seeds to configured stores. First-time provisioning uses `npm run setup`. Direct `deploy:reset` and `deploy:reset-full` commands are disabled; use the authenticated workshop reset or student deletion controls so external resources and progress are cleaned up together.

PostgreSQL startup also verifies the complete student-deletion cleanup registry before accepting requests. An incomplete migration or missing cleanup capability stops startup; inspect the startup error and run the normal initializer after correcting the configuration. `LEGACY_PLATFORM_LIFECYCLE_ENABLED=false` is an explicit maintenance opt-out: it restores pre-lifecycle legacy mutation/upload behavior and makes account deletion unavailable. Normal installations should leave this variable unset.

**Owned System package changed (existing ARM64 installation):**
After updating the code, stop the app and explicitly upgrade its installed System package:

```bash
./stop_all.sh
node scripts/install/secureshop-owned-system-upgrade.js --upgrade
./start_all.sh --init-db
```

The upgrade verifies resource ownership and readiness, preserves credentials and the restart-state volume, and retains a private original-configuration receipt. It does not reset databases. If interrupted, keep the app stopped and run the same script with `--recover` before retrying. Do not edit managed checksum records manually. This package upgrade path is ARM64-only; it does not qualify the AMD64 candidate.

**AI challenges not working:**
```bash
ollama pull llama3.1:8b       # Download model
ollama serve                  # Start Ollama
```

More: per-OS troubleshooting in [`docs/install/`](docs/install/).

---

## License

GNU General Public License v3.0. Inspired by [DVWA](https://github.com/digininja/DVWA) and [WebGoat](https://github.com/WebGoat/WebGoat).

Use your skills ethically — practice here, protect everywhere.

### Owned HTTP workshop service recovery

CSRF email and retrieved-document summaries use a 25000 ms model-stage limit by
default. Set `CSRF_HTML_SUMMARY_TIMEOUT_MS` in private configuration only when
the selected model needs more time; the accepted range is 1000–55000 ms. This
does not extend the existing CSRF owner-run or Judge deadlines, and a longer
limit alone does not establish objective completion.

MCP model timing is configurable in the private `.env` through
`MCP_DECISION_TIMEOUT_MS`, `MCP_RESPONSE_TIMEOUT_MS` and `MCP_RUN_TIMEOUT_MS`.
Defaults are 30000, 30000 and 120000 milliseconds; maximums are 90000, 90000
and 290000. Each model-stage limit must fit within the run limit. All decisions,
tools and grading share the existing owner-run deadline; retries do not extend
it. Larger limits require qualification with the selected model and do not
establish that a model is accurate or fast enough for a workshop.
`MCP_RECON_JUDGE_TIMEOUT_MS` separately controls recon grading, with a 90000
millisecond default and a 120000 maximum. It must fit within the configured run
limit and still shares that run's remaining time. The same setting applies to
the existing owner-bound retry of the saved evidence packet; retry does not
replay the actor or change the historical packet. Other objectives keep their
existing Judge limits. Qualify an increased limit before relying on it.
Graded recon responses require actual model
output; an offline catalog fallback cannot substitute for that evidence.

Fresh local setup provisions the isolated HTTP exercise service after the owned
MCP/CodeBot runner and PostgreSQL schemas pass readiness. It preserves a private
service token in `~/.dvaia/<workspace-id>/mcp-owned-http.json`; no external API
credential is needed for this teaching service. If this setup stage fails, repair
the reported CLI, Docker/AppArmor or database prerequisite and run
`node scripts/install/mcp-owned-http-setup.js`. This resumes the HTTP stage without
resetting databases or replacing learner documents. The selected macOS Colima
profile is retained in private configuration.

### Owned shadow MCP service recovery

Local setup also provisions the shadow MCP peer service with a private token and
runtime fingerprint in `~/.dvaia/<workspace-id>/mcp-owned-shadow.json`. It needs no
external MCP credentials. Resume a failed stage with
`node scripts/install/mcp-owned-shadow-setup.js`; existing state and credentials
are preserved. A changed image requires a reviewed drain/upgrade rather than
silently replacing active learner targets. Corporate TLS environments can supply
a trusted PEM bundle through `NODE_EXTRA_CA_CERTS`; the shadow image build uses
it as an ephemeral BuildKit secret and keeps certificate verification enabled.

The shadow exercise reads a real synthetic policy file in the learner's isolated
target. The policy editor preserves pending saves across retries, and loading or
editing the file never earns completion credit. Registration and a subsequent
model-selected invocation must be verified separately by the Judge. See
[the qualification record](docs/modernization/mcp-owned-shadow-server-design.md)
for the current source-release and installed-activation status.

### Owned SecureShop audit SQL service

Fresh local setup also provisions a separate synthetic-only PostgreSQL teaching
service. Its private configuration is `~/.dvaia/<workspace-id>/audit-sql-target.json`;
no external API credentials are required. Setup checks the application migration
checksums, runtime privileges and private daemon before activating newly created
configuration. Existing disabled preferences are preserved. Resume failed
provisioning with `node scripts/install/audit-sql-target.js` after repairing the
reported local Docker or schema prerequisite. This does not reset learner data.

Within an enabled bound SecureShop workshop, sign in as the admin persona and open
Audit. **Search** executes the manual SQL teaching query; **Ask audit agent** uses
the configured model and canonical Judge. The separate SQL extraction objective
is instructor-enableable and disabled by default. Neither manual search nor a
model claim without the current owned effect earns model objective credit.

### Existing owned Analytics installations

After updating application code, stop the application and run:

```bash
./stop_all.sh
npm run setup -- --upgrade --owned-analytics
./start_all.sh
```

This applies additive application migrations and upgrades the existing private
Analytics control schema to version 2 without resetting learner data. It
preserves the private cluster identity and existing enabled/disabled preference.
An installation with owned Analytics must include `--owned-analytics` during
setup; omitting it reports the required command before schema changes. Applying
application migration 0034 alone is insufficient: enabled Analytics requires
the matching private control schema and captured-mode runtime. Explicitly add
`--enable-owned-analytics` only when deliberately enabling a disabled feature.

### Local workshop email addresses

Local registration does not send verification mail or establish mailbox ownership. Accounts can log in without email verification; public verification and resend endpoints report that verification is unavailable. Instructor-created accounts retain their existing account attestation and permissions. The historical `email_verified` flag is not proof of external mailbox ownership. Changing a profile email clears that flag and retires pending tokens; changing only a name preserves it. Synthetic teaching mailboxes are separate from platform identity. Real email ownership verification requires a separately configured and qualified delivery flow.

`node scripts/test-native-browser.js --secureshop` runs the five SecureShop browser suites with owned Chromium profiles and fixed test-name checks. These controlled-provider tests qualify browser boundaries, not genuine LLM objective completion.

`node scripts/test-native-browser.js --xss` runs the four XSS browser/grading suites with owned Chromium profiles and controlled Judge/evidence services. Real browser execution here does not establish genuine model completion.

`node scripts/test-native-browser.js --secureshop-e2e` builds the actual app once into private-fenced owned output and runs the three fixed nested SecureShop browser flows plus the stored-review browser sink test. Fixture APIs are controlled; this is separate from `--secureshop` and genuine model qualification. The SecureShop unit aggregate explicitly defers these browser flows.
