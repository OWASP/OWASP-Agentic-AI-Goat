# Installation guide

This is the main installation guide. It covers components, fresh installation, daily startup, repair and troubleshooting. Optional email and advanced exercise setup remain separate only where needed.

| Platform | Current installation status |
| --- | --- |
| macOS | Implemented; reviewed with isolated tests and previously recorded current-host evidence |
| Ubuntu / Debian Linux | Implemented; reviewed with controlled installer tests |
| Native Windows | Setup/start/stop implemented; source and isolated controls verified; see requirements below |

Reviewed code and controlled tests establish engineering confidence, not proof of installation on every host. No new live or clean OS installation qualification is claimed. The Windows path passed source-integrity and isolated integration checks; interpreter-dependent PowerShell checks were skipped on this host.

Run the installer as your normal user from a downloaded or cloned checkout. Do not prefix the whole command with sudo: package operations request administrative access separately, and the exercise browser needs its user sandbox.

```bash
# macOS
bash scripts/install/Mac/install-macos.sh

# Ubuntu / Debian
bash scripts/install/Linux/install-linux.sh

# Preview without Node, downloads, package changes or service startup
bash scripts/install/Mac/install-macos.sh --plan
```

Use the Linux path for its preview. After setup succeeds, run `./start_all.sh`, open `http://localhost:3000`, and use the administrator credentials in the private file printed by setup. Stop application processes with `./stop_all.sh`. The launcher locates supported Node installations in standard Homebrew or `/usr/local/bin` paths without editing shell profiles.

## Initial accounts

A fresh platform database starts with these two public training accounts:

| Login | Username | Password |
| --- | --- | --- |
| Platform administrator | `admin` | `admin123` |
| Platform student | `student` | `student 123` |

The student password contains one space. Sign in through `/workshop-login`. The administrator has level 2 authority and workshop-management permissions. Setup retains its credential record at the private `administrator.json` path it prints; passwords in PostgreSQL are hashed. Existing installations keep their current accounts and passwords: repair, upgrade and repeat initialization do not reset them to these defaults.

SecureShop opens at `/secureshop` and uses its own sign-in at `/secureshop/login`. No workshop account or second sign-in is required. Guests can browse products; customers, merchants and shop administrators share the installation’s storefront with separate permissions and private customer carts.

Fresh SecureShop installations create these practice accounts once:

| Practice role | Username | Password |
| --- | --- | --- |
| Customer | `student_customer` | `student123` |
| Merchant | `student_merchant` | `student123` |
| Shop administrator | `student_admin` | `student123` |

SecureShop also retains synthetic lesson personas and legacy aliases referenced by its products, orders and reviews. These do not grant platform administrator access. SecureShop's password has no space. Repeat initialization preserves changed credentials and disabled accounts; it does not recreate removed defaults. Customer and merchant registration is available from the shop login page.

At runtime, `SS_ENABLE=true` composes the standalone SecureShop core, including
the independent shop sign-in, public catalog and customer, merchant and shop
administrator routes. It requires all 16 configured and migrated PostgreSQL
stores, including `secureshop_review`. The full six-panel bound application is a
separate opt-in through `SS_BOUND_REVIEWS_ENABLED=true`; that flag controls
bound-surface exposure, not the review-store schema requirement. Requested
optional services retain their individual configuration and readiness gates. An
isolated PostgreSQL run verified the real backend's public catalog, shop login,
cart access and shutdown after canonical setup primitives. This does not qualify
the complete installer or a clean operating-system installation.

Supported setup also provisions the bound upload asset listener as one private,
all-or-nothing environment tuple. It proves that the host-assigned IPv6
loopback address `::1` can accept a listener, selects a currently free private
port, and records the exact bracketed origin `http://[::1]:<port>` with a
generated capability secret. Setup never creates a loopback alias or edits host
network configuration. The ordinary application remains available through its
documented `localhost` and `127.0.0.1` origins; those exact origins remain the
shared platform authority and `::1` must not be added to `SS_ALLOWED_ORIGINS`.
An existing complete valid upload-listener tuple, including a supported legacy
distinct `127/8` listener, is preserved. An explicit disabled setting is also
preserved. A partial or invalid tuple stops setup without overwriting any of its
values or printing the capability secret. `npm run setup -- --plan` reports the
plan without opening a socket; executing setup performs the real `::1` probe
when it provisions a missing tuple.

`SS_SESSION_TTL_SECONDS` optionally shortens shop login and renewal to 120–14400 seconds (default 4 hours).
`PLATFORM_SESSION_TTL_SECONDS` optionally caps platform sessions at 120–86400 seconds; omitted defaults remain 24 hours for login and 1 hour for secure-login. Invalid values stop startup; existing sessions keep their recorded expiry.

## Add an administrator

Sign in as a level 2 administrator with `user_management` permission, then open **Settings → User Management → Add administrator**. Enter the new account details, choose its level and explicit permissions, and submit the form. Duplicate usernames or email addresses are rejected. Students and level 1 administrators cannot create administrator accounts.

The levels are enforced by the server: **Level 1 — instructor** supports permitted workshop operations; **Level 2 — elevated administrator** is also required for protected account/system operations. Individual permissions still apply at both levels. Account creation records an audit event and never exposes the password hash.

## Components installed or verified

| Component | Installation behavior |
| --- | --- |
| Node and npm | Requires Node26.10.0 and npm12.1.0 or newer, retaining newer installed versions. macOS installs/upgrades Homebrew Node or npm when needed. Linux installs the pinned Node26.10.0 official archive after SHA256 verification and updates npm when either floor is unmet. |
| Git and native build tools | Homebrew/Xcode Command Line Tools on macOS; apt build-essential, Python and supporting packages on Linux. |
| Native Windows prerequisites | On supported Windows hosts, the PowerShell coordinator verifies or provisions Node26.10.0/npm12.1.0 or newer, Git, x64 Python3.11–3.14, Visual Studio/MSVC with the Windows SDK, Ollama, Multipass1.16.4 and Microsoft OpenSSH. Docker runs in the admitted Multipass guest; host Docker Desktop is not required. |
| LangChain / LangGraph | Exact application versions installed by root `npm ci`; no global package, Python installation or framework API key required. |
| Frontend and backend libraries | Both committed lockfiles installed with `npm ci`; protected learning dependency pins remain unchanged. |
| PostgreSQL18 | Dedicated loopback-only Docker container and persistent volume, with16 isolated application stores and separate runtime/migration roles. A host PostgreSQL package is unnecessary. |
| Docker runtime | Local exercise sidecars require Docker even when PostgreSQL is external. macOS installs the Docker CLI and Colima when missing, then starts the explicit Colima profile used by the owned runner. Ubuntu/Debian installs Docker Engine when absent and starts its service. |
| Ollama and model | Installs Ollama if missing, starts the local service, checks `llama3.1:8b`, and pulls it only when absent. Agent and Judge use the same installed model by default. |
| SecureShop agent host | With `SS_ENABLE=true`, startup automatically supervises the local agent host. `SS_AGENT_HOST_PORT` must be free and distinct from application ports (default 8082); do not launch the host separately. |
| Document embedding model | Fresh setup downloads/caches `Xenova/all-MiniLM-L6-v2` q8 and verifies a finite384-dimensional embedding before provisioning. The cache lives in the workspace's private setup directory unless an absolute `XENOVA_CACHE` is supplied. Downloads use Node system CA trust with TLS verification enabled. |
| Exercise browser | Strict npm installation plus setup provisions Puppeteer's Chrome on macOS and Linux x86-64 when missing. Linux browser libraries are installed. Because Puppeteer has no matching Linux ARM64 Chrome download, Debian ARM64 installs distro Chromium and Ubuntu ARM64 installs Canonical's confined Chromium Snap. Setup must successfully launch and close a sandboxed browser before provisioning databases. |

The shared `npm run setup` command assumes native prerequisites are installed and Ollama is running. `--no-install` skips npm installation only; framework/model/browser checks still run. It never suppresses prerequisite installation in an OS wrapper.

No `.env` is overwritten. An existing `.env`, including a symlink, stops the OS wrapper before package changes. Existing installations follow the [migration runbook](../modernization/local-existing-installation-upgrade.md); removing `.env` is not an upgrade strategy. Interrupted fresh setup preserves its private provisioning state for diagnosis and never deletes existing databases.

## Repair an existing installation

Stop the application, keep its recorded Docker daemon running, and use the matching OS installer with `--repair`. Add `--plan` for a non-mutating preview. Repair retains the private environment, administrator credentials and learner data while reinstalling locked application dependencies, verifying the browser/model and using the additive database upgrade. macOS repair does not start another Colima profile or switch the Docker context. Plain `--upgrade` remains database-only. Direct `npm run setup -- --repair` assumes the native OS prerequisites already exist.

## Supported systems and requirements

- macOS: 64-bit Apple Silicon or Intel, on a version supported by the selected Homebrew/Ollama packages. Homebrew currently recommends macOS15+; Intel support has a lower support tier. macOS may require you to complete a developer-tools or application authorization dialog. The script waits for developer tools and service readiness, then reports a failure if they remain unavailable.
- Linux: Ubuntu/Debian with apt. Ubuntu24.04 and Debian13 package resolution is checked separately from complete OS installation. Other distributions fail before changing packages; install prerequisites with the distribution's supported tools and then use `npm run setup`.
- Windows: x64 Windows10 build19045 or newer or Windows11 Pro, Education or Enterprise with Hyper-V enabled, the Hyper-V PowerShell module, and normal-user membership in Hyper-V Administrators. See [Native Windows](#native-windows) for the supported setup, start, stop and recovery commands; clean-host native Windows execution is not claimed.
- Linux x86-64 uses Puppeteer's downloaded browser. Debian ARM64 automatically installs distro Chromium. Ubuntu ARM64 automatically installs Canonical's confined Chromium Snap and uses `/snap/bin/chromium`. That path requires a normal systemd-based Ubuntu host so `snapd` can start; a non-systemd environment stops before package changes and must supply a sandbox-capable browser through `PUPPETEER_EXECUTABLE_PATH`. It does not disable or reconfigure browser sandboxing, AppArmor, or user-namespace protections.
- Optional owned SecureShop system, pricing, listings and registry capabilities have separate architecture and sandbox requirements. General installer support does not establish that every optional capability works on Intel/x86-64; the owned system amd64 candidate remains disabled.
- Allow several gigabytes for the model and browser, plus container storage. At least16GB RAM is recommended for a local8B workshop; actual inference speed depends on hardware. Internet access is required for missing downloads. No GPU driver or global sandbox-security changes are made.

On Linux, adding Docker group membership continues setup in a refreshed user process. Existing terminal/login sessions need sign-out/sign-in before using Docker directly. Docker-group membership grants powerful host access; use a trusted local workshop account. If sudo policy prevents group refresh, sign in again and rerun.

Exercise visibility and objective availability are separate administrator controls. In **Manage Objectives**, use **Enable Available Objectives** or individual switches; hint/solution controls do not enable objectives. SecureShop objectives start disabled. Curriculum qualification does not provision their optional services: enable only objectives whose required local capabilities are available. Pending objectives remain excluded by the server.

### Optional owned strict policy renderer

The SecureShop strict policy renderer is not installed or enabled by ordinary
setup. It uses two paired setup flags:

```bash
# Non-mutating preview
npm run setup -- --plan --owned-policy-renderer --enable-owned-policy-renderer

# Fresh setup with explicit activation
npm run setup -- --owned-policy-renderer --enable-owned-policy-renderer

# Additive setup for an existing installation
npm run setup -- --upgrade --owned-policy-renderer --enable-owned-policy-renderer
```

`--enable-owned-policy-renderer` requires `--owned-policy-renderer`. Running
with only `--owned-policy-renderer` prepares or verifies the managed renderer
without changing an existing disabled preference. Explicit activation records
the private loopback origin only after the renderer reports ready and enabled;
an interrupted attempt retains its private setup state for a bounded retry.

The installer accepts ARM64 macOS and Linux only. It requires the installation's
recorded local Docker authority and an enforced exact workspace AppArmor
profile. Windows and x86-64 fail closed. The managed listener defaults to
`127.0.0.1:8098`; repeat setup preserves its recorded port and identity. This
renderer boundary does not claim outer network-egress isolation. The documented
surface has controlled test coverage, but a completed cold-host or native
platform qualification is not claimed.

## Services and recovery

If npm reports `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` on a network whose CA is
already trusted by your operating system, run the failed npm command with
`NODE_USE_SYSTEM_CA=1`, for example `NODE_USE_SYSTEM_CA=1 npm ci`. Supported
Node versions can use the system CA store while continuing to verify TLS
certificates. This does not install a CA or repair an untrusted certificate;
if the error persists, obtain the correct trust configuration from your network
administrator. Do not set `strict-ssl=false` or `NODE_TLS_REJECT_UNAUTHORIZED=0`.
See [Node's system CA option](https://nodejs.org/api/cli.html#node_use_system_ca1).

Homebrew services start supported macOS tools; Linux uses system services where available. An unmanaged Ollama binary falls back to a local background server with a private temporary log whose path is printed. After reboot, that fallback must be restarted with `ollama serve`. Managed Ollama services restart through their service manager. Colima/Docker must be running for the persistent PostgreSQL container to restart.

If Chromium cannot launch, setup stops before creating application databases. Resolve the OS browser dependencies/sandbox policy or supply an absolute `PUPPETEER_EXECUTABLE_PATH` to a supported system browser. Setup validates it, launches it sandboxed and records the path in `.env`. It never adds `--no-sandbox` or disables AppArmor/user-namespace protection.

To use an existing PostgreSQL18 server, export `PG_ADMIN_DATABASE_URL` privately before running the installer. This skips creation of the local PostgreSQL container; Docker remains required for the isolated exercise sidecars and owned runner. Remote servers also require `PG_TLS=require` and a trusted certificate. Do not paste real credentials into documentation or commit them.

## Reverse proxies

Direct laptop startup needs no proxy configuration. The application ignores
forwarded IP, host and protocol headers unless the connecting proxy is trusted.
Behind a reverse proxy, set `TRUSTED_PROXY_CIDRS` in the private application
environment to its exact IP addresses or subnets, separated by commas; for
example, `10.20.1.0/24,10.20.2.0/24`. Use your actual proxy subnets, not these
examples. Empty means no trusted proxies. Literal `/0` ranges, `true`, hostnames
and numeric hop counts are rejected at startup. Configure only the actual proxy
addresses: combining broad ranges can still trust unintended peers.

The trusted proxy must overwrite `X-Forwarded-Host` and `X-Forwarded-Proto` and
correctly maintain `X-Forwarded-For`; see the [Express proxy guidance](https://expressjs.com/en/guide/behind-proxies/).
This setting controls client-IP audit/rate-limit attribution and secure event
cookies behind TLS termination. Without it, requests behind a proxy share that
proxy's IP and the application sees its direct transport protocol. AWS deployment assets have been removed from this local application release.

## Browser origins and custom ports

When serving the application on a custom port or hostname, set
`SS_ALLOWED_ORIGINS` to the exact browser origins you use, separated by commas
(scheme, hostname and port; no path). Despite its historical name, this setting
also protects platform login, administration and progress APIs. For example, an
application served at `http://127.0.0.1:4100` needs that exact origin in the list.
`localhost` and `127.0.0.1` are different origins. Include each intended frontend
origin; do not use a wildcard or copy the request's Origin header into the list.

An unlisted browser origin receives HTTP 403 before authentication, even when
the same token works from an API client that sends no Origin header. This can
appear as a working page whose actions or SecureShop launch fail. Configure the
origin explicitly instead of disabling CORS checks. `TRUSTED_PROXY_CIDRS` is a
separate setting and does not add browser origins to this allowlist.

## Optional workshop entry password


Set `EVENT_GATE_ENABLED=true` and an explicit `EVENT_GATE_PASSWORD` of 12–256
UTF-8 bytes without surrounding whitespace to enable the shared event barrier.
The historical sample password is rejected. Invalid enabled configuration stops
startup before database initialization. This barrier is separate from instructor
and student account authentication. Its signed cookie expires after six hours;
changing the password invalidates existing cookies. Cookies issued by the older
gate format are invalid after upgrading, so attendees must enter the event
password again. The entry page appearance is unchanged.

## Native Windows

Use **x64 Windows Pro, Education or Enterprise**, Windows 10 build 19045 or newer or Windows 11, with Hyper-V enabled and running. Home, Windows Server and ARM64 are unsupported. The installed **Hyper-V Module for Windows PowerShell** must be available, and your normal user token must have **Hyper-V Administrators** membership. Ask a host administrator to configure these prerequisites, then complete any required restart and sign out/sign in after a group change. Run the application from a normal, non-elevated terminal. Setup does not enable Windows features, change group membership or reboot the host.

The shared read-only host preflight runs before setup/start changes, including direct Node entry points. Unknown host state and pending servicing restarts fail closed with a remedy. Stop remains available without passing the installation host gate.

The PowerShell wrappers connect the prerequisite coordinator to canonical Node setup and startup. The coordinator verifies or provisions Node26.10.0/npm12.1.0 or newer, Git, x64 Python3.11–3.14, Visual Studio/MSVC with the Windows SDK, Ollama, Multipass1.16.4 and Microsoft OpenSSH. Package installation can require administrative approval; the application itself remains a normal-user process. The wrapper changes only its child environment; vendor package installers may register their tools in the user PATH.

The backend, frontend, browser and Ollama run natively on Windows. Owned Linux lab services run in a private Multipass VM using Hyper-V. Its retained VMId, guest identity and Docker binding are checked before reuse or restart. Setup provisions ordinary sidecars and AppArmor-protected services through that admitted guest. Startup reuses the existing VM and retained containers/volumes, verifies readiness, and keeps owned loopback SSH forwards alive until application shutdown. It never creates a replacement VM or rebuilds services during startup. External PostgreSQL remains supported; an external-only configuration with no owned services and sidecar autostart disabled does not require a lab VM.

Use Windows PowerShell 5.1 or newer. From the repository root, preview first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/install-windows.ps1 -Plan
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1 -Plan
```

Plans emit the host admission, intended canonical arguments and blockers as JSON, followed by a no-changes message. They need no Node installation and perform no downloads, package installation, VM/service changes, private configuration writes or database work. A plan is not dependency readiness proof.

For fresh setup and daily use:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/install-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1 -Stop
```

`-ExecutionPolicy RemoteSigned` applies only to that PowerShell process; the scripts do not change execution policy. Organizational Group Policy still takes precedence. Review and unblock downloaded files according to your organization's policy if necessary; do not bypass it. Fresh setup refuses to overwrite an existing root `.env`. After setup, open `http://localhost:3000` and use the installation's recorded administrator credential.

Use `install-windows.ps1 -Upgrade` for the additive database upgrade path or `-Repair` for prerequisite/runtime repair of an existing installation. `-NoInstall` skips locked npm installation only; it still checks required native prerequisites. Each mode supports `-Plan`. Use `start_all.ps1 -InitDb` to apply pending migrations before foreground startup without resetting data. Startup rejects reset requests. Stop terminates only the owned application process tree and joins its forwarding jobs; it does not stop unrelated processes or delete the VM, volumes or learner data.

Managed Pricing services, Coupon activation and the retained protected-recovery capability are not yet supported by this Windows path. Missing optional configuration does not block ordinary startup. Enabling an unsupported capability does not create qualification or weaken its admission checks.

Interrupted operations retain recovery records instead of replaying uncertain changes. Finish an acknowledged package restart explicitly before retrying; uncertain operations remain blocked. Never delete private state or learner databases to bypass an error. The integrated caller paths have controlled-test coverage, and Windows maintenance schema behavior has isolated PostgreSQL coverage. The current release source, admission, recovery and inventory checks pass. Native Windows execution and POSIX-equivalent directory durability are not claimed.

## Verification and advanced setup

Installation confidence uses source review, locked dependencies, syntax checks where tooling is available, non-mutating previews and isolated command-harness tests. No new live or clean OS installation is required or claimed. Platform dialogs, system service policies and machine-specific configuration can still require operator action. Historical verification receipts are retained privately rather than presented as additional installation guides.

- [Optional SMTP/Gmail configuration](SMTP_SETUP.md). LangChain and LangGraph themselves require no credentials; cloud model provider credentials are optional private configuration.
- [Interrupted maintenance recovery](local-recovery-contract.md). Never delete private state or learner databases to bypass an error.
- Advanced SecureShop setup: [Listings](owned-listings.md), [Inventory](owned-inventory.md), [Coupons](owned-coupons.md). Qualified local SecureShop setup prepares coupons by default unless an existing Analytics or coupon preference is disabled; these guides are not additional basic installation steps.
