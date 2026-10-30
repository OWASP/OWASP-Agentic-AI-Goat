# OWASP Agentic AI GOAT Quick Start

Run these commands from the repository root. Initial setup downloads dependencies and models, so installation time depends on your machine and network.

## 1. Install

Choose your platform:

- [macOS](install/INSTALLATION.md): `bash scripts/install/Mac/install-macos.sh`
- [Ubuntu / Debian Linux](install/INSTALLATION.md): `bash scripts/install/Linux/install-linux.sh`
- Windows Pro, Education or Enterprise on x64 with Hyper-V: use the PowerShell setup/start/stop commands in the [main installation guide](install/INSTALLATION.md#native-windows). The implemented path has source and isolated checks, without fresh-host Windows qualification.

The macOS/Linux wrappers install missing system prerequisites and run application setup. The [main installation guide](install/INSTALLATION.md) contains prerequisites, components, repair and troubleshooting. If prerequisites are already available and Ollama is running, use `npm run setup`.

Setup installs the locked frontend/backend packages, including LangChain and LangGraph; verifies the browser and local models; provisions PostgreSQL databases; and writes private configuration. Local Ollama and these frameworks require no API keys. Keep the private administrator credential file whose location setup prints.

For an existing installation, follow the [upgrade instructions](../README.md#installation) and preserve its configuration and data. Do not use fresh setup or database initialization as a reset procedure.

## 2. Start

```bash
./start_all.sh              # macOS / Linux
```

On Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1
```

Keep the configured PostgreSQL, Ollama and required exercise services available. The application launcher validates configuration; it does not install prerequisites or start Ollama. If Ollama is not running, start `ollama serve` in another terminal.

The default frontend is [localhost:3000](http://localhost:3000), with the backend on port 8081. When SecureShop is enabled, the launcher automatically supervises its agent host; keep `SS_AGENT_HOST_PORT` free and distinct (default 8082), and do not launch it separately. Check [backend health](http://localhost:8081/api/monitoring/health) as well as the frontend before starting a workshop.

`./start_all.sh --init-db` applies pending migrations and idempotent seeds. Startup does not delete databases. Reset exercises through their authenticated controls.

## 3. Sign in where required

For workshop and platform-administration routes, open [workshop login](http://localhost:3000/workshop-login). Use the [fresh initial accounts](install/INSTALLATION.md#initial-accounts), or your retained credentials on an existing installation. Add further platform accounts through the administrator portal.

SecureShop is a separate application. Guests can browse at `/secureshop`; its
independent practice accounts sign in at `/secureshop/login`. Workshop
credentials do not authenticate the shop.

## 4. Explore

- `/admin` — challenge visibility, students, progress, hints and solutions.
- `/ctf` — ten-stage prompt-injection CTF.
- `/secureshop` — SecureShop entry point.
- `/workshop/prompt-injection` — direct prompt-injection workshop.
- `/workshop/sql` — ARIA SQL workshop.
- `/workshop/nosql` — NOVA NoSQL workshop.

Exercise completion requires its objective-specific evidence and Judge result; unavailable grading must not be interpreted as completion.

## 5. Stop

Press Ctrl+C in the launcher terminal, or on macOS/Linux run:

```bash
./stop_all.sh
```

The stop command targets this workspace's owned launcher. It does not kill unrelated listeners or stop your shared Ollama service.

For developer-only file watching, `npm run dev` runs the backend and frontend directly and bypasses the supported launcher's preflight and stop controller. See [architecture](ARCHITECTURE.md) for more detail.
