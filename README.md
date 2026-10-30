# OWASP Agentic AI GOAT

OWASP Agentic AI GOAT is a deliberately vulnerable application for learning how to attack and defend AI agents. It includes prompt injection, RAG and email attacks, SQL and NoSQL injection, XSS, MCP labs, a prompt-injection CTF, and SecureShop, an AI-powered shopping application.

Run it locally for training. Never expose it to the internet or use real sensitive data in the labs.

## Installation

Download or clone this repository, then run the installer from its directory:

```bash
# macOS
bash scripts/install/Mac/install-macos.sh

# Ubuntu / Debian Linux
bash scripts/install/Linux/install-linux.sh
```

For Windows, follow the [Windows installation guide](docs/install/INSTALLATION.md#native-windows).

Setup installs dependencies, prepares PostgreSQL and local lab services, downloads the local AI model, and creates your private `.env`. Local Ollama does not need an API key. The first installation downloads several gigabytes; model speed depends on your hardware.

Read the [installation guide](docs/install/INSTALLATION.md) for requirements, upgrades, repair, and troubleshooting. If the prerequisites are already installed and Ollama is running, you can use `npm run setup` directly.

## Start and use

On macOS or Linux:

```bash
./start_all.sh
```

Open [localhost:3000](http://localhost:3000) and sign in with the [initial accounts](docs/install/INSTALLATION.md#initial-accounts). Existing installations keep their current credentials.

- Choose an exercise from the workshop dashboard and follow its objectives. Hints and solutions are available when enabled by the instructor.
- Open the [admin panel](http://localhost:3000/admin) to manage students, exercises, hints, solutions, and progress.
- Try the [prompt-injection CTF](http://localhost:3000/ctf) or [SecureShop](http://localhost:3000/secureshop). SecureShop uses separate practice accounts.

Stop with Ctrl+C in the launcher terminal or run `./stop_all.sh`. Use the exercise reset controls to reset progress.

See the [quick start](docs/QUICK_START.md) for Windows startup, service checks, and more usage details.

## Configuration

Keep credentials in your private `.env`. Do not commit them.

- [Environment settings](.env.example): AI providers, models, grading, ports, and lab settings. Ollama is the default; cloud providers require your own credentials.
- [Email setup](docs/install/SMTP_SETUP.md): Gmail SMTP, SharkLasers, and local Mailpit delivery. Choose the workshop email provider in Admin → Settings → Email Delivery. With Mailpit selected, the IPI and XSS email labs include a link to the inbox.
- [Workshop entry password](docs/install/INSTALLATION.md#optional-workshop-entry-password): restrict entry during an event.
- [Custom ports and browser origins](docs/install/INSTALLATION.md#browser-origins-and-custom-ports) and [reverse proxies](docs/install/INSTALLATION.md#reverse-proxies).
- [SecureShop setup](docs/secureshop/README.md): shop accounts, agents, and optional services.

## Guides

- [Workshop guides](docs/workshops/README.md) and [facilitator outline](docs/workshops/WORKSHOP_OUTLINE.md)
- [All documentation](docs/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Current release status and known limitations](docs/modernization/current-release-status.md)
- [Installation recovery](docs/install/local-recovery-contract.md)
- [Contributing and testing](docs/CONTRIBUTING.md)
- [Security policy](docs/SECURITY.md)

Some exercises and model-based grading paths are still being verified. Check the release status before planning a workshop around them.

## License and credits

GNU General Public License v3.0.

This project originates from [DVAIA](https://github.com/hackerabhinavverma/Damn-Vulnerable-AI-Application) and was inspired by [DVWA](https://github.com/digininja/DVWA) and [WebGoat](https://github.com/WebGoat/WebGoat).
