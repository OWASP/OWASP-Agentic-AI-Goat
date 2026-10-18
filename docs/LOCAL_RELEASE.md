# Local desktop source release

This source is intended for a new repository and local educational use. AWS deployment templates, ECS/CodeBuild scripts, cloud deployment/backup workflows and the obsolete AWS-backed full-app Compose profile have been removed. Local exercise sidecars remain in `docker-compose.yml`. Optional model-provider integrations and AWS-themed synthetic lessons are application features, not deployment assets.

Use the OS installer documented in [the installation guide](install/INSTALLATION.md). Native setup/start/stop is implemented for qualifying x64 Windows Pro, Education and Enterprise hosts with Hyper-V; [the Windows section](install/INSTALLATION.md#native-windows) gives prerequisites and commands. Source and isolated checks do not establish fresh-host Windows qualification. WSL is not treated as fulfillment of native Windows support.

The source package excludes Git history, private environment files, installed dependencies, runtime databases, uploads, operational logs, build output and historical work journals/backups. Four hash-pinned synthetic FinFlow log fixtures under `server/sensitive_files/logs/` are included for teaching and regression checks. Installation creates private configuration and the documented initial training accounts; existing installations retain their credentials. Existing learner databases are not bundled or reset. Use this source package to initialize the new repository; do not copy the old `.git` directory or private configuration into it. Removed deployment configuration contained credential material, so it must not be republished from old history or reused without reviewing/rotating the credentials.

Required portable regression inputs live in `tests/release-inputs`. They are test fixtures, not evidence that an exercise succeeds with every model. Opt-in retained-evidence suites require their original private artifacts and are excluded from portable unit qualification. Two historical mail candidate receipts are unavailable; no recovery or actual-model success is claimed for them. Unique implementation history and retained learner recovery data have been preserved privately outside the public source package.

## Existing qualification limits

No clean OS installation, including native Windows, is claimed by repository cleanup. The following earlier model-capability qualifications remain deferred and unverified; their exercises, teaching content and completion safeguards remain intact:

- Broad Judge semantic qualification (`R08`).
- SecureShop pricing: `ss_pricing_false_grounding`, `ss_pricing_manual_injection`.
- CSRF: `csrf_i3`.
- Direct prompt injection: `multi_language`, `virtualization`, `side_stepping`, `obfuscation`.
- CTF stages 7, 8, 9 and 10.

A clean source package is not a claim that these outcomes or fresh-host native Windows installation have passed.
