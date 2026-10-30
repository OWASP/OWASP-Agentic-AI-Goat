# Contributing to OWASP Agentic AI Goat

Contributions to lessons, platform fixes, accessibility, documentation and local installation are welcome. Use OWASP Agentic AI GOAT in user-facing text and `owasp-ai-goat` for package names. Existing database migrations and persisted identifiers require compatibility review before renaming.

## Start here

Read [installation](install/INSTALLATION.md), [architecture](ARCHITECTURE.md) and [current release limits](modernization/current-release-status.md). Use the Node version in `.nvmrc` and lockfile-managed dependencies. `npm run setup -- --plan` previews installation; `npm run setup` provisions the local application. Never use learner databases for tests.

The platform (authentication, authorization, sessions, ownership, reset and grading) must be secure. Challenge sinks annotated `@intentional-vulnerability` are deliberate. Preserve their behavior, annotations and proof tests; an annotation does not excuse escaping the documented owner/store boundary. Review the [SecureShop map](secureshop/vuln-map.md) before changing those flows.

## Contribution workflow

1. Discuss substantial architecture or lesson changes in an issue before implementation. For security defects, use the [private reporting policy](SECURITY.md).
2. Fork the repository and create a focused branch from `main`, such as `fix/session-expiry` or `docs/setup-help`.
3. Keep one concern per change. Match existing formatting and update the relevant tests and documentation.
4. Open a pull request describing the problem, resulting behavior, validation and limitations. Include screenshots for visible changes and migration notes for schema changes.
5. Address review comments. Repository maintainers decide whether to merge; authors should not merge their own changes without another maintainer's review. Architectural, grading, isolation and intentional-vulnerability changes require explicit discussion in the PR.

Use concise imperative commit subjects: `type(scope): action`, for example:

```text
fix(auth): reject expired platform sessions
feat(workshop): add an owner-scoped teaching scenario
test(secureshop): cover fixed-mode foreign-order denial
docs(install): clarify native Windows prerequisites
```

Use `feat`, `fix`, `test`, `docs`, `refactor`, `build`, `ci` or `chore`. Explain why in the commit body when it is not obvious. Avoid messages such as “updates” or “final fix”. Maintainers may squash a PR into a meaningful final commit; the initial repository import is a multi-commit snapshot, not a claim that each intermediate import commit runs independently.

## Verification

Run relevant focused tests first, then broaden according to the change:

```bash
npm run test:unit:isolated
npm run test:frontend
npm run test:secureshop:isolated
npm run build
npm run verify:learning-dependencies
npm run verify:secureshop:vuln-coverage
```

`npm test` combines the configured isolated unit, SecureShop and frontend suites. Native PostgreSQL, browser and actual-model checks are separate: use the documented owned/disposable launchers. `npm run verify` includes schema inspection of configured PostgreSQL stores; it is not an offline test or fresh database initializer. Never run tests against retained or learner databases. Do not use reset/reseed to repair a test fixture.

The PR workflow is a lightweight contribution smoke check, not full release qualification. State every command and result, skipped checks and missing prerequisites. Controlled/mock provider results cannot prove genuine model behavior or award objective credit. For changed lessons, qualify vulnerable/fixed behavior, objective evidence, owner/session/reset/sibling isolation, admin visibility and learner progress parity as applicable.

## Data, dependencies and lessons

- Supported application storage is PostgreSQL. Use ordered, forward-only migrations in `db/postgres`; never edit an applied migration. Preserve instructor-edited defaults and learner evidence on reseed.
- Update canonical catalog, hints, solutions, evidence/rubric and UI together. New objectives require correct administrator/student availability and progress synchronization.
- Check `docs/modernization/learning-dependencies.json` before upgrades. Do not upgrade away a deliberately retained teaching vulnerability.
- Do not commit `.env`, credentials, databases, private screenshots, recordings, runtime logs, dependency folders, build output, Codex plans or scratch reports. Synthetic, reviewed teaching fixtures and source/qualification manifests required by runtime/tests are explicit exceptions, not real secrets.
- Keep local plans under ignored `tasks/` or `.codex/`. Propose durable architecture documentation under `docs/` only when useful to contributors; do not publish personal execution journals.

## Licensing and community

Contributions are provided under the repository's [GPL-3.0 license](../LICENSE). Preserve existing notices and disclose third-party code/assets and their licenses. This repository does not introduce a separate CLA or require fabricated sign-offs. Follow the [community expectations](../CODE_OF_CONDUCT.md).

Repository owners should configure branch protection/rulesets, required `contribution-smoke` checks, a reviewer requirement and private vulnerability reporting in GitHub. Files alone do not enable those settings. No CODEOWNERS approval guarantee is claimed until maintainers assign real owners.
