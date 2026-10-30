# Dependency upgrade inventory

> Current scope update: follow the [single-engine PostgreSQL plan](postgresql-single-engine-plan-2026-09-10.md) and [two workshop baselines](workshop-experience-baseline-2026-09-10.md). SQLite/MySQL entries describe the assessed source system; their runtime drivers are to be retired, with PostgreSQL `pg` (8.23.0 observed; refresh at implementation) added. Preserve intentional teaching outcomes during dialect migration. AWS deployment changes remain excluded.

Current scope: application-only upgrades. AWS images, CloudFormation and deployment workflows/scripts are frozen. These latest-version candidates may require a newer runtime than the existing Node 18 AWS images; verify engines/native compatibility and record that as a deferred deployment blocker. A local successful build does not qualify the new stack for the unchanged AWS deployment. No image or cloud-runtime update is authorized by this matrix.

## Learning dependency preservation policy

This policy takes precedence over latest-version candidates and package replacement/retirement tickets. **Do not upgrade, replace or remove a package/version required for an intentional learning vulnerability.** Upgrade ordinary platform/tooling dependencies to the latest compatible stable releases; keep verified teaching dependencies pinned to their required versions, including relevant transitive dependencies.

Before changing any dependency, classify it as `upgrade`, `replace`, `retire`, `preserve-for-learning`, or `investigate`. Record the resolved package/version and dependency path, importing code, exercise/scenario and vulnerability IDs, why that version matters, vulnerable/fixed-mode expectations, a reproducible proof test, runtime compatibility and review owner. An advisory alone is not proof of pedagogical intent, and use in a challenge alone does not prove the version must remain old. Uncertain dependencies stay unchanged until their role is established. No specific package exception is claimed verified by this planning update.

Add ticket **M02a: learning dependency inventory and protection gate**, completed before dependency waves or database driver retirement. Use the challenge catalogs, annotations, imports, manifests/lockfiles and exploit tests to populate the register. Capture passing exploit proofs before changes and repeat them after a clean install on the target Node/runtime. Check resolved transitive versions as well as direct pins; broad overrides or deduplication must not silently patch a teaching dependency. Audit findings remain visible with scoped educational dispositions; do not auto-fix intentional dependencies or hide unrelated platform findings.

Where the same package serves platform and challenge code, assess separate dependency scopes/adapters within the application so the platform can upgrade while the exercise retains its required version. Verify resolution and behavior; aliases alone are not a security isolation boundary. If the protected package cannot run on the new runtime, record a compatibility blocker and retain it unchanged pending a concrete design decision. Do not remove the lesson, silently simulate a package vulnerability, or modify AWS deployment to resolve the conflict.

PostgreSQL remains the sole target database engine. If a protected dependency or lesson requires SQLite/MySQL specifically, flag the conflicting migration ticket before driver removal; do not silently retain a second runtime engine or erase the lesson. Reconcile that specific conflict with the user once evidence identifies it.

Acceptance: all dependency changes have a disposition, protected versions survive clean installation, required exploit proofs and fixed-mode checks pass, and workshop objectives/UI remain intact. Educational exceptions are reviewed when the curriculum changes; a review date never authorizes automatic upgrade.

Registry metadata checked 2026-09-11T02:23:36.655Z. These are target candidates, not installed or compatibility-tested versions. Re-resolve latest stable tags when implementation starts and commit the tested exact lockfile.

Source: npm registry metadata retrieved with `npm view <package>@latest`; system CA trust enabled for the corporate certificate chain. No TLS verification was disabled.

| Manifest | Package | Declared | Locked | Latest stable tag |
|---|---|---|---|---|
| package.json | @aws-sdk/client-bedrock-runtime | ^3.1011.0 | 3.1011.0 | 3.1130.0 |
| package.json | @modelcontextprotocol/sdk | ^1.29.0 | 1.29.0 | 1.30.0 |
| package.json | @xenova/transformers | ^2.17.2 | 2.17.2 | 2.17.2 |
| package.json | axios | ^1.6.2 | 1.11.0 | 1.20.0 |
| package.json | bcrypt | ^6.0.0 | 6.0.0 | 6.0.0 |
| package.json | bcryptjs | ^2.4.3 | 2.4.3 | 3.0.3 |
| package.json | better-sqlite3 | ^12.11.1 | 12.11.1 | 13.0.3 |
| package.json | body-parser | ^1.20.2 | 1.20.3 | 2.3.0 |
| package.json | compression | ^1.8.0 | 1.8.1 | 1.8.1 |
| package.json | cookie-parser | ^1.4.6 | 1.4.7 | 1.4.7 |
| package.json | cors | ^2.8.5 | 2.8.5 | 2.8.6 |
| package.json | dotenv | ^16.3.1 | 16.6.1 | 17.4.2 |
| package.json | express | ^4.18.2 | 4.21.2 | 5.2.1 |
| package.json | express-rate-limit | ^8.1.0 | 8.5.2 | 8.7.0 |
| package.json | express-session | ^1.17.3 | 1.18.2 | 1.19.0 |
| package.json | helmet | ^7.2.0 | 7.2.0 | 8.3.0 |
| package.json | hnswlib-node | ^3.0.0 | 3.0.0 | 3.0.0 |
| package.json | jsonwebtoken | ^9.0.2 | 9.0.2 | 9.0.3 |
| package.json | marked | ^18.0.5 | 18.0.5 | 18.0.12 |
| package.json | morgan | ^1.10.1 | 1.10.1 | 1.12.0 |
| package.json | multer | ^1.4.5-lts.1 | 1.4.5-lts.2 | 2.3.0 |
| package.json | mysql2 | ^3.16.0 | 3.16.0 | 3.24.4 |
| package.json | nodemailer | ^8.0.2 | 8.0.2 | 10.0.3 |
| package.json | nunjucks | ^3.2.4 | 3.2.4 | 3.2.4 |
| package.json | sax | ^1.6.0 | 1.6.0 | 1.6.1 |
| package.json | sqlite3 | ^5.1.7 | 5.1.7 | 6.0.1 |
| package.json | winston | ^3.19.0 | 3.19.0 | 3.19.0 |
| package.json | xml2js | ^0.6.2 | 0.6.2 | 0.6.2 |
| package.json | concurrently | ^8.2.2 | 8.2.2 | 10.0.5 |
| package.json | nodemon | ^3.0.2 | 3.1.10 | 3.1.14 |
| package.json | puppeteer | ^24.18.0 | 24.18.0 | 25.10.0 |
| client/package.json | axios | ^1.6.2 | 1.11.0 | 1.20.0 |
| client/package.json | framer-motion | ^10.16.16 | 10.18.0 | 13.2.0 |
| client/package.json | lucide-react | ^1.23.0 | 1.23.0 | 1.44.0 |
| client/package.json | react | ^18.2.0 | 18.3.1 | 19.3.0 |
| client/package.json | react-dom | ^18.2.0 | 18.3.1 | 19.3.0 |
| client/package.json | react-icons | ^4.12.0 | 4.12.0 | 5.7.0 |
| client/package.json | react-markdown | ^6.0.3 | 6.0.3 | 10.1.0 |
| client/package.json | react-router-dom | ^6.8.1 | 6.30.1 | 7.18.3 |
| client/package.json | react-scripts | 5.0.1 | 5.0.1 | 5.0.1 |
| client/package.json | react-toastify | ^9.1.3 | 9.1.3 | 11.1.0 |
| client/package.json | recharts | ^3.9.1 | 3.9.1 | 3.10.1 |
| client/package.json | remark-gfm | ^1.0.0 | 1.0.0 | 4.0.1 |
| client/package.json | styled-components | ^6.1.6 | 6.1.19 | 6.5.3 |

## New or replacement packages

| Package | Latest stable tag | Node requirement |
|---|---|---|
| langchain | 1.5.11 | >=20 |
| @langchain/core | 1.2.10 | >=20 |
| @langchain/langgraph | 1.4.14 | >=18 |
| @langchain/openai | 1.5.12 | >=22 |
| @langchain/anthropic | 1.5.10 | >=20 |
| @langchain/ollama | 1.3.0 | >=20 |
| @langchain/aws | 1.4.5 | >=20 |
| @langchain/langgraph-checkpoint-sqlite | 1.0.4 | >=18 |
| @langchain/langgraph-checkpoint-postgres | 1.0.5 | >=18 |
| @langchain/mcp-adapters | 1.1.4 | >=20.10.0 |
| vite | 8.3.0 | ^20.19.0 || >=22.12.0 |
| @vitejs/plugin-react | 6.1.1 | ^20.19.0 || >=22.12.0 |
| typescript | 7.0.2 | >=16.20.0 |
| zod | 4.6.2 | Not returned |
| @playwright/test | 1.63.0 | >=20 |
| vitest | 5.0.0 | ^22.12.0 || ^24.0.0 || >=26.0.0 |
| @huggingface/transformers | 4.2.0 | Not returned |

The JSON inventory includes peer requirements. Install a mutually compatible set; npm latest tags alone do not prove compatibility. Add checkpoint peer dependencies where required by the selected saver. Replace react-scripts with Vite instead of retaining an obsolete build chain merely because its dist-tag is unchanged. Evaluate replacing @xenova/transformers with @huggingface/transformers while preserving model, pooling, normalization, dimensions, and cached assets; do not re-embed silently.

## September 13 runtime verification

Official release sources currently identify [Node 26.8.2](https://nodejs.org/en/blog/release/v26.8.2) as Current and [React 19.3](https://react.dev/versions) as the latest React release. The application pins React and React DOM19.3.0. The Linux prerequisite installer targets Node26.8.2 when installation is required, but the running local verification process is Node26.7.0; compatible-runtime reuse does not imply installation of the latest patch. Therefore the current local tests/build are Node26.7.0 qualification, and full latest-runtime qualification remains open. AWS deployment assets are outside this application-only update scope.


The subsequent owned Node26.8.2 Darwin arm64 binary was verified against the official archive SHA256 (`974b6d5fb2fc7c33ff2354db0902b4e91c2de01ec8acc6de48e543c97e18c9e1`). Root confirmed its version and built the current frontend from the client directory successfully, including the ARIA/NOVA instructional corrections. The existing756KB main-chunk warning remains. An initial invocation from the repository root selected a nonexistent root Vite binary; the corrected client-directory build passed. This is isolated new-runtime build evidence, not a service/runtime switch or clean-OS installation proof. Broader Node26.8.2 backend qualification is tracked separately.


Node26.8.2 backend qualification now passes113 focused setup/provider/graph tests and1,602 isolated unit tests with41 gated skips and zero failures (`owasp-ai-goat-regression-IStxSF`). Shared native modules loaded without rebuild. The repository `.nvmrc` now pins26.8.2; package engines retain Node24 compatibility. Existing running services are unchanged until deliberately restarted using the selected runtime. The owned binary is retained at `/tmp/owasp-ai-goat-node26.8.2-VD2VfH/node-v26.8.2-darwin-arm64/bin/node`; the initial reported temporary-directory suffix was corrected against the actual filesystem before root build qualification.
