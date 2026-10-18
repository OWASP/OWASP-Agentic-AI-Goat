# Dependency currency — 2026-09-19

Checked at `2026-09-19T20:22:00.067109+00:00`. Read-only comparison of current root/client manifests and exact lockfile entries against official npm `latest` metadata. No installation, dependency update, lockfile rewrite or native launch occurred.

| Package | Manifest and exact lock | Registry latest | Source |
| --- | --- | --- | --- |
| `react` | 19.3.0 | 19.3.0 | [npm registry](https://registry.npmjs.org/react/latest) |
| `react-dom` | 19.3.0 | 19.3.0 | [npm registry](https://registry.npmjs.org/react-dom/latest) |
| `vite` | 8.3.0 | 8.3.0 | [npm registry](https://registry.npmjs.org/vite/latest) |
| `express` | 5.2.1 | 5.2.1 | [npm registry](https://registry.npmjs.org/express/latest) |
| `@langchain/core` | 1.2.11 | 1.2.11 | [npm registry](https://registry.npmjs.org/%40langchain%2Fcore/latest) |
| `@langchain/langgraph` | 1.4.16 | 1.4.16 | [npm registry](https://registry.npmjs.org/%40langchain%2Flanggraph/latest) |
| `langchain` | 1.5.11 | 1.5.11 | [npm registry](https://registry.npmjs.org/langchain/latest) |
| `pg` | 8.23.0 | 8.23.0 | [npm registry](https://registry.npmjs.org/pg/latest) |

All eight sampled packages are current at the check timestamp. This refresh supersedes the older 2026-09-14 snapshot only for these eight packages; it is not a scan of all direct/transitive dependencies.

## Runtime and compatibility

The [official Node release index](https://nodejs.org/dist/index.json) reports current Node **26.9.0**, released 2026-09-16, bundled npm **11.19.1**. This matches the managed verification runtime and checked-in Unix runtime floor. Latest LTS is **24.21.0** (Krypton), not the selected current-release runtime. Frozen AWS Node18 assets remain unchanged and are not qualified by this check.

Semver checks on Node26.9.0 pass all eight declared Node engine ranges. React DOM accepts locked React19.3.0; LangGraph accepts locked Core1.2.11 and Zod3.25.76; LangChain accepts Core1.2.11. Installed Vite peer @types/node24.3.0 satisfies its advertised range. Optional/uninstalled peers were not installed. Engine/peer eligibility does not establish runtime, migration, browser, actual-model or fresh macOS/Linux installation compatibility. Those qualifications remain separate.

## Learning exceptions

The current [learning registry](learning-dependencies.json) has **0 preserve-for-learning, 0 investigate/frozen and 4 current-reviewed** entries: jsonwebtoken9.0.3, nunjucks3.2.4, sax1.6.1 and xml2js0.6.2. `node scripts/verify-learning-dependencies.js` passes against current manifests, locks and proof references. These reviewed packages implement deliberate application-level teaching sinks; the registry does not currently identify a version-specific frozen package. This is not permission to change their semantics or remove vulnerability proofs. Future changes still require the registry review and relevant exploit/fixed-mode tests.

## Next action

No update is indicated for the eight sampled packages. Continue the application qualification backlog rather than churn already-current pins. Before a release, refresh all direct dependency versions and transitive advisories, preserving any then-protected teaching versions; qualify any proposed update in isolated tests and actual-model/browser workflows where behavior changes.

## Retrieval integrity

Metadata was retrieved using system `/usr/bin/curl --fail --silent --show-error --proto =https --tlsv1.2 --max-time 25` with ordinary certificate/hostname verification enabled. No insecure flag, TLS bypass or certificate-setting change was used. An earlier Python urllib attempt failed certificate validation and was discarded; the successful curl requests independently retrieved all npm and Node metadata over verified HTTPS.
