# OWASP Agentic AI GOAT direct-dependency currency delta — 2026-09-14 PDT

Checked at 2026-09-15T03:50:46Z (2026-09-14 20:50 PDT). Scope: root, client, and agent-host direct production and development dependencies. Installed versions came from each existing `node_modules/<package>/package.json`; stable candidates came from the npm registry `latest` endpoint. No `latest` result was a prerelease. No package, lockfile, runtime, AWS asset, or `.env` was changed.

Full 63-row evidence: `/tmp/owasp-ai-goat-dependency-currency-20260914.json`, SHA-256 `8427394292ef94cd27ac5308477c917c62b1550274fcd3025f2f5c286ea635c6`.

## Foundation versions

| Runtime/package | Declared | Installed | Stable latest | Finding |
|---|---:|---:|---:|---|
| Node.js | engine `^24.15.0 || >=26.0.0`; `.nvmrc` 26.8.2 | managed 26.8.2; ambient PATH 26.7.0 | Current 26.8.2; LTS Krypton 24.21.0 | Managed runtime is current; engine admits latest LTS. |
| React / React DOM | 19.3.0 | 19.3.0 | 19.3.0 | Current. Canary/experimental tags excluded. |
| Vite | 8.3.0 | 8.3.0 | 8.3.0 | Current. |
| langchain | 1.5.11 | 1.5.11 | 1.5.11 | Current. |
| @langchain/core | 1.2.11 | 1.2.11 | 1.2.11 | Current. |
| @langchain/langgraph | 1.4.15 | 1.4.15 | 1.4.15 | Current. |

Primary evidence: Node release index https://nodejs.org/dist/index.json; React https://www.npmjs.com/package/react?activeTab=versions; Vite https://www.npmjs.com/package/vite?activeTab=versions; LangChain https://www.npmjs.com/package/langchain?activeTab=versions; LangGraph https://www.npmjs.com/package/%40langchain/langgraph?activeTab=versions; LangChain core https://www.npmjs.com/package/%40langchain/core.

## Actionable changes since the prior 2026-09-14 audit

| Manifest | Package | Declared | Installed | Stable latest | Compatibility / focused proof |
|---|---|---:|---:|---:|---|
| root | @aws-sdk/client-bedrock-runtime | 3.1131.0 | 3.1131.0 | 3.1132.0 | Node >=20; exercise Bedrock provider construction/request error handling. |
| root | multer | 2.3.0 | 2.3.0 | 2.4.0 | Node >=10.16; run multipart upload, size/field limits, and error-path tests. |
| root | nodemailer | 10.0.9 | 10.0.9 | 10.0.10 | Node >=20; run controlled SMTP/Mailpit transport tests. |
| root | puppeteer | 25.10.0 | 25.10.0 | 25.11.0 | Node >=22.12; qualify browser download/binary and browser suites. |
| client | framer-motion | 13.2.0 | 13.2.0 | 13.3.0 | Peer range accepts React/DOM 18 or 19; build and exercise animated views. |
| client | lucide-react | 1.45.0 | 1.45.0 | 1.46.0 | Peer range accepts React 16.5–19; build and spot-check icon rendering. |

Registry evidence: https://registry.npmjs.org/%40aws-sdk%2Fclient-bedrock-runtime/latest, https://registry.npmjs.org/multer/latest, https://registry.npmjs.org/nodemailer/latest, https://registry.npmjs.org/puppeteer/latest, https://registry.npmjs.org/framer-motion/latest, https://registry.npmjs.org/lucide-react/latest.

These six releases were published only hours before this check. Engine and peer metadata show no blocker on Node 26.8.2 or Node 24.21.0, but metadata is not runtime qualification. Update them in a lockfile-changing PR only after the focused proofs above; keep AWS assets out of that change.

Among 59 nonprotected direct manifest entries (58 unique packages because Axios is declared in root and client), 53 entries are already at `latest` and six are behind. Every installed direct version matches its declaration/resolution. `agent-host/package.json` declares no direct dependencies.

## Protected policy and continuing blockers

The protected register contains `jsonwebtoken@9.0.3`, `nunjucks@3.2.4`, `sax@1.6.1`, and `xml2js@0.6.2`. All four are declared, installed, and stable-latest at those versions. Each is `current-reviewed`; there are zero `preserve-for-learning` or `investigate` entries. Their teaching behavior is application-created, so the policy does not justify holding an older package when a future stable update appears, but curriculum proof tests remain required.

The frozen AWS Node 18 deployment remains incompatible with the modern application stack. Three changed candidates require Node >=20 or >=22.12, but their currently installed versions already impose the same floors, so this audit introduces no new AWS incompatibility. The recorded `@huggingface/transformers@4.2.0` ONNX/Sharp advisory graph also remains a separate replacement/graph issue: 4.2.0 is still stable-latest, so there is no direct version bump that resolves it.


## Qualification status

The six updates remain in an isolated candidate. A strict full client dependency resolution exposed the existing Babel 8 / Jest 30 syntax-plugin peer conflict. A private candidate replaces the Jest-only Babel transformer with SWC; acceptance requires a clean strict development install, the complete client test suite, production builds and affected component rendering. No force or legacy-peer-deps workaround is accepted. This audit does not claim that the upgrades are installed or fully verified. AWS deployment assets remain outside scope.

The private client candidate has now completed a clean install and all 403 tests in 51 suites (`/private/tmp/owasp-ai-goat-dependency-upgrades.686rLb/evidence/client-jest-full.log`). This is test-suite evidence, not completion of build, render or cross-platform installation qualification. The install warning for the SWC native postinstall script requires explicit install-policy review before acceptance.

Both candidate Vite builds passed, but package-identity review found the wrong Lucide target (1.0.1 instead of audited 1.46.0). The earlier client results therefore do not qualify the requested Lucide upgrade. The private manifest/lock must be corrected and clean install, tests, builds and render checks repeated with exact installed/lock identity verification. Bedrock retryMode test failure was a test expectation mismatch (string versus provider), with no application runtime change indicated.

Root independently verified all six corrected target versions and both SWC transformer versions against each manifest, lock entry and installed package. Final private logs report403client tests, both builds, five dependency behavior checks,25 existing focused checks and the browser bridge passing. Promotion remains pending the frozen candidate review; macOS was exercised, Linux installation remains a separate qualification requirement.

## Installed checkpoint

The four reviewed manifests/locks are installed. Both canonical dependency trees were freshly installed with strict peers and strict install-script checks; rollback copies remain at the path recorded in `/private/tmp/owasp-ai-goat-dependency-activation-current.txt`. The installed client passes401tests across49suites (the private candidate included two additional qualification suites), and both production builds pass. Backend/frontend return200; student login succeeds; allthree student progress projections exactly match the preserved pre-restart snapshots. `.env` is unchanged. Linux installation remains unqualified.

Browser follow-through: installed matching Chrome153 using the platform system CA (`NODE_USE_SYSTEM_CA=1`), retaining TLS verification after the default trust store failed. The production frontend browser verifier passed DPI/IPI responsive and interaction checks using injected API responses. Separately, real student login and dashboard/FinFlow/agent-runs navigation passed against the running application with zero page errors; screenshots and result are in `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-upgrade-browser-jNpuND`. The FinFlow screenshot confirms the old database challenge description still needs a guarded content update; correcting fresh-install seed text alone did not update existing content.

Linux ARM64 qualification attempt01 (actual session24460) failed during image build before package tests: `/qualification/source` retained frozen directory permissions and the nonroot npm process could not create `node_modules`. Node26.8.2 and npm11.19.1 assertions had passed. Root independently verified test container/image name, tag and nonce absence; result log SHA256 `86864c9d6fe85f2cf325c4918b54ff5392df646b8496d176bb99a65040bb1760`. This is a qualification-image staging defect, not a dependency compatibility result. Private successor correction pending.
