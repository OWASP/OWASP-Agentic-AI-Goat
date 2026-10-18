# Dependency freshness after embedding activation

Fresh official-registry comparison of all **65 root/client direct dependency and devDependency entries** found **65 current, zero upgrade gaps**. Exact pins and lock resolutions match the npm `latest` releases at the recorded timestamp. The [machine-readable refresh](../../tasks/dependency-current-refresh-2026-09-19.json) contains every package, declaration, lock version, official source URL, engine/peer metadata, integrity and input hashes. No install or lockfile edit occurred.

| Component | Current lock = official latest |
| --- | --- |
| React / React DOM | 19.3.0 |
| Vite | 8.3.0 |
| LangChain | 1.5.11 |
| LangChain Core | 1.2.11 |
| LangGraph | 1.4.16 |
| PostgreSQL driver `pg` | 8.23.0 |
| Express | 5.2.1 |
| Transformers | 4.3.0 |

Sources are the official npm registry package `/latest` endpoints, recorded per package in the artifact. This supersedes the earlier same-day direct inventory's sole Transformers4.2→4.3 gap. That update already has isolated full dependency graph, actual CPU embedding, persisted revision-transition and installed activation evidence; see [activation evidence](../../tasks/application-embedding-activation-2026-09-19.json). Repeating the upgrade would add no value.

The [official Node release index](https://nodejs.org/dist/index.json) reports **26.9.0**, released **2026-09-16**, as the newest release, with bundled npm11.19.1 and `lts:false`. The selected `.nvmrc`/managed runtime therefore matches **Current**, not LTS. Latest LTS is **24.21.0 (Krypton)**. Every audited package's declared Node engine accepts26.9.0; engine eligibility is not a substitute for native/browser/model qualification. Frozen AWS Node18 assets remain outside this application-only audit.

The [learning-dependency registry](learning-dependencies.json) currently has **zero preserve-for-learning, zero investigate/frozen, four current-reviewed** entries: jsonwebtoken9.0.3, nunjucks3.2.4, sax1.6.1, xml2js0.6.2. The verifier passes. These intentionally vulnerable behaviors are application-created sinks; maintain their exploit/fixed-mode proofs. An advisory alone is not permission to rewrite a teaching dependency. The registry's older runtimeContext narrative predates current cutovers and should not be treated as current activation evidence.

Other checked package manifests: `agent-host/package.json` and `sidecars/sandbox-runner/package.json` declare no dependencies. `sidecars/sandbox-runner/labfs/opt/app/package.json` belongs to the synthetic filesystem copied to `/opt/lab-template`; its example declarations are teaching data, not an application installation graph, and were left untouched.

Next actions:

- Continue existing application/lifecycle/rendered qualification; no direct dependency update is indicated.
- Before release, independently refresh **transitive advisories**, PostgreSQL server/OS/browser versions and fresh macOS/Linux installation checks. This direct version audit makes no claim that those surfaces are current or vulnerability-free.
- Preserve intentional sinks and existing qualified embedding fingerprint/reindex behavior when any future package release is proposed.

All metadata requests used verified HTTPS via system curl, HTTPS-only transport, TLS1.2 minimum, bounded timeouts and at most six concurrent requests. No TLS bypass, database access, model call, dependency installation or running-process change occurred.
