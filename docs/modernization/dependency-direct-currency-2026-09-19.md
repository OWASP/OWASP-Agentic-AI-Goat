# Direct dependency currency — 2026-09-19

Checked `2026-09-19T20:37:52.256416+00:00` against official npm registry `latest` metadata. [Full machine-readable inventory](dependency-direct-currency-2026-09-19.json) records every declaration, exact lock version, source URL, engine/peer metadata and classification.

- **65 direct entries:** 42 root and 23 client dependencies/devDependencies.
- **64 current; 1 upgradable; 0 investigate; 0 protected.** All 65 requests succeeded; no unsupported aliases/specs or missing lock entries were found.
- **No installations, lockfile/source changes or native launches** were performed.

| Update candidate | Exact manifest/lock | Registry latest | Decision |
| --- | --- | --- | --- |
| `@huggingface/transformers` | 4.2.0 | 4.3.0 | Evaluate and qualify before updating the exact pin. [Official registry metadata](https://registry.npmjs.org/%40huggingface%2Ftransformers/latest) |

The update candidate has no Node engine or peer constraints declared in the retrieved latest metadata. Absence of constraints is not compatibility proof. It feeds the real CPU embedding pipeline in `server/services/ragVectorStore.js`; qualification should cover the retained model/tokenizer, deterministic vector dimensions, ingestion/retrieval and owned SecureShop manual/RAG workflows, including cold-cache installation behavior. No teaching registry exemption currently protects this package.

The [learning registry](learning-dependencies.json) contains four `current-reviewed` entries (jsonwebtoken, nunjucks, sax, xml2js) and no currently version-frozen entry. Preserve all intentional sinks and require their proof tests for any future update. The earlier [eight-package sample](dependency-currency-2026-09-19.md) remains correct for its scope; this complete direct inventory identifies the additional Transformers update.

Metadata was fetched from official npm HTTPS endpoints with system curl certificate/hostname verification enabled, HTTPS-only transport, TLS1.2 minimum, 25-second per-request timeout and at most six concurrent requests. No TLS bypass was used. Latest-version classification compares semantic versions against exact lock entries; declared ranges remain unchanged and `manifestAcceptsLatest` is recorded separately.

This inventory excludes transitive dependency freshness/advisories, downloaded model assets, OS dependencies, PostgreSQL server version and runtime/browser/native compatibility. Registry metadata and a current direct pin do not establish those qualifications. Frozen AWS deployment assets remain outside this application-only update.
