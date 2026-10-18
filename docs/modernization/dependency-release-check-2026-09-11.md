# Dependency release check — September 11, 2026

The initial read-only registry snapshot at `2026-09-11T14:04:42.741Z` used npm 11.19.0 to query the `latest` tag at `https://registry.npmjs.org/` for all 62 unique direct root/client packages with `NODE_USE_SYSTEM_CA=1`; all queries succeeded and that step changed no package. A subsequent disposable-copy trial applied the compatible candidates, rejected the incompatible Babel 8 set, and passed clean-install and focused checks before the four proven manifest/lock files were carried into the working tree. No forced peer, ignored engine, TLS bypass, application setup, database, asset, model, or cloud command was used.

The complete machine-readable result is [`dependency-release-check-2026-09-11.json`](dependency-release-check-2026-09-11.json). It records every declaration, committed resolution, latest tag, engines, license, deprecation field, latest peer ranges and the resolution used to assess each peer.

## Result

- 63 direct entries represent 62 unique packages; `axios` is direct in both projects.
- 58 entries now resolve to the current `latest` version, including the frozen `nunjucks` and `xml2js` investigations.
- Seven compatible ordinary updates were applied with exact declarations and regenerated locks.
- Three Babel entries retain their prior versions because the coordinated Babel 8 trial conflicts with Jest 30's transitive Babel 7 peers.
- Two frozen learning investigations have a newer tag: `jsonwebtoken` and `sax`. They remain unchanged under [`learning-dependencies.json`](learning-dependencies.json).
- No direct lock resolution is missing and no registry result is unknown.
- `npm ls --package-lock-only --all` and `npm ls --all` exit successfully in both projects. The committed and installed current trees therefore report no peer-tree error.

## Applied compatible updates

| Project | Package | Previous | Current/latest | Verification disposition |
| --- | --- | ---: | ---: | --- |
| root | `compression` | 1.8.1 | 1.8.2 | Clean install and archive/frontend checks passed. |
| root | `morgan` | 1.12.0 | 1.12.1 | Clean install and archive/frontend checks passed. |
| root | `mysql2` | 3.16.0 | 3.24.4 | Clean install passed. Its `@types/node >=8` peer is optional. This driver remains for legacy/migration paths pending retirement. |
| root | `nodemailer` | 10.0.3 | 10.0.6 | Clean install passed; Node `>=20` is compatible with the declared runtime. |
| root | `better-sqlite3` | 12.11.1 | 13.0.3 | Exact install-script approval updated. Native in-memory create/insert/select and 18 archive tests passed. |
| root | `sqlite3` | 5.1.7 | 6.0.1 | Exact install-script approval updated. Native in-memory create/insert/select and 18 archive tests passed. Its optional `node-gyp 12.x` range does not include the direct 13.0.2 pin, but npm reports a valid tree and the native build succeeded without a forced peer. |
| client | `lucide-react` | 1.44.0 | 1.45.0 | React 19 peer is satisfied; all 24 frontend suites/214 tests and the production build passed. |

The two direct required-peer mismatches in the report are the Babel 8 presets evaluated against the retained Babel 7 core. They describe the uninstalled candidate, not an error in the current tree. The report also records 18 absent optional peers and one installed optional peer outside the latest candidate range (`sqlite3`'s optional `node-gyp`); absent optional integrations are not release blockers.

## Deferred compatible-version decision

| Project | Packages | Resolved | Latest | Concrete blocker |
| --- | --- | --- | --- | --- |
| client | `@babel/core`, `@babel/preset-env`, `@babel/preset-react` | 7.29.7 / 7.29.7 / 7.29.7 | 8.0.5 / 8.0.5 / 8.0.1 | A coordinated Babel 8 install caused npm peer overrides because Jest 30.5.1 transitively uses `babel-preset-current-node-syntax` plugins whose peer range is `@babel/core ^7.0.0-0`. The trial was reverted. Babel 7 remains the latest compatible set for this Jest configuration; no `--force` or `legacy-peer-deps` was used. |

## Frozen learning investigations

| Package | Resolved | Latest | Disposition |
| --- | ---: | ---: | --- |
| `jsonwebtoken` | 9.0.2 | 9.0.3 | Keep 9.0.2 until the `auth-bypass-jwt-none` investigation and proof review permit a change. The current evidence attributes the vulnerability to application policy, but the registry still requires explicit curriculum review before movement. |
| `sax` | 1.6.0 | 1.6.1 | Keep 1.6.0 until both XXE proof paths and curriculum review permit a change. |
| `nunjucks` | 3.2.4 | 3.2.4 | Already current; remains an investigation rather than a proven version-specific exception. |
| `xml2js` | 0.6.2 | 0.6.2 | Already current; remains an investigation and keeps the locked `sax` relationship. |

This check does not authorize updating any of the four packages. It also does not describe `better-sqlite3`, `sqlite3`, or `mysql2` as learning-version exceptions; those packages are retained because migration and isolated fixture consumers still exist.

## SBOM and licenses

npm generated CycloneDX 1.5 documents from the current installed locked trees without running lifecycle scripts:

- [`sbom-root-2026-09-11.cdx.json`](sbom-root-2026-09-11.cdx.json): 454 dependency components. Most frequent declared licenses are MIT (329), Apache-2.0 (48), ISC (32), BSD-3-Clause (21), BSD-2-Clause (7), and BlueOak-1.0.0 (7). It also contains the root project’s GPL-3.0 declaration and smaller SPDX expressions listed in the SBOM.
- [`sbom-client-2026-09-11.cdx.json`](sbom-client-2026-09-11.cdx.json): 609 dependency components. Most frequent declarations are MIT (530), ISC (40), BSD-3-Clause (12), BlueOak-1.0.0 (8), Apache-2.0 (6), and BSD-2-Clause (5), plus the smaller expressions listed in the SBOM.

These are inventories, not a legal compatibility determination or a post-upgrade final SBOM. Regenerate them after any accepted dependency/lock change.

## Registry security-audit result

The final clean trees were also checked with `npm audit --json`; no automatic fix was run. The client reports zero findings. The root reports five high-severity package entries:

- `jws` 3.2.2 arrives through the frozen `jsonwebtoken` 9.0.2 investigation. npm says a fix is available, but changing the direct package without its curriculum/proof review would violate the learning-dependency gate.
- Current `@huggingface/transformers` 4.2.0 carries the other reported chain through `onnxruntime-node` 1.24.3, `adm-zip` 0.5.18 and `sharp` 0.34.5. npm reports no automatic fix for that direct chain.

These findings require reachability and mitigation review before release. They do not authorize `npm audit fix`, an override, or an unreviewed change to a learning dependency. The JSON report records exact installed paths and dispositions; the raw audit remained under `/tmp` because it is registry output rather than an application artifact.

## Required next gate

The compatible direct updates are installed and locked. Retain Babel 7 until Jest/Babel peers provide a valid Babel 8 graph, or migrate that test transform in a separately reviewed change. Triage the five root audit entries with source reachability and the learning-dependency contract. The assembled release candidate still needs the broader isolated backend/SecureShop/native regression after concurrent source changes settle. Regenerate this check, audit and both SBOMs after any further lock change.
