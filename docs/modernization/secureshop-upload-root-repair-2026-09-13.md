# SecureShop upload root dependency repair

Previously, `buildUploadsRouter({ uploadRoot })` applied its configured root only to static serving. POST uploads and tool-based downloads read `SECURESHOP_UPLOAD_ROOT` at call time, so a router could write somewhere different from the directory it served. The earlier browser fixture had to compensate by mutating that process-wide setting.

`createUploadTools` now captures and validates a trusted construction-time root. The router uses that instance for all four upload kinds and downloads, and the same normalized root for static serving. Request-body fields cannot replace the captured dependency. Legacy tool exports retain their existing one-argument interface and environment-backed default; additional invocation context is ignored rather than interpreted as a root. As with the shared configuration helper, an empty configured root means the repository default.

The actual upload/browser tests now use injected roots without changing global configuration. A separate concurrent-router test builds two instances, makes the ambient fallback invalid, uploads independently, and reads the same relative filename through each router's download and static endpoints. Each returns its own file. It also supplies a conflicting body `uploadRoot` field and verifies that the configured dependency wins.

The intended traversal sink remains: a focused test writes and reads an absolute synthetic path outside the configured upload directory but inside an owned temporary parent. This repair provides deterministic storage configuration, not a security boundary. `extractText` still accepts absolute file paths, manual indexing still uses the shared vector corpus, and agent-host MCP callers still use the legacy wrappers. Authenticated launch ownership, contained filesystem effects and scoped indexing remain required before learner isolation can be claimed.

Verification so far:

- Four actual-router/browser/root/traversal tests passed, with no skips.
- The strengthened real file/index retrieval proof passed using isolated deterministic compatibility fixtures.
- Independent review found no blocking defect and confirmed existing callers and deliberate sinks remain compatible.
- The running backend responded; Ollama was healthy, while the endpoint reported overall `degraded` with its heap-usage metric at 93% (56 of 60 reported units). This is not recorded as a clean health pass or attributed to this change without further evidence.
- Full isolated SecureShop regression: 306 tests, 305 passed, one skipped, no failures; all three browser exploit cases passed. Runtime and focused-test files match the snapshot. Logs: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-regression-367TZM/tests.log`.

No UI, objective, schema, learner data or AWS/deployment asset changed in this repair.
