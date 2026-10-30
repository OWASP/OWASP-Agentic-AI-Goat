# MCP configuration disclosure evidence checkpoint

Current status: snapshot provenance, the v3 rubric gate and Judge v12 consistency checks are implemented and qualified within the boundaries below. Shared-target isolation and native canonical progress qualification remain open. The initial findings describe the pre-repair state.

The current `mcp_secret_exposure` Judge rubric evaluates returned tool evidence, so a final assistant denial or omission does not erase a real tool disclosure. However, the deterministic gate trusts `get_config` detector annotations without independently qualifying a current configured credential. A secret-shaped decoy can therefore receive credit if the semantic Judge incorrectly accepts it. This remains an unresolved acceptance gate.

## Execution defect repaired

`server/services/mcp/sandboxShell.js` now chains the fixed configuration reads with `&&` and requires numeric process exit code zero. Previously HTTP success plus nonempty stdout sufficed: the command's headings made stdout nonempty even when `cat` failed, and a later successful command could hide an earlier failed read. Partial raw output remains visible for the teaching exercise, but failed or unknown process completion awards no tool success. A reachable runner failure is distinguished from a transport outage. Eight execution/grader tests pass; these use injected runner outcomes and do not constitute sidecar effect qualification.

## Required evidence implementation

Do not hardcode credential values: the key-rotation exercise changes them. Do not compare the actor answer with a secret-shaped regular expression or perform a racing second read and call that a receipt.

A dedicated runner operation should read the current config buffers once, parse supported credential fields from those same buffers, and construct disclosed output from them. Return a versioned observation containing output digest, source digests, and exact output byte ranges/value digests. Missing or unparseable sources, no recognized current credentials, or truncation must not produce a qualifying observation.

The backend must bind the observation to its authenticated owner, run, generation, session and generated invocation ID. A client/model JSON object claiming the same fields is insufficient; verify an internal capability or authenticated receipt and the exact returned output before setting `configured_secret_returned`. Make that fact required and bind the unmasked-value criterion to it. The existing durable grading packet can retain the verified Boolean fact for Judge recovery. Preserve the unauthenticated lab tool and unredacted output teaching sinks.

The generic runner currently binds mutable config/secret directories globally and uses session IDs primarily for working directories. A session ID or a second read cannot establish learner isolation during concurrent rotation/reset. Resolve this containment boundary before claiming connected owner-isolated credential qualification. No AWS, image, entrypoint or deployment assets were changed in this checkpoint.

Required tests include heading-only output, failed/missing/empty/malformed sources, secret-shaped decoys under an overgenerous Judge, forged/cross-owner/cross-run/stale-generation receipts, current values before and after rotation, and exact tool disclosure with an assistant omission. Live sidecar read → receipt → Judge → canonical progress/reset proof remains open.


## Implemented configuration observation and Judge correction

The new fixed configuration snapshot operation reads the actual current `.env` and credentials JSON buffers, emits their original bytes, and records source/credential byte ranges and SHA-256 digests. JSON receipts preserve raw escape spelling; no synthesized credential assignment block is used. Reads, source sizes, receipt counts and output are bounded. The backend verifies the echoed server-generated invocation UUID, exact bytes/ranges/digests, and creates an opaque in-process capability tied to session, owner key, run and both generations. JSON-shaped tokens, altered output and changed scope do not verify. This binds invocation provenance; it does not assert that the shared mutable directories are learner-private.

`toolGetConfig` now uses this operation rather than trusting arbitrary command stdout. The v3 rubric requires `configured_secret_returned`, and both exact credential criteria reference that server fact. The grader strips the private token from model evidence. The canonical completion service independently rejects any Judge pass missing required facts before persistence, on initial evaluation and recovery. No historical learner records were rewritten.

Judge v12 aligns constrained decoding with exact server facts. A fully fact-bound rubric cannot produce an overall verdict contradicting those known facts; semantic criteria remain independently evaluated. Citations must still match allowed observed content, and inconclusive/unavailable remain non-crediting outcomes. Earlier real8B runs repeatedly returned an inconsistent fail despite both verified criteria being true; those failed runs are retained in `/tmp/owasp-ai-goat-config-grading-live-v12.log` and `/tmp/owasp-ai-goat-config-grading-v12-diagnostics.log`. The consistent schema fixes that demonstrated failure without changing the actual file output, inventing evidence or weakening the positive/negative assertions.

## Verification and packaging

- 82 focused tests passed for the snapshot, handler, client, private capability, tool, grader, Judge and persistence boundary before the packaging follow-up.
- Actual disposable old-image runner → fixed snapshot program → tool → local llama3.1:8b Judge → adapter disposition passed: a verified disclosure earns adapter credit despite assistant omission; altered output with the original token fails. Log: `/tmp/owasp-ai-goat-config-grading-v12-consistent.log`. The execution identity and final persistence callback are injected; this is not platform-authentication or native PostgreSQL credit qualification.
- The updated endpoint was then tested in the same owned disposable container: the actual buffers produced eight credential receipts and verified without `/exec`. Removing that container's `.env` caused a non-crediting unavailable result with no fallback execution. The owned container was removed. No running learner sidecar or learner file was modified.
- Old installed sidecars use their existing `/exec` Node runtime to execute the exact same fixed snapshot implementation, only when the new endpoint returns404. This is a real read, not simulated data. Failed, timed-out or truncated execution is rejected. A supported endpoint failure never triggers a second read.
- The backend compatibility program is generated into `server/services/mcp/configSnapshotProgram.js` because frozen AWS images copy `server/` but not sidecar sources. Regenerate with `node scripts/generate-mcp-config-program.js` after snapshot changes. A test compares generated output byte-for-byte with the runner implementation. Four packaging/transport tests pass after this follow-up. No AWS, Dockerfile or deployment asset changed.
- Frozen isolated backend regression: 1,322 passed, zero failed,31 gated skips, log `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-regression-Kg4M7O/tests.log`. It predates the generated-program packaging and named-pipe follow-ups below. Broad tests now point MCP/mail/SSRF sidecar URLs at inactive loopback endpoints so a copied source tree cannot modify live shared sidecars.

Remaining: native canonical receipt/progress integration, real authenticated route/actor qualification, per-learner mutable directories, authenticated backend-to-runner authority and reset isolation. Two source files are read separately, not in a cross-file transaction; final-component symlinks are rejected, but parent-directory containment needs the dedicated owned-target boundary. An internally verified operation does not close those broader isolation gates.


### Final file-type boundary follow-up

Snapshot opens now use `O_NONBLOCK` before validating a regular file, so a learner-created FIFO cannot indefinitely occupy a filesystem worker while waiting for a writer. A subprocess-bounded owned-FIFO test verifies rejection. The compatibility artifact was regenerated from the same implementation;22 final factory, observer, artifact and transport tests pass (`/tmp/owasp-ai-goat-config-final-boundary-tests.log`). The earlier live model proof used ordinary files and predates this file-type-only change.

Root and client `npm outdated --json` both returned empty objects on this checkpoint, and all five learning-dependency registry tests passed. No dependency version or vulnerability pin changed. The current application health endpoint reports healthy and local llama3.1:8b available.
# Native completion boundary follow-up

The required-fact gate exposed a storage contract mismatch: it emitted `REQUIRED_FACTS_NOT_SATISFIED`, which the native repository did not recognize. The category is now registered as terminal and non-retryable. Twelve completion-service tests pass, including the actual repository normalizer.

A frozen-source run against a fresh disposable PostgreSQL 18 database also passed the full durable-judgment integration test, without skips. An injected overgenerous Judge result traverses the actual completion service and native repository: the committed receipt reads back as `fail`, progress remains zero, replay cannot award credit, and retry is rejected with `RETRY_NOT_ALLOWED`. Evidence: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-judge-facts-gi1eewjm/result.log`. This establishes the persistence boundary; it is not a connected MCP actor-to-Judge qualification. The owned container was removed after verification.
