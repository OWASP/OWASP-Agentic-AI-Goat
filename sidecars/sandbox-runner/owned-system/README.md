# Unmounted owned System config executor

`executor.js` exports `createSystemConfigExecutor().read({operationId, path}, {signal})`.
There are no caller root, fixture, helper, binary or worker parameters. Constructor
process/filesystem hooks are trusted controlled-test seams, not HTTP inputs.

The fixed worker runs the existing single-pass traversal reader against a
read-only synthetic `/app` tree. `....//.env` reaches `/app/.env`; the runtime's
host application tree is never mounted. Runtime libraries are read-only, network
and PID namespaces are new, `/proc` is empty, and temporary writes are namespace
local. The separate fixed init drops/attests every capability set and no-new-privs
before executing Node. The worker/reader/contract bytes are checksum checked and
piped read-only into the namespace. The parent independently checks exact content,
resolved target path and digest against its fixed synthetic fixtures.

A `status: completed` receipt means a checked worker observation was obtained
with exit0 and a drained supervisor. `readResult.ok: false` is a completed
negative file observation, never a successful read. Executor timeout, truncation,
nonzero exit or uncertain drain yields `status: unavailable` without file content.
Missing namespace readiness fails closed before dispatch. No durable admission,
launch authority, readback, retry, HTTP route or installed activation exists here.
The operation UUID identifies this invocation; it is not an idempotency journal.

## Native review gate — not run

Use the explicitly owned Colima `dvaia-pg-verify` Docker daemon only, a unique
image/tag/container, and the reviewed ARM64 Node26.10 immutable base. Build a
focused temporary Dockerfile that installs the existing reviewed bwrap runtime
and compiles these new fixed C helpers at the executor's exact libexec paths.
Do not edit the shared production Dockerfile. Freeze source hashes and build
provenance before execution. Run as10001:10001, read-only outer root, no network,
512MiB memory,1CPU,128PIDs, bounded tmpfs and maximum120s qualification wall.
Use only the already reviewed AppArmor profile; no broad host/private mounts.
No PostgreSQL, model, learner data or service ports are needed.

Qualify real ordinary/traversal/denied/missing reads and exact correspondence;
read-only fixtures, no host/private visibility, network namespace isolation,
capability/init attestation; unavailable bwrap/init/asset tampering; bounded
stdout/stderr and timeout. Separately exercise the compiled subreaper with a
trusted test child that creates descendants, including detached grandchildren,
then exits or ignores TERM. Observe actual PIDs absent before reporting drained.
That subreaper stress fixture is not a public executor input or worker override.
Current fake-child timeout tests establish orchestration only, not native drain.
Finally verify exact container/process/image absence and retain failed evidence.

The September 26 source update is qualified by `tasks/sidecar-owned-system-config-diagnostic-qualified-2026-09-26.json`, `tasks/sidecar-owned-system-runtime-qualified-2026-09-26.json`, and `tasks/sidecar-owned-system-provision-qualified-2026-09-26.json`. These cover owned ARM64 runtime/provisioning fixtures, not the installed application or AMD64. Existing managed installations retain their exact source authority and require an explicit supported migration; this source update does not rotate their configuration.
