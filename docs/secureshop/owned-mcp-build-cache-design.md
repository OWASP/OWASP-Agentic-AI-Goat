# MCP candidate build cache: ownership prerequisite, not build admission

Status: **no live build admitted**. The new `owned_mcp_build_cache.py` helper is
not connected to the launcher and creates no resource. Its controlled tests
inject fake Docker responses; they do not establish BuildKit compatibility.

## Existing bounds do not cap build disk

The packaged manifest permits exactly 20 source inputs, each at most 2 MiB and
at most 8 MiB in aggregate. The launcher streams those inputs from the current
checkout. That avoids a source replica; it is not an image-size limit.

The 512 MiB executor bound is container memory. The 300-second build timeout
limits elapsed time, not bytes written. `Dockerfile.candidate` pulls a pinned
Node image, installs compiler/runtime Debian packages in two stages, runs
`npm ci`, builds native/bundled assets and exports an image. Base layers,
unpacking, package downloads, intermediate snapshots, daemon content storage,
BuildKit cache and an unrestricted build log are not bounded by the context
limit or executor memory. Digest pins establish identity, not expanded size.

The reviewed current daemon inventory has no Node base image or admitted
BuildKit worker image. It cannot complete this Dockerfile offline as-is. The
current shared-cache `docker build` path therefore remains no-go under the
task's unresolved minimal-disk constraint. A successful build followed by image
tag removal would not prove removal of intermediate cache or pulled layers.

## Proposed per-run cache boundary

Prefer a dedicated worker with no state volume over a shared builder or an
ordinary named volume. The proposed cache worker has:

- A fresh 32-hex run owner, deterministic private name, reviewed immutable image
  ID and captured immutable container ID on the exact already-owned daemon.
- Exact ownership/resource/cache-size labels; no adoption by a matching name.
- A read-only root; no binds, named/anonymous volumes, devices or inherited
  volumes; a size-limited `/var/lib/buildkit` tmpfs (1–256 MiB), plus 16 MiB
  `/tmp` and 4 MiB `/run` tmpfs mounts.
- Non-root identity, no added capabilities or privileged mode, all capabilities
  dropped and no-new-privileges; 512 MiB memory with no additional swap,
  one CPU, 128 PIDs, and Docker logging disabled.

These are a proposed strict profile, **not a verified functioning BuildKit
configuration**. Rootless workers may need permissions or filesystem behavior
that this profile denies. Do not silently add privilege, unconfined policies,
a Docker socket, persistent volumes or an unbounded fallback to make it work.
The helper does not supply create/start/build commands. No builder image is
downloaded or admitted by this proposal.

Unlike a named cache volume, removing an immutable container ID avoids a
name-based volume deletion race. Only that container's tmpfs state is reclaimed.
No generic prune, builder prune, daemon cache deletion, image deletion or volume
deletion belongs in this helper.

## Integration contract for later review

`CacheSpec(daemon_id, owner, image_id, cache_bytes)` is immutable metadata only.
The caller must pin the Docker executable and endpoint, enforce bounded command
timeouts/output, verify the existing VM's backing disk remains repository-local,
and admit the image and worker configuration separately. All caller records and
bounded logs must stay in the existing owned repository runtime directory.

After an explicitly authorized create, record the returned full container ID
before start. `inspect_cache(command, spec, captured_id)` checks daemon identity,
both name and ID, labels, image and the complete required storage/resource
profile. Missing identity, denied or malformed inspection, inconsistent identity
or any extra writable mount fails closed. An interrupted create with no reliable
ID is an unresolved resource attempt, not automatic ownership by name.

After stopping the build client and ending use of the worker, call
`cleanup_cache(command, spec, captured_id)`. It repeats identity validation,
rechecks the daemon before deletion, issues only `rm --force <captured-ID>`, then
requires both ID and name absence. A replacement with the same name is not
removed and prevents a clean receipt. Errors remain cleanup failures, including
profile drift; they do not authorize broader cleanup. A genuine live owned
worker smoke and interruption test are still required before integration.

The result deliberately retains `buildAdmitted: false`,
`daemonImageDiskBoundEnforced: false`,
`daemonImageContentCleanupVerified: false` and
`qualificationComplete: false`. Cache removal cannot close those other gates.

## Decision still required

A tmpfs worker would bound its configured scratch/cache mounts, not Docker's
shared image/content store or filesystem metadata. Streaming an image export
through memory likewise does not bound the daemon's unpacked image bytes.
Do not infer exclusive ownership of a newly observed base layer from a before/
after inventory: another client can share it. Preserve preexisting PostgreSQL
and every unrelated image/container/volume.

Before any download/build, choose an explicitly authorized storage budget and
an independently enforceable boundary for **all** new build/pull/export storage
on the same repository-local VM. Verify a compatible pinned worker and its
expanded image requirements. Bound host build logs and account for interrupted
builds, image-export failures and daemon restarts. If the existing shared daemon
cannot enforce that boundary without altering preserved resources, a fresh
daemon/VM or unbounded build is outside this task's constraint: stop for the
user's decision. Merely promising later cleanup is insufficient.

No Judge, objective qualification, execution sink, source-copy policy or runtime
launcher behavior changes in this prerequisite.
