# Local owned System listener package

`Dockerfile.local` packages the existing config and diagnostic listeners in one
image. Run separate containers using the exact final argument `config` or
`diagnostic`. No argument is a failure; selecting a mode does not enable it.
There is no generic script, module, helper path or executor argument.

The source uses the previously qualified immutable Node26.10 ARM64 base. Its
architecture check deliberately rejects another architecture. This new package
has source/controlled checks only until a separate owned native build is
qualified. Earlier executor and full-index proofs do not establish this new
image's identity. Debian package resolution is not pinned: a qualifier must
retain `/opt/owasp-ai-goat-owned-system/packages.txt`, build logs and the resulting image
ID alongside source hashes.

Build context is this directory, for example an explicitly owned build using
`docker build --pull=false -f Dockerfile.local -t <unique-owned-tag> .`.
Use the reviewed Docker authority and a bounded tracked build process. This
command is documentation, not an installer entry point.

The image compiles four fixed static helpers with warning errors, writes binary
checksum manifests, verifies checked config assets, makes code/root-owned
helpers read-only, and selects uid/gid10001. No host volume is needed. Existing
listeners still perform real executor readiness before opening a port and retain
their signal, abort, timeout and descendant-drain behavior.

A qualified runtime profile must supply:

- Read-only root, writable bounded `/tmp` tmpfs (128MiB),512MiB memory,1CPU and
  128PIDs per listener; no host mounts or privileged mode.
- Existing reviewed `owasp-ai-goat-mcp-sandbox` AppArmor profile and
  `seccomp=unconfined`, as used by the retained native fixtures. Missing user/PID/
  network namespace support fails readiness; there is no sandbox fallback.
- A private bearer and explicit enable, literal bind host and nonzero port using
  the selected listener's existing `SECURESHOP_SYSTEM_CONFIG_*` or
  `SECURESHOP_SYSTEM_DIAGNOSTIC_*` variables. The enable variable ends in
  `_HTTP_ENABLED`; token/host/port do not. Tokens are runtime private state, never
  Docker build arguments, image defaults or checked-in environment values.
- Loopback-only published host port when accessed by the local backend.
  A regular outer bridge does not establish egress isolation. The inner
  executor has its own network namespace. Stop must allow the existing20second
  listener drain deadline (the retained harness uses25seconds).

Config mode also provides real owned-listener health metrics. Diagnostic mode
has a separate authenticated readiness endpoint and target-bound execution
contract. Request stdout is not trusted exit/effect proof; the diagnostic
helpers retain the independent private status channel. Packaging adds no
persistent target files, objective grading or model execution.

## Installer work still required

Current setup provisions other owned MCP/HTTP services through the installation
Docker authority and private managed configuration. It does not build or manage
this package. No setup/start/stop integration is added here.

Before supported local activation, an explicit installer must validate canonical
schema readiness, bind the existing verified Docker authority, provision and
preserve separate private bearer values, build/verify this image, verify the
namespace profile and actual authenticated health, and record exact owned image/
container identities. It must preserve existing private environment values and
only publish the corresponding backend capability flags after readiness. It
also needs additive upgrade, restart, shutdown and partial-failure recovery
contracts. Rootless Docker/alternative Linux profiles and AMD64 remain
unqualified. AWS assets and the main sandbox-runner Dockerfile are unchanged.

The September 26 source update is qualified by `tasks/sidecar-owned-system-config-diagnostic-qualified-2026-09-26.json`, `tasks/sidecar-owned-system-runtime-qualified-2026-09-26.json`, and `tasks/sidecar-owned-system-provision-qualified-2026-09-26.json`. These cover owned ARM64 runtime/provisioning fixtures, not the installed application or AMD64. Existing managed installations retain their exact source authority and require an explicit supported migration; this source update does not rotate their configuration.
