# Explicit fresh SecureShop/System setup

The source now accepts the combined opt-in:

```
npm run setup -- --qualified-secureshop --owned-system
npm run setup -- --plan --qualified-secureshop --owned-system
```

Neither option is implicit. `--qualified-secureshop` without `--owned-system`
fails before work. The ordinary setup path is unchanged. Existing installations
may use the corresponding `--upgrade` combination; fresh setup still refuses to
overwrite an existing `.env` or regenerate existing credentials.

## Activation sequence

The existing qualified record intentionally couples bound reviews, persona inbox,
MCP trust and controlled SSRF, plus SS_ENABLE and two synthetic fixture roots.
It remains coupled. The opt-in explicitly selects the six baseline runtime
surfaces; it does not enable audit-summary, remote MCP spawn, prompt policies,
external HTTP consumers, catalog visibility or objective credit. Current curriculum
metadata additionally contains audit exercise groups; validating their declared
catalog identities does not enable those optional runtime consumers.

Before database/package/environment mutations, read-only preflight rejects any
non-ARM64 platform, verifies the exact source package manifest, reads an existing
recorded Docker authority or requires explicit DOCKER_HOST, verifies that daemon,
and verifies the exact enforced AppArmor profile. A missing profile is an unmet
prerequisite, never a reason to fall back or install a machine profile silently.
Existing pending candidate/lock state requires inspection before proceeding.

After ordinary fresh schema/seed and private credential creation, the combined
helper records the explicitly selected/reverified Docker authority if ordinary
sidecar setup did not already do so. It creates only the owned fixture roots,
stages a disabled qualified record, and writes a fixed-name private candidate
from validated captured bytes. The readiness child accepts only that canonical
private candidate path; callers cannot supply an arbitrary path or environment
substitute. Its real schema, runtime-role, privilege, migration-ledger, tool and
catalog readiness gates run before enabled publication. Its result must match
current declared objective identities and exercise-group identities; the former
stale hardcoded10-objective check was corrected without enabling objectives.

The helper checks candidate bytes/identity again, then CAS-publishes the qualified
record and invokes the qualified System activation adapter. On System failure,
it restores only the exact record this invocation published. It never rolls back
credentials, data, catalog settings, existing enabled records or concurrent edits.
Successful identical repeat does not rewrite an enabled record, including valid
comments. Changed candidate bytes remain as recovery state rather than being
silently deleted. Readiness and record publication are sequential, not a Docker/SQL
transaction. Startup retains all existing live readiness gates.

## Controlled qualification and native scope still open

65 controlled tests passed across combined setup, System activation and supported
setup regressions. They cover complete fresh-call ordering (preflight, schema,
seed, qualified readiness, System), repeat, malformed result, candidate tamper,
concurrent record drift, System failure preserving generated private credentials,
no hidden extra consumer flags, and missing profile before any setup work. The
controlled readiness results are not real PostgreSQL or model proof.

Next native proposal: reuse the owned16-store/System startup harness with a fresh
private provisioning manifest/environment created by actual setup rather than
pre-seeding a representative upgrade. Freeze current source and both package and
review renderer. Use real candidate readiness and real startup after combined
activation. The supported `--no-install` variant can reuse exact installed Node
modules/browser/model/embedding prerequisites; it must be labeled as such, not a
cold-machine package installation. Ordinary setup's actual model verification
must be explicitly bounded and coordinated; no mock replacement can count as
fresh model verification. Unrelated sidecar/email choices must be explicit in the
fixture and reported, or their actual owned containers must be added to the
reviewed resource plan. No native fresh launch has occurred yet.

## Remaining full-install requirements

ARM64 execution has real package proof. AMD64 needs a separate pinned base,
compiled-helper/package and isolation qualification, then architecture-aware
manifest selection. Merely forcing ARM64 on x64 is prohibited and now rejected.
Linux-host provisioning also needs host-level profile/authority rehearsal; the
existing Linux ARM64 container execution proof is not a Linux fresh-host installer
proof. Windows/rootless/unsupported namespace profiles remain unqualified.

A separate reviewed profile provisioning step is required on a fresh machine:
render the exact checked template; verify the selected local daemon/Colima VM;
check sudo capability and parse with `apparmor_parser --skip-kernel-load`; refuse
an existing differing profile; install only a missing exact profile at
`/etc/apparmor.d/dvaia-mcp-sandbox` as root:root0600; load it and verify exact digest,
ownership and enforced state. Existing `mcp-owned-provision` Linux/macOS routines
implement those operations, but also provision other owned resources and reload
the profile. They are not a read-only `--plan` command or an automatically granted
System-only profile operation. A dedicated narrow profile installer/plan wrapper
and explicit machine-wide scope review remain required before invoking them for
this fresh path. No profile/daemon/installed environment changes were made during
this source phase.
