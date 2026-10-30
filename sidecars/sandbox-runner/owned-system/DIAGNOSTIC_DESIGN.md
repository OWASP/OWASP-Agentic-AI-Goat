# Dedicated diagnostic executor — unmounted source candidate

This candidate preserves `diagnosticCommand`'s exact shell concatenation. It does not change the qualified config reader, listener, database or application routes. It is an ungraded teaching tool; controlled tests are not genuine model or native isolation proof.

## Trust boundary

The fixed outer supervisor is a Linux subreaper. It creates a private pipe and gives only its write end to the fixed inner init as FD3. Its own FD3 is a different pipe to the Node executor. The inner init becomes non-dumpable before forking, clears all capability sets and enables no-new-privileges. The shell child closes FD3 before exec. An empty `/proc` directory and no mounted procfs prevent descriptor reopening; non-dumpability independently prevents same-UID ptrace/proc access to the trusted init. The shell has no capability to remount procfs. Signals against the init can deny service, but cannot produce an accepted receipt.

An additional close-on-exec pipe distinguishes failure to exec the shell from the shell legitimately exiting127. `waitpid` supplies command exit/signal. The init writes one bounded status record; neither stdout nor command/parent argv is interpreted as a status record. The outer supervisor accepts it only if bubblewrap exits0 and the complete adopted descendant set reaches ECHILD. It then emits the separate drained status. A command exiting70 therefore differs from init or supervisor failure70.

The namespace includes read-only runtime binds, an empty read-only synthetic `/app/config`, ephemeral writable `/work` and `/tmp`, no host/private fixtures, no procfs, and separate PID/user/network/IPC/UTS namespaces. Runtime paths and helper paths are fixed, not caller inputs. Helpers require root-owned, non-writable regular files and installation hash manifests; production packaging is not yet supplied. No relaxed isolation fallback exists.

## Receipt and lifecycle

The executor binds output to normalized operation/request digest and exact constructed command. Raw stdout/stderr use base64 with exact byte counts and SHA256, preserving invalid UTF8. The trusted status contains exitCode or signal and drained=true. Timeout, abort, output overflow, malformed status and helper failure reject without an executed receipt or automatic retry. An enclosing durable admission must regard post-spawn failure as potentially effected, not rolled back.

This initial receipt attests actual shell execution and captured output, not arbitrary semantic claims made in that output. It currently does **not** claim an independently read persistent file-effect artifact. A native probe must demonstrate a genuine fixed synthetic file write/read in the namespace plus clean process teardown; adding persistent artifact publication would require a separate safely inspected target store after drain, not parsing a learner marker.

## Qualification still required

Five initial controlled Node tests cover status forgery, exit70 separation, fixed argv, timeout and pre-abort. The C helpers have not been compiled or executed on Linux yet: the current host is macOS without Linux headers. No existing config-native evidence applies to these new bytes.

Before any mount, use a separately reviewed owned ARM64 build: compile both helpers with warnings as errors, generate immutable helper digests, and enforce the existing bounded disposable container profile. Native cases must include regular shell output and semicolon injection; command70 versus broken init/shell; writing forged status bytes to stdout; attempted FD3/proc/ptrace access; detached setsid descendants; timeout/output flood/abort; read-only runtime and absent host/private/network access; and observed descendant absence. Ordinary FD3 inheritance and actual capability dropping must be demonstrated. An outer hard-kill is an uncertain cleanup outcome, never a successful drain.

Backend admission, original persona/session authority, quotas, immutable durable readback, lifecycle retirement and sibling isolation remain separate unimplemented integration work. Do not manufacture an MCP graph runId or reuse MCP protocol credentials for this direct admin tool.

## Prepared native command (not yet run)

`python3.14 -B tests/run-system-diagnostic-native-isolated.py --docker-host unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock`

The launcher freezes only the dedicated diagnostic closure and itself. It checks the exact ARM64 base, builds both root-owned helpers and their manifests with warnings-as-errors, records resolved packages, then uses an owned network-none readonly container (uid10001,512MiB,1CPU,128PIDs,128MiB tmpfs). Build deadline300s; execution120s. Cleanup verifies owner labels before deletion and absence of exact container, image tag/ID and build process group. No DB, model, application stack or host mount is involved. Source remains unlaunched pending resource review.

The qualification-only `diagnostic-native-attack.c` binary attempts actual PTRACE_ATTACH to the live same-UID trusted init, requiring EPERM; it also checks the shell's empty capabilities and no-new-privileges. It is not a production executor dependency. The Node fixture additionally checks no new outer-container process remains after each run, including detached descendants and failure paths.

Current synthetic effect probes deliberately create and read `/work/diagnostic.conf` within one fixed shell invocation. A realistic read-only `/app/config/application.json` and synthetic `/app/.env` should later use fixed checked-in bytes supplied through input FDs, bubblewrap `--file`, and `/app` remount-readonly, matching the proven config-reader file-link semantics. No caller-supplied roots or host fixture binds are acceptable. That addition is not claimed by the present empty `/app/config` namespace.

A future durable receipt wrapper must additionally bind the full launch target identity and original persona/session/authority version. The current private per-spawn pipe already associates status with this child invocation; it is not a transferable receipt authenticated by a public digest or stdout nonce.

## FD transport correction after retained native failure

Cohort52108 established that packaged bubblewrap0.12.0 rejects `--preserve-fds`. Upstream v0.12.0 bubblewrap.c monitor/reaper branches explicitly preserve passed descriptors in the executed child; its exec path closes proc_fd and explicitly selected sync_fd, not ordinary FD3. The supervisor uses dup2 to clear CLOEXEC. Only the unsupported option was removed; no sync-fd, capability or namespace changes were made. Source: https://raw.githubusercontent.com/containers/bubblewrap/v0.12.0/bubblewrap.c (SHA2563f17ee26057cae9d660801ca8d9ba84722f1bafdcd072d5151ee1c64eeeb15f4). Actual descriptor isolation remains a native proof requirement.

## Native qualification result

Cohort60472 (`vq7nrjkg`) passed13 actual Linux ARM64 probes after the retained FD-option and `/app` mountpoint failures. The only namespace correction was creating `/app` as tmpfs before remount-readonly. CAP_NET_ADMIN was not added. Evidence: `tasks/secureshop-system-diagnostic-native-2026-09-20.json`, including all preceding failures, frozen hashes and exact cleanup. FD closure/ptrace denial, exit70 separation, network denial, detached descendants and failure-path drain now have native proof. Realistic immutable config files, independently published artifact evidence, durable authority binding and application mounting remain open.

## Private target-bound transport candidate (controlled qualification only)

New proposed endpoints are authenticated GET `/secureshop/system/diagnostic-health` and POST `/secureshop/system/diagnostic`; neither is mounted. The private POST is exactly `{targetId,request:{operationId,cmd_template,args}}`. A future durable admission service generates targetId; public teaching requests remain exactly three fields and reject targetId. The wire digest binds protocol namespace, target UUID and original teaching-request digest. `executeBound` requires this envelope, derives the actual namespace hostname from targetId, and wraps the unchanged validated execution result with targetId, hostname and binding digest. The old `execute` method remains unmounted qualification compatibility only.

The client requires a trusted current-authority callback, checks it before readiness/before POST/after result, enforces strict origin and bearer configuration, no redirects, hard transport deadlines and512KiB streamed response bound. Post-dispatch failures are branded unknown with automaticRetry=false; no retry exists. Readiness or authority failure before dispatch remains non-uncertain. The handler authenticates timing-safely, rejects duplicate auth, limits128KiB JSON bodies and concurrency including async readiness, sanitizes errors, and aborts/joins active operations on close. Readiness probes are distinct from admitted diagnostic calls.

21 controlled/unit/real-loopback checks pass, including target mismatch, schema expansion, forged wrappers, wrong bearer, concurrency, streamed timeout/cancel, shutdown drain and single dispatch. These are controlled executor results, not native execution proof. The targetId executor extension changes bytes after native60472: that cohort remains valid only for its frozen unbound execution closure. New target-bound native and HTTP composition qualification is pending. No DB schema, durable original persona tuple, application mounting, deployment or UI changes are included.

Transport deadline correction: the diagnostic client defaults to18seconds (maximum configurable20seconds), covering up to7seconds readiness,3seconds bounded request body,7seconds default execution/drain and1second transport margin. Executor defaults remain4seconds execution+2seconds graceful drain+1second forced-close confirmation. Readiness receives the disconnect/shutdown AbortSignal and is joined before handler close completes; its time no longer consumes the body timer. Controlled24-test aggregate includes an actual3.1second loopback operation (previous3second default would reject), streaming deadline, readiness disconnect and readiness shutdown. Config transport is unchanged.

Prepared native successor adds actual executeBound `/usr/bin/uname -n` correspondence to the admitted target UUID, strict wrapper validation against the real result and malformed private authority expansion rejection. This fixture is syntax-checked but not launched as part of these transport changes.

## Standalone listener and prepared HTTP-native mode

`diagnostic-http-listener.js` is a separate opt-in factory/CLI. It requires `SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED=true`, private bearer, explicit literal bind host and port. Startup awaits actual executor readiness under an8second deadline; shutdown aborts startup/readiness/admitted execution, joins under20seconds, then closes sockets. Headers are bounded8KiB/32entries,64connections,100requests/socket,5second header and20second request/socket deadlines. No config listener or main entrypoint changes.

The28-test controlled aggregate passes. The prepared native command adds `--http` to the same reviewed launcher; it freezes listener/handler/client/wire and helper dependencies, then runs the actual listener on an ephemeral127.0.0.1 port **inside** the network-none container. No port is published. Its random bearer exists only in fixture memory and is not logged. Actual probes cover target-derived hostname through the client, wrong bearer, closed body, overload during a real held command, client disconnect abort/drain, exactly3 diagnostic dispatches and final process absence. Readiness probe count is reported separately. No native HTTP run is claimed until that mode is reviewed and executed.
