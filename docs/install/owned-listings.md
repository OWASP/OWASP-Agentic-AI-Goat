# Owned Listings installation

Preview with `npm run setup -- --plan --owned-listings`. Install or add the
runtime with `npm run setup -- --owned-listings` or
`npm run setup -- --upgrade --owned-listings`. The Unix bootstrap scripts accept
the same option. Plans do not mutate the installation.

The opt-in prepares one shared manager and private persistent journal volume.
It verifies the checked-in package qualification, uses the application's
recorded Docker authority, automatically installs the exact workspace AppArmor
profile, builds the package and checks authenticated manager health. No manual
package record or preinstalled Listings profile is required. Source changes
invalidate the qualification and stop preparation before application changes;
a new package must receive independent native review before its checked-in
manifest is updated.

Only Linux ARM64 containers are currently qualified, including macOS ARM64
through the recorded Colima VM. AMD64 fails before provisioning. Qualification
on macOS does not establish native Linux host or AMD64 installer coverage.
The checked-in manifest is
`scripts/install/manifests/owned-listings-arm64.candidate.json`; the retained
candidate filename does not bypass its exact source and evidence checks.

Preparation is separate from activation. Its successful result reports
`managerReady: true`, `ready: false`, `capabilityAvailable: false` and
`activationEnabled: false`. It writes disabled private configuration. The
production backend assembly requires canonical schema privileges and lifecycle
hooks, the qualified manager, model and Judge dependencies, and the hashed
Product description renderer/browser dependency before exposing readiness.
Do not manually enable the private configuration to bypass qualification.

The supported activation contract has narrow installed ARM64 qualification;
fresh provisioning and other platforms retain the limits below.
`--owned-listings` alone continues to prepare the manager and stage disabled
configuration. For an additive activation, first stop the application, then use
the exact command below:

```bash
npm run setup -- --upgrade --no-install --owned-listings --enable-owned-listings
```

`--enable-owned-listings` is invalid without `--owned-listings`. The combined
command must verify the qualified package, retained manager identity, schema,
cleanup bindings, private configuration and application prerequisites before it
atomically publishes the enabled state. Repeating it for an already enabled
installation is verification-only. Restart the application normally after the
command completes. An enabled configuration alone is not workflow or release
evidence.

The integration spans `scripts/install/listings-setup.js`,
`scripts/install/secureshop-owned-listings-provision.js`,
`scripts/install/secureshop-owned-listings-activate.js` and
`scripts/start-application.js`; freeze and qualify that closure together.

For an already enabled installation, normal `./start_all.sh` startup will verify
and recover only the exact retained stopped manager named by the managed
configuration. Startup does not build, create or adopt a Listings manager. A
missing, changed or foreign manager fails readiness instead of silently
replacing it.

The installation contains one narrow recovery for an existing disabled,
never-admitted manager recorded at `127.0.0.1:8095` when that exact retained
container is running but has no network attachment or published endpoint.
Recovery runs only during explicit paired activation under the maintenance
lease. It requires an empty private journal and all seven owned-work tables to
be empty, unchanged private configuration and token, the exact qualified
source, authority, profile, image, network, volume and container, and a free
`8099` host and Docker port. It journals each step, stops and retains the
original container under a deterministic recovery name, creates and
health-checks the canonical successor with the same token, image and private
journal volume, and CAS-retargets the still-disabled managed record to `8099`
before activation continues. Interrupted recovery resumes from the private
journal. Enabled, used, foreign, mismatched or non-`8095` managers are not
retargeted; failures preserve the retained resources and disabled state.

The supported v85 explicit activation exercised this recovery on the installed
application: it retained the original container, enabled the successor on
`8099`, and preserved all 271 captured database-table fingerprints. The
source-v86 cold-start check then restarted the exact same enabled container and
matched its managed configuration, image, network and journal mount. See
`listingsActivationV85` in the [retained evidence summary](../../tasks/secureshop-cart-browser-2026-10-09.json)
and the private v86 receipt at
`~/.dvaia/recovery/secureshop-activation-preservation-2026-10-10/coldrestart-v86.json`.

A separate benign installed workflow used actual `llama3.1:8b` to fetch the
owned synthetic JSON source, then publish **Supplier lamp** as product 127. The
product survived reload and the qualified cold restart. Its immutable receipt
is summarized as `listingsBenignImportV85` in the retained evidence summary and
stored privately as
`~/.dvaia/recovery/secureshop-activation-preservation-2026-10-10/benign-import-v85.json`.
This proves that one bounded benign fetch-to-publish path and persisted product;
it does not prove an exploit, Judge result, broader Listings workflows or model
reliability.

A later vulnerable-mode run used actual `llama3.1:8b` to select
`listing.fetch_parse` and `listing.publish` for the owned protected training URL
`http://10.0.1.100:8080/catalog.json`. Operation
`7cfae1c6-0012-42c8-bc5d-200497a7dadb` published product 129 once. Reload showed
the product once, preserved the same award and did not repeat the import. The
canonical Judge evaluated `ss_listing_internal_fetch` once and awarded the
objective. The retained summary is `listingsInternalFetchJudgeV86` in the
[evidence inventory](../../tasks/secureshop-cart-browser-2026-10-09.json).

This proves only the bounded vulnerable-side fetch of that owned source and its
durable publication. It does not prove a denied-egress-policy bypass or
arbitrary private-address reachability. The fixed-mode denial and no-effect/
no-credit counterpart, exact saved-operation recovery, final workflow readback
and full current source/build compatibility of the private receipt remain
pending. This result therefore does not establish Listings or release
readiness.

The checked-in package copy and retained qualification record remain validated
as frozen inputs. Fixture and copy corrections in controlled tests do not
extend the installed evidence beyond the exact v85/v86 cases above.

The installer copies the exact source closure into a private build context,
records immutable image/source/runtime identities, and stages the private
bearer before container creation. The bearer is absent from command arguments
and returned results. Repetition preserves the same container, volume and
bearer. An uncertain create result is read back under the original identity.
Failed health preserves disabled configuration for recovery. Existing private
application configuration and learner data are preserved.

Fresh preparation selects the first loopback host port that is free in both the
host network namespace and every published binding in the recorded Docker
daemon from `8099` through `8108`; the container endpoint remains `8095/tcp`.
If the entire range is unavailable, preparation fails before staging manager
resources. The managed configuration records the selected loopback origin, and
repeat setup verifies and preserves that exact port. Container limits are 512
MiB memory, 1 CPU, 128 PIDs and a 16 MiB temporary filesystem, with a separate
private persistent journal volume. These limits do not establish model
throughput or learner-capacity qualification.

Profile installation uses Linux sudo or the recorded Colima SSH authority. It
serializes under a root-owned profile lock, parses before publication, publishes
without replacement, and rejects changed or foreign profile bytes. The lock
`/etc/apparmor.d/.<profile>.install-lock` remains for repeat installation.
Disposable qualification launchers account for their exact profiles and locks
when cleaning up; they never remove another installation's resources.

Supported setup also uses an explicitly configured `npm_config_cafile`,
`NPM_CONFIG_CAFILE` or `NODE_EXTRA_CA_CERTS` bundle, in that precedence order.
Preflight validates and hashes it; a change before provisioning fails closed.
The automatic provision API accepts `buildCaFile` with `buildCaSha256` for a
reviewed build CA bundle. It validates a bounded regular file and copies it
privately for Docker's `npm_ca` BuildKit secret. This is not a runtime credential
or an image layer.

The isolated ARM64 installer gate proved fresh installation, repetition,
failed-health recovery and private configuration preservation; its independent
review receipt is retained privately and is not part of the source release.
A separate native assembly gate proved runtime-role schema checks, private cold
loading, HTTP readiness, actual import publication/replay, rewrite save and
canonical reset with remote retirement and sibling preservation. Its provider
was controlled: it establishes no genuine model, browser or Judge credit.
New worker assets require a new package qualification even if these earlier
installer and assembly mechanisms passed.

Controlled checks:

```bash
node --test tests/secureshopListingsInstall.test.js tests/setupApplication.test.js tests/installBootstrap.test.js
node --test tests/secureshopListingsRuntime.test.js tests/secureshopListingJournal.test.js tests/secureshopBoundShutdown.test.js
```

Native installer and assembly launchers require the explicitly reviewed Docker
host, disposable stores/configuration and the sole heavy-test slot. They never
target the installed application. Remaining release gates include fresh
provisioning and port-range qualification, the fixed internal-fetch counterpart,
current-source receipt compatibility, broader rendered-workflow qualification,
and each additional supported architecture or host.
There is no native Windows qualification. The installed v85 activation and v86
same-resource cold start qualify only the retained ARM64 installation described
above. Fresh provisioning across the `8099`–`8108` selection range remains
unqualified, as do other architectures and hosts, other exploit/Judge behavior,
and full workflow/browser acceptance.
