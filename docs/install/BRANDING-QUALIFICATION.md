# Rename qualification status

The `owasp-ai-goat` rename changes executable paths, environment variable names,
private installation directories, and source hashes. It is scoped to fresh
installations. It does not migrate an existing private installation or prove that
previously qualified native packages still work after the rename.

## Checks completed for this change

- Frontend: 374 suites / 3,502 tests passed; production and renderer builds passed.
- Database: seven disposable PostgreSQL checks passed for fresh/populated migrations, preserved rows and no-op reruns. All 406 historical migration files remain byte-identical.
- Installer: 128 focused tests passed. An expanded run passed 192 of 193 tests; the remaining fixture checksum assertion was corrected and verified in a subsequent 55-test boundary/path/email run.
- SQL role construction: 24 focused tests passed. A separate controlled launcher run passed 70 of 75 checks; its remaining failures need classification before claiming an aggregate pass.
- Dependency and intentional-vulnerability coverage checks passed.

The broader backend unit run was stopped after failure classification. It had
3,230 passes and 296 failures at that point, including historical source gates;
it was not a completed or passing aggregate run. These results do not establish
that a fresh full installation is ready.

## Native package gates

These historical qualification records remain unchanged. Their checks reject
renamed source until a new native qualification is completed:

| Package | Current gate | Required follow-up |
| --- | --- | --- |
| ARM64 owned System | `SYSTEM_PACKAGE_SOURCE_CHANGED` in `scripts/install/secureshop-owned-system.js` | Rebuild and qualify the renamed config, diagnostic, restart, and upload-preview package; capture new source hashes and actual native results. |
| ARM64 owned Pricing | `PRICING_PACKAGE_SOURCE_CHANGED` in `scripts/install/secureshop-owned-pricing.js` | Qualify the renamed package and its supported isolated startup, then publish the new package record. |
| ARM64 owned Listings | `LISTINGS_PACKAGE_SOURCE_CHANGED` in `scripts/install/secureshop-owned-listings-qualified-candidate.js` | Qualify a new package cohort, including image digest and source-bound native report; then qualify installation/restart. |

Updating hashes alone would falsely attach historical results to different code.
Do not bypass these gates or rewrite historical qualification reports to make an
installation pass. The AMD64 owned-System candidate manifest has current source
hashes, but retains `qualification: null` and `status: unqualified_candidate`.

## Existing native launchers

The following launchers provide the relevant qualification flows:

```bash
python3 tests/run-system-local-package-native-isolated.py --docker-host "$QUALIFICATION_DOCKER_HOST"
python3 tests/run-system-local-package-native-isolated.py --docker-host "$QUALIFICATION_DOCKER_HOST" --upload-preview
python3 tests/run-listings-shared-manager-native-isolated.py --docker-host "$QUALIFICATION_DOCKER_HOST"
python3 tests/run-owned-listings-install-native-isolated.py --docker-host "$QUALIFICATION_DOCKER_HOST"
python3 tests/run-pricing-supported-startup-native-isolated.py --docker-host "$QUALIFICATION_DOCKER_HOST"
```

These are references for maintainers, not currently portable installation commands.
The launchers bind a specific historical Docker authority, SSH configuration,
Rancher Desktop Docker executable, and private Node runtimes under
`/Users/averma5/`. Those paths are absent from the current workstation. An ARM64
Docker daemon is available, but that alone does not satisfy the launchers' ownership
checks. Adapt and review explicit disposable authority binding before running;
never substitute an application database or remove the ownership checks.

The Listings install launcher also requires a qualified package before it runs.
Complete the package cohort first. System and Pricing likewise require source
records that accurately describe what was executed. Controlled unit tests do not
replace these native qualification steps.

## macOS isolated-test runner

Accumulated ignored scratch files can make the macOS sandbox profile exceed its
compiler limit. The observed failure was `INSTR_JUMP_NE_MAX_LENGTH`, with over
3,000 masks, mostly under `tasks/tmp` and `tasks/qualification`.

Use a fresh temporary source snapshot containing the intended source changes and
required dependencies, excluding ignored work journals, then run the normal
isolated launcher there. Retain its filesystem and database guards. Do not run
tests without isolation just to work around the sandbox compiler failure.

Use the self-contained official Node release matching `.nvmrc`, verified against
the release's published checksum. Homebrew Node may load shared libraries outside
its runtime directory; those reads remain blocked by the test sandbox. A temporary
official Node installation avoids widening the filesystem permissions.
