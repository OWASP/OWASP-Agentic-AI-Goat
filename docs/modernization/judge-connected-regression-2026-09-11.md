# Connected Judge and ownership regression checkpoint

This checkpoint extends the grounded-v11 250-case supplied-evidence qualification with actual actor/tool workflows and fixes found while checking the path to durable completion. It does not certify every possible prompt or the complete modernization release.

## Implemented corrections

- DPI reset during inference returns `409 AGENT_RUN_CANCELLED`, with no provider-outage hint or late receipt/credit.
- CodeBot preserves the exact explicit JSON manifest after the model selects `check_dependencies`. The actual model previously truncated a valid manifest to `{`, causing a tool failure before grading. The binding also covers objects without recognizable package fields, preventing an invented model transform from replacing user data. Ambiguous or malformed explicit data returns an actionable400 before effects. Intentional transform fields remain unchanged.
- Main startup requires both PostgreSQL engine selectors before application/database imports. A partial configuration could previously leave MCP/CSRF on a legacy SQLite branch.
- Platform imports record an immutable archive-bound attendee identity map. MCP, CSRF, XSS, FinFlow, Supply Chain, CTF and legacy-sensitive import paths require a verified matching mapping before applying owned state. Canonical and explicitly resolved numeric aliases map to the target identity; unresolved, unused and colliding resolutions fail. Raw provenance and teaching-local IDs remain unchanged.
- FinFlow and legacy-sensitive archives now have independent immutable import records. Additive migration0007 preserves historical legacy-sensitive records while moving them to their own namespace. Both import orders are tested.

## Recorded verification

The 937-test backend and 71-test native results below are checkpoints from before the XSS DOM-v2 correction. They must not be presented as a regression run of that later change.

| Check | Result | Evidence |
| --- | --- | --- |
| Isolated backend regression | 937 passed,23 gated skips,0 failures | `/tmp/owasp-ai-goat-owner-judge-isolated-unit.log`; owned source copy `owasp-ai-goat-regression-z5I4Tb` |
| Native PostgreSQL aggregate | 2 operator CLI tests +69 native tests passed,0 failures | `/tmp/owasp-ai-goat-owner-judge-native-aggregate.log`; owned source copy `owasp-ai-goat-regression-pemM5e` |
| Application boot | 2 checks passed after14 native initializers | Same native aggregate |
| Workshop service suites | ARIA105 passed/7 gated skips; NOVA137 passed/7 gated skips | Same native aggregate full `tests.log` |
| Native200-attendee workload | 200 HTTP200,210 completed runs,10 resets; p50=2395ms,p95=3948ms,total4541ms | Same native aggregate; explicit mock inference |
| Frozen learning packages | 4 investigate/frozen packages retained | `/tmp/owasp-ai-goat-owner-judge-learning-gate.log` |
| Owner mapping across stores | Native tests preserve source7 provenance and map attendee state to71, leaving current7 unrelated | Native aggregate, plus focused native import and owner-proof tests |

The native aggregate used a new empty PostgreSQL container on loopback32777. The owned container was removed after successful completion; the separate shared fixture server was retained. Working `.env`, databases and uploaded assets were not used for these checks. Earlier verification incidents remain recorded separately in `verification-incidents.md`.

Actual local8B workflow results, actor variability, failed fixture assumptions and exact scope are recorded in [live workflow qualification](judge-live-workflow-qualification.md). These representative probes are separate from the full250-case evidence matrix. The CTF level-1 successful guardian-disclosure path and XSS reflected DOM-v2 path now have bounded connected proofs, recorded in that document. Other objectives and adapters, whole-installation asset activation/recovery and the final release-candidate browser flow remain subject to their explicit gates. The historical 250-case supplied-evidence matrix predates `xss_dom_preservation.v2`; the later supplement below qualifies the changed contract. No AWS/CloudFormation/deployment asset was changed by this continuation, and the mock workload is not an AWS or200-way model-throughput claim.

## XSS DOM-v2 final supplement

The reflected HTML objective previously treated the exact opening-tag substring as proof of preservation. An actual actor response added styling to `<b>hello</b>`, causing a false negative. The grader now uses an isolated browser comparison of the learner element, contents and supplied attributes; added presentation class/style are allowed. Escaping, changed contents/attributes and unrelated wrappers do not qualify. Only the R2 rubric changed, to `xss_dom_preservation.v2`; shared Judge policy remains grounded-v11.

- Six dedicated real local8B DOM cases passed all assertions: two expected passes and four expected failures. Log: `/tmp/owasp-ai-goat-xss-dom-v2-live.log`.
- All24 XSS and8 legacy-email evidence cases passed:16 pass,16 fail, no unavailable/inconclusive, false positives or false negatives. p50=2298ms, p95=4388ms, max=5368ms; three primary repairs. Log: `/tmp/owasp-ai-goat-xss-dom-v2-all-objectives.log`.
- The actual reflected actor/browser/Judge/native-receipt workflow passed1/1, including styled preservation, inert-script rejection, event execution and authenticated reset. Log: `/tmp/owasp-ai-goat-xss-browser-native-dom-v2.log`.
- Final isolated backend regression after the change:940 passed,24 gated skips,0 failures (964 total), approximately119 seconds. Log: `/tmp/owasp-ai-goat-dom-v2-final-unit.log`; owned copy `owasp-ai-goat-regression-lmzT5i`.
- Independent DOM integration review found no concrete defect;22 focused tests passed with one live-model skip. Log: `/tmp/owasp-ai-goat-xss-dom-final-review.log`.

The [machine-readable supplement](judge-dom-v2-qualification-2026-09-11.json) preserves the six individual cases and the32-case summary. The original250-case report remains historical; this targeted supplement does not claim a new full250-case run or universal semantic accuracy. No working database, environment file or uploads were used for these runs.


Latest assembled follow-up:970 backend passes/24 skips and75 native checks are recorded in the [release-candidate checkpoint](release-candidate-checkpoint-2026-09-11.md), alongside actual R2 DOM-v2 dashboard parity and9 offline fixed-tree tests. The earlier937/71 table remains historical. Subsequent owner metadata and archive-reader bounds corrections still require their own closure evidence.
