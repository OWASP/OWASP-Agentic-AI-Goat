# XSS email authenticity follow-up — September 13

Current source review distinguishes the XSS external email exercise from MCP captured Mailpit. XSS uses Gmail SMTP (`server/services/gmailEmailAgentService.js`) and GuerrillaMail retrieval (`server/services/sharkLasersScraper.js`). SMTP acceptance is not inbox delivery. The existing API parameter `fromEmail` is misleadingly named but represents the recipient; retain its compatibility while correcting learner-facing sender/recipient wording.

## Exercise decisions

- **Keep with repair: email baseline (`xss_e1`).** A successful real query of the configured inbox, including an empty result, is a valid baseline. It does not demonstrate message delivery or execution.
- **Repair: send (`xss_e2`).** Show SMTP acceptance and subsequent retrieval separately. Require a provider receipt and persist an owner/run/generation-bound dispatch record before credit. No actual external messages were sent during this review.
- **Repair: retrieve/execute (`xss_e3`).** The route currently selects by sender substring and first match; it does not bind the retrieved message to this learner's dispatch. Shared or reused public inboxes can supply another learner's payload. The browser proof must use the exact matched retrieved body, with documented wrapper removal/entity decoding, and award nothing for unmatched or stale messages.
- **Keep with corrected explanation: stored profile (`xss_s3`).** The implemented lab proves persistence and execution on the learner's own profile. General multi-viewer stored-XSS risk is context, not evidence that this exercise affected another learner.

## Required provenance implementation

Create an immutable dispatch identity before SMTP, with an unpredictable correlation marker, owner, run, reset generation, canonical recipient, payload digest and pending status. Record actual SMTP acceptance/Message-ID separately; transport timeout remains uncertain and must not trigger automatic resend. Match external retrieval by the server-held marker plus the expected envelope and content evidence, never by sender substring alone. GuerrillaMail message IDs and SMTP Message-IDs are different identifiers.

Persist the dispatch through the PostgreSQL owner workflow and invalidate credit eligibility on reset without claiming to delete external mail. Carry the matching receipt into the grading evidence and require it as deterministic ground truth before the Judge can award completion. Preserve the intentional unsafe HTML sink and existing UI layout. Existing customized instructor solutions must survive any default-content migration.

Qualification must cover two owners sharing an inbox, wrong/missing markers, stale reset generation, modified body, SMTP rejection/timeout, retrieval absence, actual isolated-browser execution and no-execution controls. Use an owned SMTP/API fixture for deterministic tests; qualify an explicitly configured external service separately without sending mail from incidental test execution. The external credentials and public-inbox dependency remain unresolved local-onboarding/reproducibility limitations.

## Implemented teaching-copy checkpoint

The existing page now labels sender and recipient correctly, reports SMTP acceptance separately from retrieval, explains inert innerHTML script elements, and states observed-effect/Judge requirements. Default solution content distinguishes owner-scoped profile proof, external transport, decoded retrieved content and isolated browser execution. No exercise IDs, layout, styles, intentional sinks or instructor database rows changed. The focused mounted frontend suite passes 6/6, including navigation, recipient request contract and acceptance feedback. Full provenance repair remains open.

Final frontend regression: **287 tests across 32 suites passed**. No external email was sent. This validates frontend behavior, not external delivery or completion provenance.

## Dispatch implementation checkpoint

The mounted XSS route now uses `xssEmailDispatch` for sending and retrieval. It records pending evidence before the run ledger admits SMTP, records acceptance only after exact recipient/Message-ID/sender checks, and matches retrieved messages against a current owner/reset-bound accepted dispatch. Opaque in-process proofs are required by the grader; copied JSON success fields cannot award credit. Anonymous sending is rejected before transport. Failed inbox queries cannot count as an empty baseline.

`xssEmailCodec` preserves exact UTF-8 payload bytes through an encoded MIME HTML wrapper. Persisted metadata contains the marker, byte lengths and SHA-256 digests; it does not duplicate raw attack bodies. Existing four-argument Gmail rendering remains unchanged; only the XSS dispatch opts into the exact wrapper. The actual vulnerable decoded HTML sink remains present.

No new schema was needed: the existing PostgreSQL objective-evidence repository provides immutable append and canonical-generation fencing. The service adds actual graph owner/run/generation checks. Retention is bounded to100records in this scenario and30days, not permanent audit history. Pending/accepted/retrieved records consume that cap. Missing, expired, reset or pruned evidence cannot earn new credit. Timeout/crash leaves an uncertain effect; the service does not automatically resend. External mail is not deleted by reset.

The e2 rubric is now `xss_email_acceptance.v2`, describing SMTP acceptance rather than delivery. The e3 rubric is `xss_email_chain.v3`. Browser qualification marks only event handlers from the exact verified email body; unrelated model-summary handlers cannot satisfy the execution criterion.

### Evidence and remaining qualification

- Dispatch service12unit checks pass: pre-effect pending persistence, uncertain send, exact acceptance, immutable proofs, owner/run/reset scope, foreign mail, mutation and missing history.
- Codec3 and SMTP8focused checks pass using actual mail-options encoding and injected transport; no external email was sent.
- Native PostgreSQL integration passes in owned root `owasp-ai-goat-xss-email-dispatch-nm0br61g`: actual identity migrations, evidence repository, run ledger and canonical reset with two owners sharing an inbox. Its SMTP/mailbox responses are injected, and it does not run the Judge/browser. The exact owned container was removed.
- Local `llama3.1:8b` checks pass for e2/e3 positive and copied-proof negative cases; e3 uses actual isolated Chrome. Transport and evidence storage are fixtures in that test, so this is separate from native qualification.
- The real-browser grader test additionally proves that an executing summary sibling cannot credit an inert verified email body.

The complete mounted native+SMTP+mailbox+model+browser+UI path remains unqualified. The current public inbox integration is a material compatibility risk: [GuerrillaMail documents filtering returned HTML](https://www.guerrillamail.com/GuerrillaMailAPI.html), while the new codec intentionally rejects modified wrappers. Do not claim external success from exact fixture round trips. A reproducible locally captured SMTP/mailbox path and an explicitly configured external qualification are still required; no public message has been sent during this repair. [Nodemailer documents accepted/rejected SMTP recipients](https://nodemailer.com/), which support the acceptance distinction used here.

Broad isolated checkpoint `owasp-ai-goat-regression-WgIzde`:1469passed,1failed,37skipped (1507total,162.8s). The sole failure was an older rubric-recovery fixture expecting unowned raw mail to satisfy v2; the fixture now asserts v3 rejects that mail while retaining all required facts. The corrected recovery+grader+dispatch combination separately passes23checks. This is not a green final-source broad result.

SMTP admission follow-up: a single-address check now runs before transport initialization, rejecting lists/display names/header syntax/multiple-at forms while preserving plus aliases. Nine focused service checks pass, including zero initialization/send calls for invalid recipients. Native launcher cleanup also passes explicit SIGTERM fault injection and a clean normal rerun (`owasp-ai-goat-xss-email-dispatch-xbwgnj_m`); that test remains DB/service composition, not external transport qualification.

Subsequent broad isolated regression `owasp-ai-goat-regression-3kz2PO` passes1471tests,0failures,37gated skips (1508total,156.8s). Final follow-ups add the expected sender to pending provenance and advance the deployed Judge bundle to `2026-09-13.grounded-v13`, preventing old unavailable pre-provenance packets from being newly awarded through the existing retry version fence. Existing historical completions are not silently reset/regraded. The sender snapshot separately passes dispatch12checks and actual native composition in `owasp-ai-goat-xss-email-dispatch-a7tld6iu`; final retry-version qualification is being recorded separately.

Final local8B rerun under grounded-v13 passes e2/e3 positive and cloned-proof negative cases (13.96s), including actual target-scoped browser execution for e3. No external mail was sent.

Native final retry fence passes in `owasp-ai-goat-xss-email-dispatch-spl42rvx`: oldv12 unavailable e2 evidence has canRetry=false underv13; beginRetry rejects JUDGE_VERSION_CHANGED; child_evaluation_id staysnull and canonical credit remains0. Actual PostgreSQL repository and owned cleanup are verified. This closes the old-packet retry bypass without deleting historical results.
