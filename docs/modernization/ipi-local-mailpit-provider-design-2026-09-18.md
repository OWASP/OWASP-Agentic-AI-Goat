# IPI local Mailpit provider design (2026-09-18)

Status: design only. No application, database, native, browser, model, or external-mail execution was performed.

The IPI route currently pairs `server/services/gmailEmailAgentService.js` with the external `server/services/sharkLasersScraper.js`; its test fixture Mailpit adapter is not production delivery. Add an opt-in `IPI_EMAIL_PROVIDER=mailpit` composition that pairs a local SMTP sender with a bounded Mailpit HTTP inbox reader. Keep Gmail as the default and leave AWS assets unchanged.

Use a small `server/services/ipiEmailProvider.js` factory with `sendEmail`, `fetchEmails`, `fetchEmail`, status, validation, and close methods. Base transport/readback checks on `server/services/xssLocalMail.js`, but use an IPI-specific sender and opaque server-assigned inbox address derived with a server-held HMAC over the authenticated owner and current durable generation. Resolve it inside an admitted execution; reject arbitrary, foreign, and stale addresses. Do not expose the Mailpit API URL to the browser. Require SMTP `messageId`, exact accepted recipient, empty rejects, then read back the exact Mailpit recipient/sender/body with a distinct Mailpit message ID. Persist SMTP and Mailpit IDs through the existing email log and `runEmailFetchGraph`/`emailArtifactStore` paths.

Route health should expose the local owned inbox and provider mode while preserving the current UI response shape. `save-email`, send, and fetch should verify the current server-owned address. Reset should retain existing run/artifact fencing and rotate the local generation; the next admitted execution derives a new inbox. Add `IPI_EMAIL_PROVIDER`, `IPI_MAIL_DOMAIN`, `IPI_MAIL_FROM`, `IPI_MAIL_HMAC_SECRET`, Mailpit endpoint/limit config, and compose wiring. Host Mailpit ports must bind loopback; full-app Mailpit should remain internal. Pin the image separately instead of using `latest`.

Acceptance requires two-owner disposable PostgreSQL coverage, real SMTP acceptance plus Mailpit HTTP body/ID provenance, foreign/stale/reset isolation, and canonical artifact/judge receipts. A Mailpit sink does not qualify Gmail delivery, and the existing fixture pass must not be reported as production qualification.

Evidence and exact source ranges are recorded in [the companion JSON](../../tasks/ipi-local-mailpit-provider-design-2026-09-18.json).
