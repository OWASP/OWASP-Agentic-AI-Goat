# Gmail SMTP Setup

DVAIA supports optional Gmail SMTP for these workshop features:

- **Email Agent challenge** — Indirect Prompt Injection via email
  (`/api/email-agent`, backed by `server/services/gmailEmailAgentService.js`)
- **XSS Workshop, "email" tab** — the stored-XSS-in-email exercise on
  `/workshop/xss`

Fresh setup provisions the owned local Mailpit service for local lab workflows.
The XSS email exercise defaults to Gmail and an editable SharkLasers inbox, so
it needs these credentials before sending. The IPI Email Agent remains
configurable independently. Local delivery does not require a Gmail account or
App Password. External email delivery and HTML filtering differ from local
Mailpit and are not proof of exact exploit-body preservation.

The fresh installer deliberately does not collect third-party credentials, but
it writes blank `GMAIL_USER` and `GMAIL_APP_PASSWORD` placeholders into the
private `.env` it creates. Configure SMTP after setup by following the steps
below.

---

## Step by step

### 1. Pick a Gmail account

We strongly recommend a **dedicated Gmail account** (something like
`dvaia-lab@gmail.com`) rather than your personal one. During the workshop
this account will:

- Send test emails to attackers
- Receive replies containing student payloads
- Show up in every generated email header

Create one at <https://accounts.google.com/signup> if you don't have a
throwaway account yet.

### 2. Enable 2-Step Verification

Google requires 2FA on the account before it will hand out App Passwords.

1. Sign in to the Gmail account.
2. Visit <https://myaccount.google.com/security>.
3. Under **How you sign in to Google**, enable **2-Step Verification**.
4. Follow the prompts (phone number or authenticator app).

### 3. Create an App Password

App Passwords are 16-character tokens Gmail issues per app. Regular Gmail
passwords will not work for SMTP.

1. Visit <https://myaccount.google.com/apppasswords>.
2. Under **App name**, type `DVAIA` (or pick "Mail" from the dropdown if
   your account UI still shows the legacy picker).
3. Click **Create**.
4. Google shows a 16-character password like `abcd efgh ijkl mnop`. Copy
   it — you cannot view it again. Spaces are optional; the code treats
   `abcdefghijklmnop` and `abcd efgh ijkl mnop` the same.

### 4. Add the credentials to `.env`

Open the DVAIA repo root, edit `.env`, and set:

```env
GMAIL_USER=dvaia-lab@gmail.com
GMAIL_APP_PASSWORD=abcdefghijklmnop
# Enable Gmail only for the exercise(s) you want to send external mail:
IPI_EMAIL_PROVIDER=gmail
XSS_MAIL_PROVIDER=gmail
```

### 5. Restart

```bash
./stop_all.sh && ./start_all.sh
```

On Windows, stop the foreground launcher with Ctrl+C and start it again:

```powershell
.\scripts\install\Windows\start_all.ps1
```

Verify by opening the Email Agent challenge or the XSS Workshop's email
tab. If SMTP is configured, sending an email returns success. If not,
you'll see `Gmail SMTP not configured`.

---

## Troubleshooting

**`Error: Invalid login: 535-5.7.8 Username and Password not accepted`
(`EAUTH`).** You're using a regular Gmail password, or the App Password
was mistyped. App Passwords are 16 characters — no more, no less. Delete
the entry at <https://myaccount.google.com/apppasswords> and generate a
new one.

**`App Passwords` link says "This setting is not available for your
account".** Your account does not have 2-Step Verification enabled, or
Google Workspace admin has disabled less-secure app access. Enable 2FA
first (Step 2 above); for Workspace accounts ask your admin to allow
App Passwords, or use a personal Gmail account instead.

**Emails send but never arrive.** Check the sender account's **Sent**
folder — Gmail keeps a copy of every outbound SMTP message. Also check
the recipient's spam folder.

---

## Credential-free local IPI Mailpit mode

Fresh setup provisions the owned loopback Mailpit provider automatically. It requires the supported local Docker authority and verifies both the Mailpit API and SMTP listener before completing setup. Existing installations preserve their configured provider. To select local Mailpit explicitly during an existing-installation migration, use:

```bash
IPI_EMAIL_PROVIDER=mailpit
IPI_MAIL_HMAC_SECRET=$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")
MAILPIT_SMTP_HOST=127.0.0.1
MAILPIT_SMTP_PORT=1025
MAILPIT_API_URL=http://127.0.0.1:8025
```

The application assigns a generation-scoped inbox per signed-in learner. It accepts a message only after local SMTP reports the exact recipient, then reads the exact message through Mailpit's bounded HTTP API. The Mailpit API is loopback-only in host mode; this mode provides local capture, not external delivery.

To use the XSS email exercise with the same local capture service instead of
SharkLasers, add this setting and restart the application:

```bash
XSS_MAIL_PROVIDER=mailpit
```

Open <http://localhost:8025> to inspect captured messages. Mailpit accepts SMTP
on `127.0.0.1:1025`; it does not send mail to external inboxes.

## SecureShop external test email

SecureShop's merchant Inbox has a separate, opt-in external delivery test.
It does not forward lesson mail or give agents permission to send through Gmail.
The existing isolated Inbox, auto-reply lessons and their intentionally vulnerable
behavior remain separate.

Configure the following privately in the repository's `.env`, then restart:

```env
SS_EXTERNAL_MAIL_ENABLED=true
SS_EXTERNAL_MAIL_GMAIL_USER=your-dedicated-test-account@gmail.com
SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD=
```

Fill the last value locally with a dedicated App Password. Never paste it into
chat, commit it, or put it in frontend configuration. These settings do not fall
back to the workshop `GMAIL_*` variables. The feature is disabled by default.
Transport uses Gmail's fixed TLS SMTP endpoint on port 465.

From the merchant Inbox, open **Send external test email**, enter a single
address such as `yourname@sharklasers.com`, and review the exact recipient and
server-generated plaintext message. **Cancel** before sending has no SMTP effect.
Only the explicit send confirmation can submit the message. Arbitrary message
content, attachments, CC/BCC and HTML are not supported.

Use only synthetic test data: disposable inboxes are not private. Open
[SharkLasers](https://www.sharklasers.com/) separately, select the same username
and domain, and check for the message. SMTP acceptance means Gmail accepted
the submission; it does not prove arrival or visual rendering in that inbox.

Dispatch attempts are limited to three per hour per registered principal and
twenty per hour per configured sender. Lab resets do not reset these limits.
Draft preparation is also capped at twenty per hour per principal.
Prepared reviews expire after ten minutes. If sending is interrupted, use the
saved operation's status check. An unknown outcome never automatically resends;
do not assume a timeout means the email was not sent. Cancellation cannot retract
an already dispatched email.

A prepared draft from an earlier login or practice is read-only. After the
server verifies that it expired without being claimed for sending, its status
can be dismissed and a new message prepared explicitly. Dispatched or unknown
operations never become dismissible merely because time has passed.

## Skipping SMTP

If you select Gmail without setting `GMAIL_USER` and `GMAIL_APP_PASSWORD`:

- The Email Agent challenge returns `Gmail SMTP not configured` when a
  student tries to send unless `IPI_EMAIL_PROVIDER=mailpit` is configured with a private HMAC secret.
- The XSS Workshop's **email** tab returns the same error; the other
  three tabs (reflected, stored, LLM-generated) work normally.
- The rest of the platform — CTF, DPI, IPI/RAG, SecureShop v2, SQLi,
  XSS reflected/stored, sensitive-info, excessive agency, supply chain,
  ARIA/NOVA agents — is fully functional with no SMTP.

You can add credentials any time later by editing `.env` and restarting.
