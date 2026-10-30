# Platform signing configuration

Supported application startup requires PostgreSQL and a private `JWT_SECRET` of
at least 32 bytes. The backend validates it before importing Express, databases,
providers, or feature compositions. Maintenance opt-outs do not bypass this
gate. The canonical PostgreSQL identity adapter repeats the check before it
creates a pool, so direct consumers cannot regain the former public fallback.
The weak session keys inside isolated challenge fixtures remain intentional and
are outside this platform contract.

For a fresh installation, run `npm run setup`. It creates a mode-0600 `.env`
with a randomly generated 48-byte signing key. It refuses to overwrite an
existing `.env`.

For an existing installation with a missing, sample, or inadequate key, use an
operator-controlled maintenance window:

1. Stop the application. Do not rotate the key while any backend can mint or
   accept sessions.
2. Back up the existing private `.env` with mode 0600 according to the normal
   application backup procedure.
3. Generate a replacement into a private file without putting it in shell
   history or terminal output:

   ```bash
   install -d -m 700 "$HOME/.owasp-ai-goat"
   (umask 077; node -e "process.stdout.write(require('node:crypto').randomBytes(48).toString('hex') + '\n')" > "$HOME/.owasp-ai-goat/jwt-secret.new")
   ```

4. In a private editor, replace only the `JWT_SECRET` value in `.env` with the
   file contents. Do not change database URLs or challenge configuration. Run
   `chmod 600 .env`, then remove the temporary key file.
5. With the new private configuration loaded and the backend still stopped,
   revoke the durable records for every token signed by the previous key:

   ```bash
   node scripts/admin/revoke-platform-sessions.js
   ```

6. Start the application normally and sign in again. Rotation deliberately
   invalidates every existing platform session. It does not change users,
   roles, passwords, progress, instructor configuration, learner data, or
   challenge-local credentials.

The application never rotates or rewrites this value automatically. The
revocation command uses the configured PostgreSQL identity runtime role, writes
only the session revocation fields through the existing repository contract,
and reports a count without printing tokens, hashes, database URLs, or keys.
