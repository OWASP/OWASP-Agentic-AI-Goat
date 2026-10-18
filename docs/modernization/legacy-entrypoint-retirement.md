# Legacy secure-server entrypoint retirement

This is a source-only retirement record. `server/secureServer.js` remains in
the repository so the historical isolated teaching sinks and their tests stay
available as source evidence. It is no longer a runnable application
entrypoint. Its guard runs before any import and rejects both direct execution
and `require()` with `ERR_DVAIA_LEGACY_ENTRYPOINT_RETIRED`.

The supported process is `server/index.js`, launched by `npm run server`,
`npm run dev`, or `npm start` with the PostgreSQL engine selected. This keeps
the current user-facing lessons on their mounted routes, including:

- `/api/workshop/sql` and `/api/workshop/nosql` for ARIA/NOVA;
- `/api/workshop/prompt-injection`, `/api/workshop/rag-injection`,
  `/api/email-agent`, and the FinFlow, XSS, CSRF, MCP, excessive-agency, and
  supply-chain routes;
- `/api/ctf`, `/api/solutions`, `/api/hints`, and the SecureShop v2 routers.

The retired server's classic route pair is deliberately not migrated by this
change. Its historical `/api/challenges/sqli/search`, `/sqli/login`,
`/sqli/extract`, `/xss/comment`, and `/xss/comments` sinks remain in
`server/routes/secureChallenges.js` for source-level teaching tests only. The
modern supported replacements are the PostgreSQL-backed SQL workshop and XSS
workshop routes above. The retired eight-level CTF and caller-supplied
progress endpoints already return their explicit retirement responses in that
historical router; supported CTF progression is `/api/ctf`.

The alternate server's `/api/auth` implementation, `/api/health`,
`/api/security/database-status`, and isolation report are also retired
contracts. Main-server operations use the PostgreSQL-selected `/api/auth` and
`/api/monitoring/health` paths. No compatibility alias or database-status
projection is claimed here.

This disposition does not import or merge `platform_secure.db`,
`sqli_challenge.db`, `xss_challenge.db`, or `ctf_ai_challenge.db`. Any archive
of those files remains source/archive evidence requiring a separately reviewed
mapping. No lossless historical merge, route parity, or asset continuity is
claimed.
