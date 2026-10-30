# Security Policy

## Do not deploy publicly

**OWASP Agentic AI GOAT is deliberately vulnerable.** It exists to teach exploitation and
defense in a safe local environment. It is not hardened for production and
must not be exposed to the public internet.

If you deploy OWASP Agentic AI GOAT on a machine that is reachable from the internet:

- Anyone on the internet can hit the intentionally vulnerable challenge
  routes (SQL injection, XSS, prompt injection, file reads, RCE via the
  DevOps terminal challenge, SSRF via SecureShop, etc.).
- The default credentials in this repo are public knowledge.
- The Event Gate middleware is off by default; even when on, its password
  is a single shared secret.

Run OWASP Agentic AI GOAT on `localhost`, in an isolated VM, or behind a private network
only.

## Teaching credentials and installation credentials

Challenge credentials are synthetic teaching data and are documented with the
relevant exercise. Fresh PostgreSQL setup creates the documented local teaching accounts, including
`admin` / `admin123` and `student` / `student 123` (one literal space). Private
installation state records the administrator credential; upgrades do not reset
existing users. Historical SQLite accounts are not runtime authority. Never reuse any OWASP Agentic AI GOAT credential for a real
system.

## Responsible disclosure — real bugs vs. intentional bugs

OWASP Agentic AI GOAT is full of `@intentional-vulnerability <id>` annotations that mark
teaching sinks. Those are not bugs.

**A "real" bug is one of:**

- A vulnerability in the platform layer (`server/routes/postgresAuth.js`,
  PostgreSQL session/admin middleware, `server/database/postgres/*`, or admin
  routes).
- A vulnerability in the CI/CD or deployment infrastructure.
- A supply-chain issue (dependency, package, action).
- A crash or data-loss bug that breaks the learning experience.
- A vulnerability that lets a challenge cross PostgreSQL store, owner, role,
  session, or reset boundaries, or bypasses the Event Gate.

If you have found one:

1. **Do not open a public issue.**
2. If enabled, use this repository’s GitHub Security → Report a vulnerability.
   Otherwise, contact the maintainer privately using the contact information on:
   <https://github.com/hackerabhinavverma>
3. Include a clear reproduction (URL, payload, expected vs. actual).
4. Give the maintainer a reasonable window to fix before disclosure.

Everything else that looks vulnerable is very likely a teaching sink. Before
reporting, check for an `@intentional-vulnerability` annotation in the
relevant file, and consult
[`secureshop/VULNERABILITIES.md`](secureshop/VULNERABILITIES.md) for the full
catalog.

## Live-event mode

The Event Gate (`server/middleware/eventGate.js`) can gate the entire app
behind a shared password to prevent uninvited traffic during workshops:

```
EVENT_GATE_ENABLED=true
EVENT_GATE_PASSWORD=<shared-with-attendees>
```

This is not a security control — it is a friction gate for live audiences.
