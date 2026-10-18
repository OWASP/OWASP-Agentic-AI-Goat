# SecureShop v2 — Overview

SecureShop v2 is a deliberately-vulnerable, LLM-driven e-commerce app used by
DVAIA to teach the intersection of OWASP LLM Top 10, OWASP MCP Top 10, and
classic OWASP Web Top 10 attack surfaces. It is intentionally insecure by
design.

**Start here:** [QUICK_START.md](QUICK_START.md) describes supported startup,
the standalone shop accounts and the current learner surfaces.

## Standards and coverage status

Reference editions checked: official [LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), [Agentic Applications Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and the currently published [MCP Top 10](https://owasp.org/projects/mcp-top-10?tab=top10) on 2026-10-11. A category mapping describes teaching intent; it does not prove a working exploit or complete standards coverage. Current execution evidence remains in the [release acceptance checklist](../../tasks/secureshop-workflow-acceptance-2026-10-09.md).

The generated vulnerability map retains historical identifiers, while its MCP metadata follows the current official list: tool poisoning/rug pulls map to MCP03:2025, exposed credentials to MCP01:2025, contextual prompt injection to MCP06:2025, and unverified server identity to MCP07:2025. The legacy `mcp08-ssrf` identifier has no direct current MCP Top 10 category and must not be read as MCP08:2025 (lack of audit and telemetry). Keep stable vulnerability IDs and existing teaching sinks; reconcile category metadata separately. Agentic and updated LLM category coverage still requires an explicit source-to-effect crosswalk and objective-specific evidence. No full Top 10 coverage claim is made.

## What lives where

| Layer               | Path                                       | Role                                                                                          |
|---------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------|
| Frontend (v2)       | `client/src/pages/secureshop/*`            | React storefront at `/secureshop/*`; the `/secureshop/v2/*` alias preserves older bookmarks |
| Backend             | `server/routes/secureshop/*`               | Public catalog, standalone shop authentication, role APIs and launch-bound teaching flows |
| Supervisor loop     | `server/services/secureshop/supervisors/*` | customer / merchant / admin supervisors — run the LLM ⇄ tool dispatch cycle                    |
| Provider ladder     | `server/services/secureshop/providers/*`   | Ollama → Anthropic → OpenAI → Bedrock → mock, with a configured override moved to the front |
| Task agents (17)    | `agent-host/agents/*`                      | One MCP server per task agent. Each exposes 1–5 tools.                                        |
| Agent Host process  | `agent-host/index.js`                      | When SecureShop is enabled, boots 17 MCP servers over SSE on port `8082` by default |
| PostgreSQL stores   | `secureshop`, `secureshop_agents`, `secureshop_review` | Commerce, agent lifecycle and owner-bound review state; legacy SQLite files are fixtures only |
| Vuln map            | `docs/secureshop/VULNERABILITIES.md`       | Auto-generated table of every `@intentional-vulnerability` annotation                          |

## Do-not-fix policy

Every file under the paths above may contain code annotated with
`@intentional-vulnerability <id>`. These annotations mark **deliberate**
teaching sinks. They are NOT bugs.

**Before "fixing" any code in a SecureShop v2 file:**
1. Run `npm run docs:secureshop:vuln-map` and check the vuln map.
2. If the code you're about to edit carries an `@intentional-vulnerability`
   tag, **STOP**. It is meant to be exploitable.
3. If in doubt, run `npm run verify:secureshop:vuln-coverage` — every listed
   vuln id must have both a code annotation and a matching test annotation.
   Removing an intentional vuln will fail that check.

## Running the stack

```bash
# One-time supported installation
npm run setup

# Validated foreground backend + frontend startup
./start_all.sh
# → open http://localhost:3000/secureshop

# Quick health check
npm run verify:secureshop
```

SecureShop has its own sign-in at `/secureshop/login`; workshop credentials do
not authenticate the shop. The launcher does not start Ollama. Start the
configured provider separately before launch when the selected provider is not
already running. With `SS_ENABLE=true`, the backend supervises the Agent Host.

## Testing

### SecureShop renderer builds

Fresh setup builds and verifies the five SecureShop renderer artifacts: ReviewCard,
product description, mail, ticket and search echo. The canonical application
build is `npm --prefix client run build`; setup invokes the five pinned renderer
build scripts individually before runtime readiness. For an immutable-source
ReviewCard qualification build, set `SECURESHOP_REVIEW_RENDERER_OUT_DIR` to an
explicit staging directory before running the `build:review-renderer` script
from `client` with `npm run build:review-renderer`. Set the same directory as
the absolute
`SECURESHOP_REVIEW_RENDERER_ROOT` when starting the backend; the default
composition then loads and verifies that staged manifest and artifact. Relative
runtime roots are rejected, and the manifest continues to bind the renderer to
the current ReviewCard source hash.

```bash
npm run test:secureshop              # all SecureShop v2 tests
npm run test:secureshop:unit         # unit — no server / agent-host boot
npm run test:secureshop:integration  # agent-host boot required
npm run test:secureshop:vuln         # every @intentional-vulnerability proof
npm run test:secureshop:chains       # multi-hop chain scenarios (M6)
npm run test:secureshop:parity       # 6 vulns × 3 providers (M6)
npm run test:secureshop:e2e          # Puppeteer end-to-end flows (M6)
```

## Provider ladder

Set `AI_PROVIDER=<provider>` in `.env` to override the default order:

1. **ollama** — the configured local model, normally `llama3.1:8b`
2. **anthropic** — the configured Anthropic model
3. **openai** — the configured OpenAI model
4. **bedrock** — the configured Bedrock model and region
5. **mock** — deterministic fallback for controlled tests or ungraded execution

An available `AI_PROVIDER` value moves that provider to the front of the same
order. A mock or provider-parity fixture is not evidence of a genuine model run
and cannot earn objective credit where model provenance is required.

## Current evidence limits


The approved local-release scope contains **226 included checks** and **24 deferred,
unverified checks** from the historical 250. The newly deferred checks are V12,
V21, V22, V34, V39, Q05 and Q08, in addition to the previous 17. Q05/Q08's broad
all-lesson coverage claims are unverified; supported authentication, confirmation,
isolation and credit boundaries remain required. Deferred code and teaching content
are retained, but deferred lessons must not be advertised as qualified or earn
unsupported credit. The exact deferred IDs are V12, V14, V15, V16, V19, V21, V22, V23, V24, V25,
V26, V27, V30, V31, V32, V33, V34, V35, V36, V37, V38, V39, Q05 and Q08.
Final current-source local verification passed.
This scoped result does not qualify deferred lessons or clean-machine installation
on every operating system.

The latest exclusions concern order-detail disclosure (V12), sensitive/account
lookup disclosure (V21/V22), pricing false grounding (V34), and poisoned MCP
description adoption (V39). Their exploit/Judge qualification is incomplete or
unreliable with llama3.1:8b. Q05 and Q08 therefore do not establish universal
confirmation coverage or vulnerable/fixed/Judge correctness across every lesson.
Normal storefront/account workflows remain separate from these teaching claims.


The installed Listings evidence includes one genuine `llama3.1:8b`
vulnerable-mode fetch of an owned internal training URL, one durable product
publication and one canonical Judge award for `ss_listing_internal_fetch`. Its
fixed-mode no-effect/no-credit counterpart and full source/build compatibility
remain pending. The result does not prove arbitrary private-address reachability
or overall release readiness; see the [Owned Listings guide](../install/owned-listings.md).

A separate inventory request explicitly said not to change product 129. The
genuine model still called `set_stock` and changed its own synthetic stock from
0 to 20. The dashboard and trace prove the observed effect, but the request did
not earn read-only task or Judge credit and does not prove cross-merchant
access. Fixed-mode ownership fences do not guarantee obedience to a
natural-language no-change request. The retained evidence inventory records
these scopes under `listingsInternalFetchJudgeV86` and `merchantOverviewV86` in
[`tasks/secureshop-cart-browser-2026-10-09.json`](../../tasks/secureshop-cart-browser-2026-10-09.json).

## Related docs

- [`owned-system-diagnostics.md`](owned-system-diagnostics.md) — isolated execution, recovery, configuration and qualification status
- [`../install/INSTALLATION.md`](../install/INSTALLATION.md) — supported installation, accounts and optional service setup
- [`../install/owned-listings.md`](../install/owned-listings.md) — opt-in Listings manager setup and its qualification limits
- [`QUICK_START.md`](QUICK_START.md) — one-page how-to for instructors and students (start here)
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — topology + request-flow diagram
- [`AGENTS.md`](AGENTS.md) — one paragraph per task agent
- [`VULNERABILITIES.md`](VULNERABILITIES.md) — auto-generated vuln table
