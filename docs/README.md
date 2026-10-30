# DVAIA Documentation

**Damn Vulnerable AI Application** is an educational security platform for
learning AI security, web vulnerabilities, and safe LLM application design.
It has a deliberate split architecture: a hardened platform layer (auth,
session management, audit logging) alongside intentionally vulnerable
challenge and workshop content used to teach the OWASP LLM Top 10, OWASP MCP
Top 10, and classic OWASP Web Top 10 attack surfaces.

---

## Getting started

- [Installation guide — all platforms](install/INSTALLATION.md)
- [Quick start (all platforms)](QUICK_START.md)
- [Tracing at smith.langchain.com](install/LANGSMITH.md) — configuration and a walkthrough of agent decisions, model calls, and tool results.

## Project docs

- [Architecture](ARCHITECTURE.md) — how the platform, challenges, databases,
  and AI service layer fit together.
- [Engineering code map](code-map/README.md) — executable wiring, module
  boundaries, file ownership, data relationships, tests, and change impact.
- [Security policy](SECURITY.md) — responsible disclosure, deployment warning,
  and credentials disclaimer.
- [Contributing](CONTRIBUTING.md) — how to contribute without breaking
  intentional vulnerabilities.
- [Repository change instructions](../instructions.md) — minimal-change, TDD,
  documentation, logical-chunk, and adversarial-review requirements.

## Workshops

- [Workshop index](workshops/README.md)
- [95-minute workshop outline](workshops/WORKSHOP_OUTLINE.md)
- [Direct Prompt Injection](workshops/PROMPT_INJECTION.md)
- [Excessive Agency + BOLA](workshops/EXCESSIVE_AGENCY.md)
- [SQL / NoSQL payloads reference](workshops/PAYLOADS_REFERENCE.md)

## SecureShop v2

The flagship end-to-end LLM-driven target that ties LLM, MCP, and Web Top 10
categories together.

- [Overview](secureshop/README.md)
- [Quick start](secureshop/QUICK_START.md)
- [Architecture](secureshop/ARCHITECTURE.md)
- [Vulnerabilities catalog](secureshop/VULNERABILITIES.md) — auto-generated
- [Agent catalog](secureshop/AGENTS.md)
