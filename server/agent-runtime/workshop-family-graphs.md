# FinFlow and CodeBot graph entrypoints

| Active entrypoint | Graph execution | Existing behavior retained |
| --- | --- | --- |
| `POST /api/workshop/sensitive-info/chat` → `SensitiveInfoWorkshopAgent.processMessage` | Classification node branches to recon, traversal, SSRF, error, admin, or tool-loop nodes | Exact regex priority, vulnerable/fixed gating, existing interceptor tools and reliable generation summaries |
| FinFlow normal message branch | Model → sequential tools → model, bounded at four rounds, optional summary | Tool DTO fields, 1500-character model context, raw exploited output, objective detection/judge and fallback |
| `POST /api/workshop/supply-chain/chat` | Tool-loop subgraph → text-call fallback → manifest retry → response fallback | Three model rounds, exact parsing/retry order, preserved RCE teaching sink and output, existing objective grading/HTTP DTO |
| FinFlow reset route | Existing owner-exclusive state/persistence lock | Reset waits for same-owner chat and canonical progress writes; other users remain independent |
| CodeBot reset route | Owner runtime cancellation/generation fence, then clear/reseed | Reset prevents later model-proposed tools and waits for existing operations before clearing canonical progress |

Tool implementations in the FinFlow and CodeBot service tool sections are unchanged.
Graph tests inject model/tool results; they do not execute file attacks or external
requests. FinFlow's constructor now supports injected model, tool executor, and
judges for isolated verification. Existing model provider adapters use LangChain.

Limits: FinFlow reset drains its existing lock rather than actively cancelling the
model. CodeBot has same-process fencing; in-flight tool mutations cannot be undone,
and its reset waits for them. Neither family has a durable cross-process run ledger,
checkpoint recovery, side-effect replay, or transactional multi-database reset.
HTTP disconnect cancellation is not yet wired for these two families.
