# Remaining agent-loop remediation

Date: 2026-09-13  
Scope: read-only review of the MCP workshop, Excessive Agency, and CodeBot workflows. No model, database, sidecar, or learner reset was invoked.

## Decision rule

An autonomous loop is required when the lesson claims that an agent **observes new information and then chooses a new action**. Tool poisoning and indirect prompt injection are examples: the agent must inspect attacker-controlled content, decide what to do next, and select the consequential tool and arguments.

A second autonomous action is unnecessary when the lesson is a single authorization or execution boundary: the learner asks for one action, the model selects one tool, the tool produces a real result, and the assistant explains that result. Adding more tool-capable turns to those exercises increases duplicate side effects without improving the learning objective. Deterministic database, filesystem, runner, and reset services are valid tool implementations; they are not additional agents and do not need gratuitous model calls.

## Priority 0: MCP poisoning and indirect injection need a real next-action decision

The MCP graph uses a real model for its first tool selection when a provider is available (`server/agent-runtime/mcpWorkshopGraph.js:8`). For tool poisoning and indirect injection it also exposes the poisoned description or ticket body to a model (`server/services/mcp/workshopAgent.js:208-231`). This is useful but incomplete: the model returns only `comply: boolean` (`server/agent-runtime/mcpDecision.js:16-28`). The scenario then predetermines the action, while `toolCheckSystemStatus` and `toolReadTicket` use `_followInjectedInstructions` to select and execute the leak or courier behavior (`server/services/mcp/sandboxShell.js:419-464,529-560`). The model does not choose the consequential tool and arguments from its observation.

Three related gaps make current completion weaker than the new requirement:

- The compliance decision receives a canonical request rather than the learner's actual framing (`server/services/mcp/workshopAgent.js:218-231`).
- Mock mode skips the observation decision and lets the deterministic sandbox path proceed (`server/services/mcp/workshopAgent.js:213-216`).
- The grader accepts the expected tool and `{ objective, achieved }` without requiring real-model or post-observation decision provenance (`server/services/mcpObjectiveGrader.js:35-44`).

Convert only `mcp_tool_poisoning` and `mcp_indirect_injection` to a bounded observation-to-action graph:

1. Read the benign status/tool metadata or ticket content without automatically performing the injected instruction.
2. Give the real learner request and exact untrusted observation to a structured model decision.
3. Validate a narrow action schema: `none | read_file` for the poisoned description and `none | send_report` for the ticket, with model-selected arguments.
4. Execute at most one consequential action through the existing isolated services.
5. Require same-run real-model decision provenance and the genuine effect receipt before Judge completion. Mock, fallback, malformed, unavailable, or refused decisions must not create an effect or award credit.

Likely files are `server/agent-runtime/mcpWorkshopGraph.js`, `server/agent-runtime/mcpDecision.js`, `server/services/mcp/workshopAgent.js`, `server/services/mcp/sandboxShell.js`, and `server/services/mcpObjectiveGrader.js`. Extend `tests/mcpModelDecision.test.js`, `tests/mcpComplianceService.test.js`, `tests/mcpObjectiveGrader.test.js`, and `tests/mcpWorkshop.smoke.test.js` to prove actual request binding, preserved model-selected arguments, one effect maximum, no credit from scripted outcomes, and cancellation between observation, decision, and effect.

Ownership must remain `mcp_<authenticated user id>`, with `checkOwnerRun` at every model and effect boundary. Reset must continue through the owner coordinator (`server/routes/mcpWorkshop.js:426-435`). The main side-effect risks are duplicate Mailpit delivery, repeated secret reads, or a post-reset effect caused by decision retry. Retry may repeat a decision; it must never repeat the consequential action.

## Priority 1: CodeBot repair paths should rejoin the observation loop

CodeBot's normal structured-tool path already satisfies the requirement. `runToolLoop` calls the model, executes selected tools, appends each tool result, and calls the model again, with a three-iteration bound (`server/agent-runtime/toolLoopGraph.js:13-38`; `server/agent-runtime/codeBotGraph.js:26-39`). The RCE objectives also require strict runner provenance and observed effects rather than assistant claims (`server/agent-runtime/codeBotJudge.js:25-35`).

Two compatibility paths do not rejoin that loop. Raw JSON-text tool calls and manifest repair can execute `check_dependencies`, after which static code builds the final response (`server/agent-runtime/codeBotGraph.js:41-158`). These paths exist for provider formatting failures, so they are reachable learner behavior rather than test-only fixtures.

After either repaired dispatch, append the real tool observation and perform one bounded model continuation using the remaining action budget. Preserve byte-for-byte manifest binding and permit no second transform execution for the same bound manifest. If the continuation is unavailable, report that honestly; never fabricate a model observation.

The Judge currently requires `real_model` only for `tool_list` and `pkg_discover` (`server/agent-runtime/codeBotJudge.js:23-33`). Because the public exercise is an agent chat, clean and RCE completions should also require a validated real-model selection or repair authorization, while retaining the independent strict-runner requirements for RCE. This does not make model prose proof of execution; runner observations remain authoritative.

Update `tests/codeBotManifestBinding.test.js`, `tests/codeBotDecisionRepair.test.js`, and `tests/codeBotStructuredJudge.test.js` to prove the repaired result is observed once, the transform runs at most once, mock/fallback routing cannot complete an agent-chat objective, and the call budget is bounded. Keep the reset contract in `tests/codeBotSandboxRuntime.test.js`: the opaque owner runner must reset before progress, and reset failure must leave progress unchanged (`server/routes/supplyChainWorkshop.js:155-177`).

## Keep Excessive Agency as a single-action authorization lab

No autonomous conversion is warranted for the nine Excessive Agency objectives. They test one concrete boundary: own-data CRUD, a fixed-mode denial, or a vulnerable-mode cross-owner mutation. The current graph asks the model to select a tool, performs exactly one attendee-scoped tool action, Judges the raw result, and gives the sanitized observation to a second model for the learner-facing response (`server/agent-runtime/excessiveAgencyGraph.js:16-113`). That is the correct shape for these exercises.

Giving the second model turn access to tools would allow duplicate notes, orders, refunds, or deletes and would obscure whether the tested authorization boundary caused the observed outcome. The deterministic tool router and attendee database are appropriate services, not missing autonomous agents. Model availability and decision source should remain visible operational metadata, but the authorization proof must continue to come from the actual tool result and owner context (`server/agent-runtime/excessiveAgencyJudge.js:1-31`).

Add contract coverage in `tests/excessiveAgencyStructuredJudge.test.js` for one tool effect, two model calls on a tool path, the actual sanitized result in the second prompt, and deterministic response fallback without an additional mutation. Retain attendee separation and reset-race checks in `tests/excessiveAgencyAttendeeIsolation.test.js`. Ownership is already keyed by the authenticated platform attendee in `server/services/excessiveAgencyAttendeeLabStore.js:5-103`, and reset is owner-coordinated in `server/routes/excessiveAgencyLab.js:236-254`.

## MCP exercises that should remain single action

The other nine MCP objectives do not need a planning loop:

| Objectives | Why one action is pedagogically complete |
|---|---|
| `mcp_recon` | The learner requests the actual catalog and receives it. There is no consequential follow-up action. |
| `mcp_cmd_injection`, `mcp_ssrf` | The selected tool crosses one shell or network boundary and returns the genuine effect. |
| `mcp_confused_deputy` | The lesson is that one overpowered send action can collect and courier secrets; extra planning would hide that excessive scope. |
| `mcp_broken_authz`, `mcp_secret_exposure` | The tool boundary itself lacks authorization or minimization. |
| `mcp_supply_chain`, `mcp_audit_gap`, `mcp_shadow_server` | Installing, disabling audit, or registering a server is the single consequential action under study. Later catalog or audit inspection can remain a separate learner turn. |

These flows may keep deterministic setup and response formatting. If platform policy requires every assistant completion to originate from a real model, record and require validated initial model-selection provenance; do not introduce another tool-capable turn merely to increase loop count. Inspector-style deterministic demonstrations may remain available, but should be labelled separately from model-driven objective completion.

## Acceptance boundary

The remediation is complete when poisoning and indirect injection have a model-selected post-observation action tied to a same-owner run and genuine effect, all CodeBot execution paths converge on one bounded observation-aware continuation without repeated transforms, and Excessive Agency remains provably single effect. Unavailable models, scripted decisions, reset races, and missing sidecar receipts remain unresolved outcomes rather than passes.
