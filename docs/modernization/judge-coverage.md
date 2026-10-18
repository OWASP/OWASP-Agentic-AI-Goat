# Judge coverage audit

Audit snapshot: September 10, 2026. Source inspection only; no grading code, teaching sink, or user database was changed. This document applies the active goal and decision/observability amendment to the additional requirement that a Judge LLM work for every exercise/objective. Concurrent implementation is active; the findings describe the inspected callsites, not a release qualification result.

## Implementation status — September 11, 2026

All106 canonical workshop objective IDs now resolve to actual grading adapter definitions, verified by `tests/judgeCoverageCatalog.test.js`. Shared judging uses real LangChain/Ollama schema-constrained inference and a LangGraph validation/repair flow. The generic completion APIs reject unjudged client writes. PostgreSQL grading receipts bind outcomes to owner, objective, mode, evidence digest and reset generation; only an accepted completion receipt can publish canonical credit.

**Definition coverage is not end-to-end qualification.** All212 canonical positive/non-pass evidence cases and the separate CTF20 cases have passed local8B qualification across the final family runs and documented corrections. See [the verification record](judge-verification-2026-09-11.md) for versions, evidence boundaries and regression counts. Selected invalid semantic assessments remain unavailable and award no credit; this is not a perfect-accuracy claim. Legacy namespaces are separately audited. Durable recovery from a judge outage after tool execution is being added; the broader PostgreSQL-only release goal remains incomplete.

The remainder below is the preserved initial audit, useful for tracing why the implementation changed. Its callsite descriptions are historical and must not be used as the current release status.

## Original audit findings (before implementation)

At the time of the original audit, there was no universal objective judge. The canonical workshop catalog has **106 objective IDs in 10 families**. Only DPI, part of document RAG, and Sensitive Information contain explicit outcome-judge helpers. Even those helpers frequently bypass the model. SQL/NOSQL, XSS, CSRF, MCP, Excessive Agency, Supply Chain and email objectives use deterministic detection, browser/client reports, or action completion. CTF has an LLM defense filter, which is a different responsibility from grading. SecureShop v2 and legacy challenge experiences sit outside the 106-objective catalog.

A graph node named `judge`, a model-generated answer, or a successful deterministic exploit test does not prove model judging coverage. Completion should require an objective-specific, versioned judge verdict tied to an observed attempt, with deterministic evidence requirements retained. Existing vulnerable tools must continue to accept the same teaching payloads; grading changes belong at the trusted completion boundary.

## Canonical coverage inventory

The counts and IDs below come from `server/config/workshopCatalog.js`, not UI totals. Production totals must still intersect this catalog with enabled PostgreSQL objective rows.

| Family | Objectives | Current grading trigger | Actual Judge LLM coverage | Persistence / reset boundary |
|---|---:|---|---|---|
| `direct_prompt_injection` | 8 | Practice interaction validation; active-objective detectors; conditional `judgeAttack` | Partial. Practice and detector hits skip judge; judge itself has regex/length fast paths and an override allowlist | `promptInjectionWorkshop` route → dedicated progress service; route owner coordinator checks before persistence. Legacy SQLite progress service still exists |
| `indirect_prompt_injection` — document | 5 | Upload/document selection, answer length, filename/content tests; detection/bypass heuristics; synthetic teaching responses | Only ambiguous refusal/detection in `judgeInjectionDetection`; other document objectives do not invoke a judge | RAG local progress then canonical sync; owner checks in graph; reset is a separate owner workflow |
| `indirect_prompt_injection` — email | 5 | Inbox setup, send/retrieve actions, injection/defense outcome checks through email graph | No separate universal judge | Numeric email objective maps to canonical `email_*` ID; identity email store then canonical sync |
| `xss_workshop` | 12 | Client `/progress/complete` reports, tool actions, sent attack email | No judge at completion boundary | Native XSS store then canonical sync, some callback/fire-and-forget paths. Root is actively adding owner coordination |
| `csrf_workshop` | 12 | Server victim-state changes, vector/defense outcome, ordered prerequisites; inbox/KB actions; frontend completion endpoint | No general judge | Dedicated native PG store + canonical progress, shared owner coordinator and victim flush. Partial tab reset increments canonical generation |
| `mcp_workshop` | 11 | Observed tool outcome/technique IDs; frontend may credit recon only | No general judge | Native PG progress/log then canonical sync; same owner coordinator for chat/reset |
| `excessive_agency` | 9 | Tool/result + current mode, own/cross-user action and blocked/allowed effects | No general judge | Native progress tracker plus `objective_<n>` canonical writes; process-local workflow fence |
| `sensitive_info_disclosure` | 18 | Regex/tool-result detectors plus `judgeObjectives`, separate recon judge; explicit admin/pre-intercept branches | Partial. Normal vulnerable path unions judge IDs with deterministic IDs; fixed path skips judging; some specialized paths remain deterministic | Native state/local result plus route canonical writes; must retain mode policy and reconcile local/canonical failures |
| `supply_chain_rce` | 6 | Tool name/params/result/response detector after CodeBot graph | No judge | SQLite `sc_progress` completion then canonical sync; owner coordinator checks before each completion |
| `sql_injection_workshop` | 10 | Actual SQL errors/results plus attack-pattern detector on chat; frontend completion endpoint | No objective judge, even though ARIA model now chooses actions | Canonical writes from graph `onResult` callback with run checks; frontend completion bypasses that run boundary |
| `nosql_injection_workshop` | 10 | Operator/error/result detector on chat; frontend completion endpoint | No objective judge; NOVA operator behavior is an intentional simulation | Same canonical/run pattern as ARIA, with frontend completion bypass |

### Exact IDs

- **xss_workshop (12):** `xss_r1`, `xss_r2`, `xss_r3`, `xss_s1`, `xss_s2`, `xss_s3`, `xss_g1`, `xss_g2`, `xss_g3`, `xss_e1`, `xss_e2`, `xss_e3`.

- **csrf_workshop (12):** `csrf_g1`, `csrf_g2`, `csrf_g3`, `csrf_p1`, `csrf_p2`, `csrf_p3`, `csrf_x1`, `csrf_x2`, `csrf_x3`, `csrf_i1`, `csrf_i2`, `csrf_i3`.

- **direct_prompt_injection (8):** `interact`, `system_prompt`, `jailbreak`, `multi_language`, `virtualization`, `role_playing`, `side_stepping`, `obfuscation`.

- **indirect_prompt_injection (10):** `rag_upload`, `rag_clean_doc`, `rag_query`, `rag_injected_doc`, `rag_query_injection`, `email_create_inbox`, `email_send_attack`, `email_retrieve`, `email_trigger_injection`, `email_understand_defense`.

- **mcp_workshop (11):** `mcp_recon`, `mcp_cmd_injection`, `mcp_ssrf`, `mcp_tool_poisoning`, `mcp_indirect_injection`, `mcp_confused_deputy`, `mcp_broken_authz`, `mcp_secret_exposure`, `mcp_supply_chain`, `mcp_audit_gap`, `mcp_shadow_server`.

- **excessive_agency (9):** `objective_1`, `objective_2`, `objective_3`, `objective_4`, `objective_5`, `objective_6`, `objective_7`, `objective_8`, `objective_9`.

- **sensitive_info_disclosure (18):** `tool_enum`, `llm_identify`, `tool_version`, `traversal_secrets`, `traversal_passwd`, `traversal_llm`, `ssrf_oob`, `ssrf_internal`, `ssrf_ollama`, `error_leak`, `admin_enum`, `admin_backup`, `admin_dl_backup`, `admin_read_logs`, `admin_llm_logs`, `admin_modify_logs`, `admin_secrets`, `admin_dirlist`.

- **supply_chain_rce (6):** `tool_list`, `pkg_discover`, `clean_request`, `rce_env`, `rce_ssh`, `rce_cmd`.

- **sql_injection_workshop (10):** `sqli_1`, `sqli_2`, `sqli_3`, `sqli_4`, `sqli_5`, `sqli_6`, `sqli_7`, `sqli_8`, `sqli_9`, `sqli_10`.

- **nosql_injection_workshop (10):** `nosqli_1`, `nosqli_2`, `nosqli_3`, `nosqli_4`, `nosqli_5`, `nosqli_6`, `nosqli_7`, `nosqli_8`, `nosqli_9`, `nosqli_10`.

## Other exercise namespaces

- **CTF:** ten stages, separate stage/participant/attempt progression and success criteria, intentionally absent from `WORKSHOP_OBJECTIVES`. `ctfDefenseLayers.metaLLMJudge` decides whether a response leaks a protected secret and participates in defense filtering. The CTF route scores the response actually delivered after defenses. A universal objective judge must use a namespace such as `ctf/stage/<id>` and preserve post-defense secret evidence and adaptive stage state; do not replace the defense judge with the grading judge or count CTF in canonical workshop totals accidentally.
- **SecureShop v2:** its 17 task-agent teaching surfaces and `@intentional-vulnerability` map have code/test proofs rather than catalog objective rows. The versioned vulnerability map and curriculum must supply the authoritative exercise identity before promising all-exercise judge coverage. Coverage by one of the 106 workshops cannot stand in for these independent exercises.
- **Legacy challenges:** `challenges.js`, old SQLi/XSS/SecureShop and related platform demos use their own routes/state. They require an explicit disposition in the new registry: retained exercise with a rubric, or documented legacy experience outside current grading. No blanket “every exercise” completion claim is justified until these namespaces are enumerated.

## Concrete findings

### 1. Completion APIs can bypass every future judge unless centralized

`server/routes/postgresWorkshop.js` `/objective/complete` writes any recognized enabled workshop objective for the authenticated attendee, rejecting only DPI. `workshopProgressIntegrityHandlers.completeObjective` retains the corresponding legacy path. SQL and NoSQL `/progress/complete` validate membership but credit directly without execution evidence or judge. XSS `/progress/complete` only requires a nonempty objective ID before native completion; canonical validation can subsequently reject an unknown ID while native storage already accepted it. CSRF permits a known visible objective after its prerequisite, without requiring the actual corresponding attack event in that request. Document RAG `/progress/complete`, email objective completion, and Excessive Agency `/progress/complete` likewise accept a selected valid ID/number and persist it without a judge; owner serialization alone does not validate evidence. MCP correctly restricts direct completion to recon, but recon still has no judge.

These are grading-boundary issues, not reasons to sanitize intentional exploit inputs. A new judge inside chat alone leaves all these bypasses open. Convert completion endpoints into evidence submission/grade requests (or retire them), and make the canonical writer require an accepted grade attempt ID. Browser XSS “event fired” reports need a session/scenario-bound event receipt; a model reading a claimed event cannot prove browser execution.

### 2. DPI's “judge” path is narrower than its name

`server/agent-runtime/dpiGraph.js:63` credits detector hits before reaching the judge. `server/services/promptInjectionWorkshop.js:622` refuses to judge detector misses except for `JUDGE_MAY_OVERRIDE_DETECTOR`, then returns true from keyword or length fast paths before the provider call. Thus many successful attempts never reach a Judge LLM. This is incompatible with universal judging, although deterministic evidence remains useful as a prerequisite and diagnostic.

### 3. Document RAG can award synthetic outcomes

`server/agent-runtime/ragQueryGraph.js` synthesizes a secure detection/refusal or vulnerable bypass response when poisoning is retrieved but the real model produces a different outcome. It then completes `rag_injected_doc` / `rag_query_injection`. This is an intentional teaching simulation currently embedded in grading. A judge of the synthesized response would validate the simulation, not the real model's behavior. Record both raw observed model outcome and presentation source, and keep simulation qualification visibly distinct from live model qualification. Preserve the teaching experience while changing which evidence earns a live benchmark grade.

`judgeInjectionDetection` in `server/routes/ragInjection.js` has regex fast paths and falls back to `detectInjectionSuccess` on judge error. Judge failure is therefore not uniformly an unavailable verdict. Its prompt criteria require detection **and refusal**, while some positive regexes merely mention injection. A structured rubric must separate “recognized suspicious content” from “refused to follow it.”

### 4. Judge input/output contracts are too weak for a trusted grader

DPI accepts any response beginning `SUCCESS`; RAG accepts any response beginning `YES`. Sensitive Information extracts the first bracketed array and accepts catalog IDs without an evidence reference per ID. These outputs have no schema version, attempt ID, mode, objective version, provenance, or unavailable/error outcome. Student payloads and tool text are interpolated into judge instructions, so a malicious payload can also attack the evaluator. The judge should receive bounded, explicitly labeled untrusted evidence and emit strict structured data. Deterministic resource/action receipts must remain authoritative; an injected verdict cannot fabricate a transfer, disclosure, or shell effect.

Sensitive Information truncates tool results to 300 characters and final response to 600, which can omit decisive success or refusal evidence. `judgeObjectives` calls `(tc.result || '').substring(...)`; a non-string result throws and the catch silently returns `[]`. Enforce a typed evidence envelope, not ad hoc string truncation. Its vulnerable-only completion policy is intentional and should become an explicit rubric mode condition, while the judge can still report a blocked/fixed outcome without awarding an exploit objective.

### 5. Canonical generation exists but grading does not consistently bind to it

`workshopProgressRepository.syncObjectiveComplete` accepts `expectedGeneration`, and reset increments `workshop_platform.user_state.generation`. The standard `syncObjectiveComplete` callsites omit that sixth argument. A long Judge LLM call must capture generation **before** inference and pass it to the transactional completion check afterward. Pre/post runtime checks help, but a check followed by a separate DB write is not an atomic generation check. Runtime `family:owner` generation and canonical per-workshop generation are separate authorities; they need an explicit bridge, including per-tab/scenario reset semantics.

Process-local CSRF/MCP coordination now drains active owner work, and ARIA/NOVA have durable graph fencing. That does not prove cross-process safety for every family or every direct completion endpoint. A second process, another reset route, or a legacy caller can still write without the expected canonical generation. Test paused judges against same-owner full reset, partial scenario reset and another process's completion.

### 6. Native and canonical commits can diverge

MCP/CSRF/email/Supply Chain and XSS write native progress before canonical completion. Separate challenge databases cannot commit this atomically. XSS callback paths catch canonical failures and return success; Supply Chain's native `completeObjective` returns false for already-completed rows, so a retry after a failed canonical sync can skip the missing canonical write. That leaves dashboard totals inconsistent despite a successful native grade.

Use a durable grade/evidence receipt and retryable idempotent canonical projection, or make canonical grade state authoritative and native progress a projection. A retry must reconcile an already-recorded native success, not conclude there is nothing to do. Never rerun an external effect merely to recover its grade.

### 7. Rubric identity and availability are not durable

There is no one-to-one registry of all 106 IDs to a judge rubric and evidence schema. Existing helper strings, detector maps and label catalogs can drift independently. Current source tests explicitly prove skipped judges and fixture detectors; they do not prove real 8B judge coverage for every objective. Existing successful PG/exploit suites remain valuable storage/teaching tests, but cannot be cited as universal Judge LLM qualification.

## Recommended integration contract

1. Add a versioned rubric registry keyed by `(exerciseNamespace, workshopKey, scenarioId, objectiveId, rubricVersion)`. Use canonical IDs verbatim. Every enabled catalog row must resolve to exactly one rubric; unknown/stale IDs must fail before native or canonical mutation. Keep CTF/SecureShop namespaces separate from dashboard totals.
2. Capture an immutable attempt envelope: authenticated owner, run/scenario ID, canonical generation, mode, objective/rubric version, model/provider, allowed evidence types and source (`live_model`, `deterministic_action`, `browser_receipt`, `teaching_simulation`). Agent action selection and Judge LLM evaluation are separate invocations.
3. Add actual LangGraph nodes `collect_evidence → validate_evidence → judge_model → validate_verdict → optional_bounded_repair → commit_grade`. Every submitted objective invokes the configured Judge LLM, including setup/blocked objectives; simple objectives use small rubrics and concrete action receipts. No provider outage, malformed output or exhausted repair becomes a silent pass. Return `unavailable`/`invalid`/`pending` separately from `fail`.
4. Verdict schema: exact objective/attempt/rubric IDs, `pass|fail|insufficient_evidence`, bounded learner-facing explanation, evidence references, and mode. Do not request hidden chain-of-thought. Validate membership, references and required ground truth after the model response. The model cannot approve an ID outside the requested attempt or override owner/mode/generation.
5. Commit with a transaction that locks the canonical owner/workshop state, compares expected generation and current visibility, inserts an idempotent grade receipt and completion, and bumps the revision. Include a unique attempt/rubric key. Keep grading and external-effect idempotency distinct. Regrade must never repeat an action.
6. Persist owner-scoped judge start/end/error events, provider/model, rubric version, duration, measured usage and verdict summary. Store bounded evidence references rather than arbitrary prompts, provider secrets or hidden reasoning. Retention of trace content must not erase effect replay tombstones or the minimal audit receipt needed to explain a grade.
7. Update each completion caller listed above to submit an evidence envelope. Preserve vulnerable sinks unchanged. Explicitly label intentional simulations and distinguish pedagogical completion from live-model benchmark success.

## Required verification before universal-coverage claims

- Enumerate all enabled objective rows and assert exact rubric coverage, unique IDs and all namespace dispositions. Exercise objective rename/removal, disabled visibility, challenge-key remap, per-objective hints/solutions independence, and all three dashboard counts.
- For every rubric: positive, negative, insufficient evidence, wrong-mode, prompt-injected evidence, unknown ID, malformed verdict, timeout and provider-unavailable fixtures. Confirm no direct completion endpoint bypasses grading.
- Run actual Ollama `llama3.1:8b` judgments across every objective's evidence fixtures; record model identity, rubric version, decision, measured usage and latency. Include attack outcomes and benign near-misses. Report observed false positives/negatives; no fixture verdict may be labeled a live-model judgment.
- Pause inference and reset the same owner/scenario; release the judge and assert no late completion or response. Repeat across processes, with partial reset and config changes. Ensure a different attendee remains unaffected.
- Inject failure between native evidence persistence and canonical grading; retry the attempt and verify reconciliation without repeating its side effect. Crash after uncertain external effects and ensure grading reads receipts rather than replaying tools.
- Saturate judge/model leases while checking authentication, reset and dashboard/control traffic remain responsive. Include bounded queue cancellation and explicit unavailable outcomes; report 200-attendee application capacity separately from 8B model throughput.

## Immediate migration order

Close the generic/direct completion bypasses through one grade boundary first. Add the shared rubric/evidence/verdict contract and durable generation-aware grade receipt. Integrate ARIA/NOVA as the first already-instrumented graph pair, then DPI and document/email IPI, then native XSS/CSRF/MCP, then remaining families. Add CTF/SecureShop namespace rubrics before claiming “every exercise.” Keep the current PG/native migration verification separate from judge qualification.
