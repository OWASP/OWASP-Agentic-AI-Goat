# Exercise UI authoring template

Use this checklist when adding or modernizing a learner-facing workshop exercise. It applies the two supported workshop experience templates documented in [workshop-experience-baseline-2026-09-10.md](./workshop-experience-baseline-2026-09-10.md). DPI and IPI are the reference consumers. This guide does not define a third template, a page generator, or a new grading path.

## 1. Choose the learning structure

Choose the template from the learner's workflow before building the page.

### Single scenario: one workflow, multiple objectives

Use `single-scenario` when every objective is attempted through one primary workflow. DPI is the reference: it has one chat scenario, multiple server-catalog objectives, and an independently retained conversation for each objective. Objective navigation stays inside the scenario.

```js
import { defineWorkshop } from '../../components/workshop/experience.mjs';

export const exampleExperience = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'canonical_workshop_key',
  template: 'single-scenario',
  scenarios: [{
    id: 'primary-workflow',
    label: 'Learner-facing scenario name',
    workflow: 'chat',
    objectiveSource: 'canonical-catalog',
    resetPolicy: 'reviewed-reset-policy',
    navigation: 'manual',
    capabilities: { chat: true, objectiveHelp: true },
  }],
});
```

### Multiple scenarios: scenario tabs with independent workflows

Use `multi-scenario` when the workshop contains two or more scenarios with independently owned workflow state. IPI is the reference: Document Upload and Email Agent are tabs, and each tab owns its objectives, requests, artifacts, help capabilities, progress, and reset behavior.

A scenario tab is not an objective tab. Objectives remain inside their scenario. Two scenarios may use the same workflow renderer when their state and curriculum boundaries are different.

```js
export const exampleExperience = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'canonical_workshop_key',
  template: 'multi-scenario',
  scenarios: [
    {
      id: 'documents',
      label: 'Documents',
      workflow: 'rag',
      objectiveSource: 'canonical-catalog',
      resetPolicy: 'documents-reset',
      navigation: 'manual',
      capabilities: { upload: true, query: true, objectiveHelp: true },
    },
    {
      id: 'messages',
      label: 'Messages',
      workflow: 'email',
      objectiveSource: 'canonical-catalog',
      resetPolicy: 'messages-reset',
      navigation: 'manual',
      capabilities: { email: true, objectiveHelp: false },
    },
  ],
});
```

Use only the workflows and navigation policies exported by `experience.mjs`. A capability describes available UI behavior; it does not grant visibility, help access, completion, or permission. Render a capability only when the definition declares it and the corresponding backend contract exists. Unsupported cancellation, help, reset, provider, mode, or tool behavior stays absent or explicitly unavailable; never fabricate a working control.

## 2. Keep the three authorities separate

Before implementing the page, record the source of each decision.

| Authority | What it owns |
|---|---|
| Shared workshop experience | Shell, tokens, layout, scenario navigation, action/status primitives, objective presentation, help/reset surfaces and accessible interaction behavior |
| Versioned workshop definition | Stable workshop/scenario IDs, one supported template, workflow, capabilities, navigation policy and reset-policy reference |
| Server catalog/configuration | Exercise and objective visibility, objective order, prerequisites, mode, progress, completion, time, and effective Hint/Solution gates |

Do not put objective totals, completion truth, visibility switches, mode authority, or help permissions into the page definition. Do not use capability flags to bypass a server gate.

## 3. Register curriculum and admin controls

Complete the supported PostgreSQL catalog path before treating the UI as available:

- Add or update the canonical workshop/family curriculum defaults and keep stable objective IDs.
- Maintain `CHALLENGE_TO_WORKSHOP_KEY` when a route key and workshop key differ.
- Use the provenance-aware PostgreSQL seed path and a forward-only migration when schema data must change. Preserve instructor-owned content and learner evidence.
- Project exercise visibility from `catalog_active` plus `is_visible`, and objective availability from `catalog_active` plus `is_enabled`.
- Project Hint and Solution controls independently. Effective access combines the master setting, the per-objective gate, and actual content.
- Verify the admin challenge and solution surfaces show the same effective state that the learner page enforces.
- Provide instructor-authorized editing of objective labels, teaching descriptions, hints and solutions, including initially empty content. Persist edits in canonical PostgreSQL and project them to every learner surface. Use checked-in descriptions only as a fallback when the canonical description is empty.
- Keep objective identity, Judge rubrics and security policies separate from teaching-content edits. Saving content must not enable its visibility gates or imply model qualification.
- Verify populated and second-run seeds preserve instructor edits; verify student readback and permission revocation for the authoring controls.
- Derive learner totals, completions, and time from the canonical repository so the dashboard, challenge list, progress page, and exercise agree.

Render a valid empty state for zero enabled objectives. Never turn `0/0` into a completion celebration.

Keep the student surfaces distinct while preserving their shared facts. Overview (`/workshop-dashboard`) owns the aggregate status and time summary. The exercise library/detail surface (`/workshop/challenges`) owns discovery and exercise cards, with only the slim page-level progress it needs. Do not duplicate the full Overview dashboard in the exercise library. Both surfaces must project the same catalog-derived exercise count, objective total, completion state, and time.

## 4. Treat completion as server authority

A finished request, assistant response, animation, local matcher, or selected objective is not proof of completion. Update completed styling and progress only from the canonical progress returned by the server or from a subsequent authoritative progress read.

- Keep practice participation distinct from scored objective completion.
- Require the family Judge/evidence decision and effect provenance when the objective contract requires them.
- Treat unavailable, inconclusive, unqualified, stale-generation, or owner-mismatched results as no completion.
- Reconcile polling and mutation responses through the same ownership/generation guards. A late response must not update a reset objective, another attendee, or a newly selected scenario.
- Preserve prior evidence when a run fails. Do not clear progress while a refresh is unavailable.
- Use the server-catalog objective order and declared navigation policy. DPI's delayed next-incomplete movement is an explicit policy; IPI keeps manual selection.

## 5. Declare and display mode honestly

Mode is a server-owned exercise contract. Read the effective mode through the existing workshop/config adapter and send only the mode fields expected by the exercise API.

- Keep vulnerable and fixed behavior distinct where the exercise supports both.
- Do not infer mode from a scenario tab, URL label, local button, or response text.
- Do not let a client-only toggle create completion authority or reach a platform capability.
- Keep unknown or degraded provider/mode state honest in the UI. Do not show an unconditional connected or protected state.
- Test each supported mode against the same catalog, ownership, reset, and completion boundaries.
- Every chat scenario in this baseline requires a visible, working vulnerable/fixed control backed by the server. If its backend mode capability is missing, implement and qualify that capability before marking the scenario complete; do not substitute a cosmetic switch or omit the requirement. Non-chat tools may declare an explicit reviewed mode scope. During an unavailable mode read, display an honest unavailable state and prevent ambiguous submission.

## 6. Compose the workspace from shared primitives

Use `SingleScenarioWorkshop` or `MultiScenarioWorkshop` as the outer experience, `ScenarioNavigator` and `ScenarioWorkspace` for multi-scenario navigation, and the shared layout, button, status, objective, chat, help, and reset primitives where they fit. Keep the exercise-specific document, email, comparison, sandbox, victim, or tool view in a reviewed workspace slot.

Do not copy a reference page to obtain its controls. Prefer a small adapter around the existing API and keep domain execution and grading in services.

For ordinary learner and model text, use the safe formatted-chat path. Preserve text/code formatting, long-output containment, copy behavior, and clear user/assistant/tool labels. Do not pass ordinary content to `dangerouslySetInnerHTML`.

An exercise that intentionally teaches XSS or raw-output execution may use an exploit renderer only when all of these are true:

- The renderer is an explicit scenario capability and documented intentional teaching sink.
- It is limited to the exercise's established browser or sandbox isolation boundary.
- The exact source/effect is attributed to the current owner, scenario, objective, and generation.
- Safe chat, help, status, and admin content continue to use inert rendering.
- Fixed mode preserves the lesson contract without removing the vulnerable-mode teaching sink.

Never make unsafe HTML a global message-rendering option, and never globally sanitize away an intentional exercise.

## 7. Define reset scope before adding the button

Name the reset after its real scope and list what it clears and preserves.

| Reset type | Clears | Preserves |
|---|---|---|
| Conversation | Active objective conversation/model memory and declared draft/run state | Completed objectives, workshop time, sibling artifacts |
| Scenario progress | That scenario's objective evidence, summaries, transcript/artifacts described by its policy | Sibling scenarios, other attendees, unrelated exercises, workshop time unless the server owns finer-grained time |
| Lab | Current attendee's complete declared lab scope | Other attendees, account and global curriculum |

Use the shared reset controller for confirmation, durable operation identity where supported, generation invalidation, server mutation, reconciliation, error recovery, focus restoration, and duplicate-click prevention. Clear UI state only after the server acknowledges the reset and canonical state has been reconciled. Switching scenarios is never a reset.

For multi-scenario pages, prove that resetting one scenario preserves every sibling scenario. Also prove that a slow response started before reset or tab switching cannot commit into the new state.

Do not infer reset behavior from the template or reuse one scenario's reset mutation for every tab. DPI conversation reset, DPI progress reset, IPI Document Upload reset, and IPI Email Agent reset deliberately preserve different state. Each scenario must name and verify its own server-backed policy.

## 8. Accessibility and responsive acceptance

- Keep a logical heading and reading order when the workspace/aside stacks.
- Use the shared tab semantics. Arrow keys, Home and End move among enabled scenario tabs; the active tab owns `aria-selected` and its panel relationship.
- Give icon-only actions accessible names. Keep visible labels specific about action and scope.
- Preserve keyboard submission rules: Enter submits, Shift+Enter adds a newline, and IME composition does not submit.
- Use status/alert semantics for asynchronous outcomes, completion, warnings, and errors. Do not rely on color alone.
- Keep controls at least 44px high, visible focus indicators, usable disabled/loading states, and modal focus trap, Escape, and trigger restoration.
- Respect reduced motion and avoid layout movement that hides the composer or active objective.
- Check 375, 768, 1024 and 1440px widths, plus a short mobile viewport. Verify no horizontal overflow and that long prompts, code and tool output remain reachable.

## 9. Focused verification checklist

Run checks in proportion to the change, and keep controlled checks separate from native browser, PostgreSQL, and actual-model qualification.

- [ ] `defineWorkshop` accepts the definition, the correct template cardinality, a supported workflow and navigation policy, `objectiveSource: 'canonical-catalog'`, and a reset policy.
- [ ] The shared component tests cover the adapter states used by the exercise: initializing, ready, submitting/running, failed, completed and resetting.
- [ ] Catalog tests cover active/hidden exercises, enabled/disabled objectives, zero objectives, prerequisite state, and stable objective IDs.
- [ ] All four Hint/Solution combinations are verified independently; unavailable content has no action and cannot be fetched through a stale open surface.
- [ ] Completion styling, counts, time, and next-objective behavior come from authoritative server projections.
- [ ] Owner changes, reset generations, stale mutation responses, polling races, and failed reconciliation cannot overwrite current state.
- [ ] Every reset proves its clear/preserve contract and duplicate confirmation behavior.
- [ ] Multi-scenario exercises prove tab keyboard behavior, state retention on revisit, slow-run isolation, one-scenario reset, live scenario hiding, and correct aggregate progress.
- [ ] Ordinary formatted content stays inert; each intentional exploit renderer has a focused isolation and exact-effect test in both supported modes.
- [ ] Focus, modal restoration, status announcements, reduced motion, contrast, long content, and responsive breakpoints are verified.
- [ ] `node scripts/validate-workshop-experience.mjs` passes.
- [ ] Relevant component/service tests pass. Use `npm run verify:workshop:browser` only when rendered DPI/IPI baseline behavior or shared browser interaction changed.
- [ ] Required disposable PostgreSQL, actual-model, or native-browser qualification is run through its separately owned launcher; controlled fixtures are not reported as that proof.

An exercise is ready when its definition validates, its server catalog and admin gates agree, canonical evidence controls completion, mode and reset scopes are explicit, safe and intentional renderers remain separated, and focused interaction tests demonstrate the promised learner behavior.

The 12 historical model-capability qualifications remain deferred and unverified. Preserve each path’s existing evidence requirements and false-positive credit guards. A deferral records a qualification limitation; consult that path’s documented credit policy rather than treating the deferral list as a universal scoring switch. UI checks cannot promote a deferred qualification.
