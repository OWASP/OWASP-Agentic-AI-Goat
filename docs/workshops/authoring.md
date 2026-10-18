# Workshop experience authoring

New workshop pages use one of two versioned templates from `client/src/components/workshop/experience.mjs`:

- `single-scenario` for one workflow with several objectives, such as Direct Prompt Injection.
- `multi-scenario` for two or more independently owned workflows, such as the Document Upload and Email Agent scenarios in Indirect Prompt Injection.

Start from `singleScenarioFixture` or `multiScenarioFixture` in `client/src/components/workshop/fixtures.mjs`. The rendered state gallery is `WorkshopExperience.gallery.js`. Run the contract check from the repository root:

```bash
node scripts/validate-workshop-experience.mjs
```

A definition declares stable workshop and scenario IDs, a reviewed workflow module, `objectiveSource: 'canonical-catalog'`, a reset policy, and an optional navigation policy. Definitions describe composition only. They do not contain objective totals, visibility, completion, permissions, secrets, remote code, or grading logic. Those values remain owned by the server catalog and database.

Use `SingleScenarioWorkshop` for the single scenario template. Use `MultiScenarioWorkshop`, `ScenarioNavigator`, and one mounted `ScenarioWorkspace` per scenario for the multi scenario template. Scenario navigation is controlled by the page. Switching scenarios must preserve each scenario’s draft, artifacts, output, objective selection, and pending run ownership.

Use `useWorkshopResetController` with `ResetConfirmation` for destructive resets. Name the affected scenario and preserved state in the confirmation. The mutation must complete before `onCommit` clears local state. Disable conflicting mutation controls while resetting, invalidate the scenario’s pending run generation in `onBegin`, and keep sibling scenario state out of `onCommit`. A workshop-wide reset is a separate policy and control.

Use the shared button, status, progress, objective, layout, chat, and tool-result primitives where their contract fits. Keep exercise-specific RAG, email, comparison, victim, and intentionally unsafe lab renderers in reviewed local slots. Do not route intentional raw HTML through a global renderer or sanitizer.

Before adding or changing objectives, follow the repository’s workshop synchronization checklist: update the canonical server objective map, visibility and hint seeds in both initialization paths, progress/time writes, admin toggles, and all three student dashboard parity checks. Never hardcode a total in the template.

Acceptance for a new adapter includes definition validation, empty/loading/error/completed states, all hint/solution gate combinations, keyboard scenario navigation, retained state after scenario switches, scoped reset races, hidden objectives, and production build verification. Check 375, 768, 1024, and 1440 pixel layouts in a real browser before declaring visual or accessibility parity.
