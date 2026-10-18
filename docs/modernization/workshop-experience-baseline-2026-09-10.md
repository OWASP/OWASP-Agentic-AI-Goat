# Workshop experience baseline v1

Status: baseline v1 implemented. The shared contracts and components live in `client/src/components/workshop/`; `client/src/pages/challenges/DirectPromptInjectionChallenge.js` (DPI) and `IndirectPromptInjectionChallenge.js` (IPI) are the reference consumers. This intentionally refines the earlier absolute UI freeze: preserve the DPI/IPI visual identity and educational behavior, while standardizing inconsistent workshop controls/layouts/workflows. AWS/deployment changes remain excluded.

The user explicitly confirmed TWO baseline templates:

- **Single-scenario / multiple objectives (DPI baseline):** one scenario, one primary workflow type, multiple objectives; retain DPI's per-objective conversation state.
- **Multiple scenarios / scenario-specific workflows (IPI baseline):** a workshop contains several scenarios such as RAG and Email Agent. Each scenario owns its workflow, objective set, input/artifact state, execution state, help capabilities and reset policy.

The two templates share a design system and common controls. They do not share one forced workflow. A scenario is not an objective and need not correspond to a unique tool type: two scenarios may both use chat but have different content and execution rules. Navigation between scenarios is separate from navigation between objectives. Prerequisite-driven progression is an explicit curriculum capability, not a layout side effect.

## Evidence and design direction

The initial design direction came from source inspection. The implemented production bundle is now also qualified in headless Chrome by `npm run verify:workshop:browser`. That local fixture injects deterministic API responses and captures DPI/IPI full-page screenshots at 375, 768, 1024 and 1440 pixels plus readable viewport-height captures at 375 pixels. It waits for finite entry animations, verifies no horizontal overflow or browser runtime errors, keyboard scenario navigation, reset-dialog focus and focus restoration, scenario state isolation during a delayed response, and DPI objective transcript ownership. Its contrast check resolves alpha through the element's background chain, requires an opaque active-tab surface and unit ancestor opacity, and currently measures the rendered `#3347b0` text on `#ffffff` at 7.87:1. The qualification does not exercise a live backend, database, model, real email provider, screen reader, or cross-browser rendering; those remain separate release checks.

DPI and IPI share an indigo-to-purple gradient, light surfaces, rounded panels, objective states, motion and the outer `VulnerabilityTemplate`. DPI retains its chat-first 2:1 workspace/objective layout; IPI retains its RAG/email tabs and 1:1 work areas. Both collapse their main columns at 1024px; IPI comparisons also use 900px, the outer shell uses 1200px and global mobile rules use 768px. Preserve/test these contexts rather than flattening every breakpoint into one value. Different exercise types need distinct work areas within the same recognizable shell.

DPI already distinguishes resetting the active conversation from resetting progress (`:1030`, `:1042`). IPI resets RAG and email progress through different endpoints (`:1806`, `:2336`). DPI uses `ObjectiveHelpModal`; IPI RAG imports `HintPanel` and has its own solution presentation. IPI Email currently has no objective hint/solution controls, so its adapter must not invent help content or expose unavailable actions. These are candidates for shared behavior, not reasons to copy whole pages into future exercises.

The visual signature is the existing purple agent workspace paired with a clear objective/progress panel. No unrelated theme, new font family or generic dashboard redesign is introduced.

## Token system

The versioned workshop theme contract is defined in `client/src/components/workshop/experience.mjs` and consumed by shared components. Reference values below are extracted from the reference pages; status roles normalize existing variants. Browser qualification measures the active scenario-tab text contrast, while broader contrast and assistive-technology audits remain release work.

| Token/role | Baseline value | Use |
|---|---|---|
| Brand start/end | `#667eea` / `#764ba2` | Header and primary-action gradient, selected objective accent |
| Surface / subtle surface | `#ffffff` / `#f8f9fa` | Panels, workspace background |
| Text / secondary text | `#333333` / `#555555` | Main content and descriptions |
| Border / control border | `#e9ecef` / `#e2e8f0` | Cards and inputs |
| Completed | `#22c55e` with `#f0fdf4` surface | Completed indicator plus icon/text; never green alone |
| Warning | `#ffc107` with dark text | Teaching warning/attention, not a generic error |
| Destructive | `#dc3545` / `#c82333` | Confirmed destructive actions |
| Body / code | Existing Inter/system stack / Fira Code/monospace stack | Reuse `client/src/index.css`; no extra font downloads |
| Card / control radius | 16px / 8px | Panels and ordinary controls; use named tokens |
| Spacing | 4, 8, 12, 16, 24, 32px | Proposed normalized scale based on existing rem spacing |
| Main collapse breakpoint | 1024px | Workspace/objective layout stacks |
| Motion | Short existing hover/state transitions; reduced-motion override | Avoid layout jumps and perpetual decorative motion |

Separate brand colors from accessible action/text tokens. If the existing gradient/white-label combination fails required contrast, adjust the action variant within the purple family and document the small visual change; do not propagate a known contrast failure merely because it exists in a reference page. Define focus, disabled, loading, selected, success, warning and error tokens centrally. New exercises must not define arbitrary button colors or duplicate typography declarations.

## Shared layout and components

```text
WorkshopShell
  Existing navigation / breadcrumb
  ExerciseHeader: title, scenario summary, mode, honest provider status
  ScenarioNavigator (multi-scenario baseline only)
  WorkspaceLayout
    Main: active objective context + exercise-specific workspace
    Aside: objective list + progress + independent help actions
  Scoped reset action in a consistent, documented position
  Shared dialogs / status feedback
```

On desktop, default to DPI's main/aside relationship; retain IPI's comparison/RAG/email layouts inside the main area. On smaller screens, stack in a consistent reading order with an accessible objective selector and reachable composer. Avoid hard-coded chat heights that hide the composer on short/mobile viewports. Compare against both reference pages before accepting the shell.

Implemented core modules under `client/src/components/workshop/` provide the template shells, scenario navigation/workspaces, layout, buttons, objective/progress, chat/status, help, reset controller and versioned definitions. The remaining names below describe the supported extension surface rather than requiring one file per name:

- `WorkshopShell`, `ExerciseHeader`, `ScenarioNavigator`, `SingleScenarioWorkshop`, `MultiScenarioWorkshop`, `ScenarioWorkspace`, `WorkspaceLayout`.
- `ObjectiveList`, `ObjectiveCard`, `ExerciseProgress`.
- `WorkshopButton`, `ActionGroup`, `StatusNotice`, `EmptyState`.
- `ChatPanel`, `MessageList`, `MessageBubble`, `ChatComposer`, `ToolResultPanel`.
- Shared objective-help surface composed from existing `ObjectiveHelpModal`/`HintPanel`, with independent Hint and Solution presentation.
- `ResetMenu`/`ResetConfirmation` and one reset-controller hook.
- Slots for RAG upload/retrieval, email composition/inbox, output comparison, query tools, sandbox/victim views and future exercise-specific evidence.

Use composition and a small explicit variant set, not one component with dozens of boolean props. CTF level progression and SecureShop storefront/admin layouts are specialized products; shared workshop primitives can be reused where appropriate, but this baseline does not authorize redesigning those entire products into the DPI page.

## Standard learning workflow

Every exercise exposes a consistent sequence of activities:

1. **Understand:** read scenario, objective and current mode/status.
2. **Prepare:** load documents, select a target or set up input when the exercise requires it.
3. **Try:** send a prompt, execute a tool or trigger the designated interaction.
4. **Observe:** inspect response, tool effects and evidence.
5. **Learn:** open independently gated hints/solutions and retry.
6. **Continue:** select the next available objective or reset the intended scope.

This is the interaction model, not six mandatory new screens. Preserve familiar inline layouts. Workshop → scenario → objective is the canonical hierarchy. Objective order comes from the canonical curriculum; available/locked/completed state comes from the server. Default navigation lets learners revisit enabled objectives without losing their transcript. Preserve DPI's current delayed next-incomplete-objective navigation (approximately two seconds) as an explicit policy; preserve IPI's manual selection behavior. Future exercises declare a navigation policy. Do not let background reconciliation unexpectedly switch objectives; an unavailable selection is reconciled deliberately.

Represent runtime states explicitly: initializing, ready, submitting, running, completed, failed, cancelling and resetting. Only show cancellation when the backend supports it. An objective completion is separate from a finished chat turn: a response can finish without solving the objective. Busy/error transitions must not clear prior evidence or progress.

## Chat and action contract

Keep DPI's familiar user/assistant presentation, purple chat header and multiline composer. Standardize:

- Enter sends; Shift+Enter inserts a newline; IME composition must not submit accidentally.
- One in-flight mutating run per conversation; prevent duplicate submits and retain draft on failure.
- Clear labels for user, assistant and tool messages. Preserve code formatting, copy controls and appropriate long-output containment.
- Honest provider state: do not display an unconditional green “connected” indicator when status is unknown or degraded.
- Autoscroll follows new output only while the learner is near the bottom; preserve scroll when reading older content.
- Cancel/run status tied to actual server state; aborted or stale responses cannot append to a new objective/reset generation.
- Preserve HTTP/SSE field/event compatibility through adapters. Do not force the frontend to consume raw LangGraph state.
- Ordinary chat rendering uses the safe shared renderer. Intentional XSS/raw-output lessons require a clearly declared lab rendering slot in the appropriate isolation boundary; never globally sanitize away an exercise or globally allow unsafe HTML.

Actions use stable variants: primary for the main action, secondary for navigation/utilities, tertiary for copy/help where appropriate, danger for destructive confirmation. Consistent icon placement, sizes, hit targets, focus rings and disabled/loading behavior are mandatory. Labels state scope and action; avoid a generic “Reset” when it could erase different data.

## Reset contract

| Control | Intended scope | Must preserve | Confirmation |
|---|---|---|---|
| Reset conversation | Active objective's conversation/model memory and pending draft/run | Completed objectives, workshop time and scenario artifacts | Lightweight unless the user would lose meaningful unsaved input |
| Reset exercise progress | Named exercise/tab objective evidence and derived summaries; transcript behavior explicitly declared | Other tabs/exercises/attendees; unrelated scenario state | Required, with exact affected scope |
| Reset lab | Current attendee's complete scenario, transcript, checkpoints and progress | Other attendees, global curriculum and account | Required; shown only where the backend implements it |

The current DPI progress reset also resets conversation state. Preserve that declared behavior in its adapter; do not silently apply the same side effects to every exercise. IPI RAG progress reset clears its loaded document/session/query/results; IPI Email reset clears pipeline outputs while retaining temporary email, selected scenario and custom payload. These current differences must be encoded, not erased by a shared reset handler.

For the multi-scenario baseline, the normal destructive action is “Reset this scenario,” with a confirmation naming the scenario and affected state. It must not reset sibling scenarios. A workshop-wide reset is a separate explicit action only where implemented. Switching scenarios is never itself a reset. Preserve draft and last confirmed state; an in-flight scenario can continue or be cancelled according to its declared policy, but must never write into the newly active scenario. For partial resets, preserve workshop-level time unless the server records trustworthy per-exercise time. For a full lab reset, clear only that lab's time according to the documented policy. Never invent per-tab time subtraction from a workshop-only total.

One reset controller owns confirmation, cancellation, reset generation, server mutation and canonical reconciliation. Do not show success or clear a UI optimistically before the reset is durably acknowledged. Reset errors retain last confirmed state and provide retry. Disable conflicting submit/reset actions while reset owns the workspace. Test slow responses arriving after reset, cross-tab updates and repeated confirmation clicks.

## Configuration and authoring contract

Split configuration into three authorities:

| Authority | Owns | Must not own |
|---|---|---|
| Shared versioned theme/component library | Colors, type, spacing, variants, behavior primitives | Exercise content, completion totals, permissions |
| Typed workshop/scenario definitions | Stable workshop/scenario keys, one of two baseline templates, content references, workflow slots, capabilities, reset policy references | Secrets, arbitrary executable configuration, authoritative completion/visibility |
| Server database/config API | Enabled objectives, progress/time, prerequisites, mode, owner identity, hint/solution gates | Duplicated per-page hardcoded totals |

The implemented `defineWorkshop` authoring API follows this shape:

```ts
// Baseline A: one scenario, one primary workflow, multiple objectives.
defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'direct_prompt_injection',
  template: 'single-scenario',
  scenarios: [{
    id: 'direct-chat',
    workflow: 'chat',
    objectiveSource: 'canonical-catalog',
    workspace: directPromptInjectionWorkspace,
    resetPolicy: 'dpi',
    navigation: 'next-incomplete-after-completion',
  }],
});

// Baseline B: multiple scenarios, independently composed workflows/objectives.
defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'indirect_prompt_injection',
  template: 'multi-scenario',
  scenarios: [
    { id: 'rag', workflow: 'rag', objectiveSource: 'canonical-catalog',
      workspace: ragWorkspace, resetPolicy: 'ipi-rag' },
    { id: 'email', workflow: 'email', objectiveSource: 'canonical-catalog',
      workspace: emailWorkspace, resetPolicy: 'ipi-email' },
  ],
});
```

Here `workspace` is a reviewed code module reference, not code loaded from remote JSON. Help capability flags do not override effective server gates. There are exactly two baseline templates: `single-scenario` and `multi-scenario`. Workflow renderers inside a scenario initially cover `chat`, `rag`, `email`, `comparison` and `tool-workspace`; these are scenario capabilities, not five competing page templates. Validate that single-scenario definitions contain exactly one scenario and multi-scenario definitions contain multiple scenarios. Do not build a general no-code page builder.

Future exercise authors choose one of the two templates and provide scenario definitions, content/tool adapters and canonical objective registration. A multi-scenario workshop can reuse the same renderer for multiple scenarios. Keep stable existing objective IDs through migration and add an explicit server-side mapping for scenario membership; do not rewrite IDs just for visual grouping.

State keys and authorization include attendee + workshop + scenario + objective/conversation where appropriate. Persist scenario ownership independently of selected UI tab. Read per-scenario progress and workshop aggregates from the same server catalog, counting each enabled objective once. Distinguish practice participation from scored objective completion: DPI currently has one practice objective and seven graded objectives; preserve that distinction without hardcoding 7 in the template. Hidden scenarios/objectives are excluded according to the canonical visibility contract; an empty set renders 0/0 without a false completion celebration. Mode scopes are declared and server-owned rather than inferred from the active scenario. The local validator in `scripts/validate-workshop-experience.mjs` verifies registered definitions and fixtures; automatic page generation is not implemented. Database migrations/seeds and the existing admin sync rules remain required. New exercises may not copy a 1,000-line workshop page or define independent chat/reset implementations.

Version theme/experience contracts, keep a component gallery with all states, and document extension rules. Treat configuration and shared component changes like APIs: review impact on every consumer. Layout selection is configured; lab execution and grading stay in domain services.

## Delivery and acceptance

| Ticket | Work | Gate |
|---|---|---|
| U01 | Capture DPI single-scenario and IPI multi-scenario browser screenshots, interactions, responsive states and current discrepancies | Reference evidence approved for comparison; source findings distinguished from rendered evidence |
| U02 | Extract tokens and button/status/objective primitives; build component gallery | No unexplained visual change in the two reference pages; keyboard, contrast and reduced-motion checks |
| U03 | Two template shells, scenario navigation/state boundaries, workflow slots, chat/help/reset controllers and typed definition schema | All documented states/reset scopes covered; existing polling/ownership protections retained |
| U04 | Migrate DPI and IPI as reference consumers | Chat/RAG/email behavior, independent help gates, reset and dashboard parity pass |
| U05 | Retrofit remaining workshop pages incrementally | Page-specific migration inventory, allowed intentional differences, specialized tool views preserved |
| U06 | Future-exercise generator, author guide and contract checks | A fixture for each template created through the baseline; multi-scenario fixture proves independent workflows/state/reset without custom core chat/reset/button code |

Upgrade build tooling/runtime dependencies in separate PRs from visual standardization so library-default changes are distinguishable from planned UX changes. Token extraction can precede the upgrade; components must be validated again on the final React/router/motion/markdown versions. PostgreSQL migration and agent orchestration changes likewise retain independent contract gates.

Test browser widths including 375, 768, 1024 and 1440px; keyboard navigation, modal focus/escape/restore, textarea composition, long prompts/tool output, empty/loading/error/completed states, disabled objectives, all four Hint/Solution combinations, reset races and two attendees. For multi-scenario workshops, switch scenarios during a slow run, revisit a previous scenario, reset one scenario, hide a scenario live, and verify sibling state and aggregate progress stay correct. Target WCAG AA behavior and verify contrast rather than assuming the source palette passes. Do not claim screenshot or accessibility validation has already occurred.

All three student dashboards must agree on DB-derived objective totals, completions and time. Both admin surfaces must remain synchronized for exercise, hint and solution visibility; hints and solutions remain independent. Existing silent HTTP reconciliation and stale-response protection are baseline requirements, not optional per-page implementations.

Completion means all future exercises use this baseline contract, DPI/IPI work as reference implementations, and existing workshop differences have a planned or completed disposition. It does not mean identical layouts for chat, document upload and email; it means consistent controls, appearance and behavior within the right workspace for the task.
