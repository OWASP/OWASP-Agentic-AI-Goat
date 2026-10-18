# Workshop Polling and Reliability Changes

## Colleague handoff and verification guide

**Repository:** Damn Vulnerable AI Application (DVAIA)

**Feature branch:** `cc-no-websocket`

**Feature commit:** `7f8495c`

**Merged to `main`:** `16e9790`
**Scope:** Workshop application only. Secure Shop is intentionally excluded.

## Purpose

The Workshop previously depended on live WebSocket messages to propagate
administrator changes. That communication was unreliable when several
attendees were connected at the same time.

Workshop state is now persisted in the database. The browser performs a small
periodic revision check and fetches full Workshop data only when a relevant
revision has changed. Administrator configuration changes reach every
applicable attendee, while attendee-owned progress, mode, chat, simulator, and
reset state remain isolated by user.

This guide explains what changed and how to verify it manually and with the
automated test suite.

## Expected propagation rules

| Change | Who should receive it? |
|---|---|
| Administrator enables/disables an exercise | All attendees |
| Administrator enables/disables an objective | All attendees in that workshop |
| Administrator changes hint or solution visibility | All applicable attendees |
| Attendee changes vulnerable/secure mode | Only that attendee and workshop |
| Attendee completes or resets progress | Only that attendee |
| Attendee sends chat messages or changes simulator state | Only that attendee |
| Administrator resets a selected attendee | Only the selected attendee |

## Polling behavior

- Workshop WebSocket runtime communication has been removed.
- Changes are persisted before their revision is published.
- The normal visible-tab revision interval is approximately 12 seconds and is
  capped at 15 seconds.
- The browser requests full configuration only after a relevant revision
  changes.
- Global revisions are used for broadly applicable administrator changes.
- Workshop revisions are used for changes limited to one exercise.
- User revisions are used for progress, resets, and other attendee-owned state.
- Hidden tabs pause ordinary polling.
- Overlapping checks are prevented.
- Late responses cannot replace newer state.
- Transient failures retain the last confirmed state and retry later.
- Repeated reconciliation timeouts use bounded backoff.

## Changes by segment

### 1. Exercise visibility and navigation

- Disabled exercises are removed from the attendee dashboard and navigation.
- Direct URL access is protected after an exercise is disabled.
- SQL, NoSQL, and the primary Sensitive Information route now use the same
  visibility protection as other Workshop routes.
- Exercises with no enabled objectives are displayed as locked.
- Locked exercises do not provide a dashboard navigation action.
- Locked exercises remain absent from the navbar after its background refresh.

### 2. Objective visibility

Canonical objective visibility now controls:

- rendered objective cards and tabs;
- active-objective selection;
- progress totals and completion banners;
- hint and solution availability;
- pending or open solution modals;
- server-returned objective metadata where applicable.

This behavior is implemented for Indirect Prompt Injection, XSS, CSRF, MCP,
Excessive Agency, SQL, NoSQL, Sensitive Information, and Supply Chain.

### 3. Hints and solutions

- Hints and solutions are independently controlled.
- Enabling solutions does not implicitly expose disabled hints.
- Disabling a disclosure invalidates pending requests and closes stale content.
- Supply Chain solution-modal hints follow the independent objective hint gate.
- Sensitive Information progressive hints also follow their independent gate.

### 4. Vulnerable and secure mode

- Mode is persisted per attendee and per workshop.
- Refreshing or logging back in does not silently switch mode.
- One attendee's mode change does not affect another attendee.
- Client requests cannot select another attendee's identity or stored mode.

### 5. Attendee isolation

The following state is attendee-owned:

- SQL and NoSQL progress, fallback caches, chat, drafts, loading state, message
  IDs, and solution modals;
- Sensitive Information files, backups, deletion state, logs, simulator state,
  and operation ordering;
- MCP progress, tool activity, sandbox, and listener ownership;
- XSS identity, local progress, email progress, and reset ownership;
- Excessive Agency's complete five-persona mutable graph, conversations,
  progress, and destructive exercise targets;
- general Workshop progress and completion state.

### 6. Student and administrator resets

The dashboard reset now delegates to the authoritative owner for each workshop
instead of reporting success after only generic progress is removed.

- Supply Chain clears local and central progress.
- Sensitive Information clears FinFlow progress, tool logs, auxiliary rows,
  central progress, and attendee simulator state.
- MCP clears attendee progress, activity, central progress, and the attendee's
  sandbox/listener state.
- Indirect Prompt Injection clears progress and the attendee's current RAG
  document session.
- CSRF retains its wallet and tool-log reset behavior while clearing canonical
  progress correctly.
- Excessive Agency's in-lab reset reseeds only the current platform attendee's
  five-persona graph. The generic dashboard still provides an explicit message
  directing the attendee to that authoritative **Reset Progress** control.

### 7. Workshop-specific server enforcement

- CSRF hidden objectives cannot be credited through old payloads. Visible-only
  prerequisites, payload state, solutions, and tab reset use the canonical
  objective set.
- MCP hidden objectives are excluded from chat scoring, progress responses, and
  manual recon completion.
- Excessive Agency progress metadata, flags, counts, totals, and completion
  timestamps are filtered through effective objective visibility.
- The attendee activity timeline excludes disabled exercises and objectives
  while preserving visible MCP activity through its canonical alias.

## Manual verification setup

1. From the repository root, start the application:

   ```bash
   ./start_all.sh
   ```

2. Open `http://localhost:3000`.
3. Use three separate browser sessions or profiles:

   - administrator: `admin / admin123`;
   - Attendee A: for example `student_1`;
   - Attendee B: for example `student_2`.

   The default local workshop-student password is normally `Workshop2026!`.
   Use environment-specific credentials if the local database was seeded with
   different values.

4. Keep attendee tabs visible during propagation checks.
5. Allow up to 15 seconds for an ordinary polling update.
6. Restore administrator toggles after each scenario.

## Manual verification checklist

### A. Confirm WebSocket removal and durable polling

- [ ] Open Developer Tools and select the Network panel.
- [ ] Filter by `WS` and navigate between Workshop pages.
- [ ] Confirm no Workshop WebSocket connection appears.
- [ ] Filter requests by `change-revisions`.
- [ ] Confirm small revision requests occur periodically.
- [ ] Change an exercise or objective setting as administrator.
- [ ] Confirm the attendee fetches updated configuration after the revision
      changes.
- [ ] Refresh the attendee page and confirm the new state remains.
- [ ] Restart the application and confirm the administrator setting remains.

### B. Verify exercise enable/disable propagation

- [ ] Open `/admin/exercises` as administrator.
- [ ] Open the same enabled exercise as Attendee A and Attendee B.
- [ ] Disable the exercise.
- [ ] Within 15 seconds, confirm both attendees receive the disabled state or
      are redirected.
- [ ] Confirm the exercise is unavailable on `/workshop-dashboard`.
- [ ] Paste its direct URL into an attendee browser and confirm access is
      blocked.
- [ ] Refresh and confirm direct access remains blocked.
- [ ] Re-enable the exercise and confirm it returns for both attendees.

Representative routes:

- `/workshop/sql`
- `/workshop/nosql`
- `/workshop/sensitive-info`
- `/workshop/supply-chain`
- `/vulnerabilities/xss`
- `/vulnerabilities/csrf-via-ai`
- `/vulnerabilities/indirect-prompt-injection`
- `/vulnerabilities/mcp-server`
- `/vulnerabilities/excessive-agency`

### C. Verify objective enable/disable propagation

- [ ] Note the current objective count in an attendee workshop.
- [ ] Select an objective and open its solution if permitted.
- [ ] Disable that objective as administrator.
- [ ] Confirm the objective disappears within 15 seconds.
- [ ] Confirm the progress denominator decreases.
- [ ] Confirm selection moves to another visible objective when necessary.
- [ ] Confirm an open or pending solution for the hidden objective closes.
- [ ] Refresh and confirm the objective remains absent.
- [ ] Re-enable it and confirm it returns without altering other objectives.

Repeat with representative objectives in Indirect Prompt Injection, XSS, CSRF,
MCP, Excessive Agency, Sensitive Information, Supply Chain, SQL, and NoSQL.

### D. Verify zero-objective locking

- [ ] Leave an exercise enabled.
- [ ] Disable every objective in that exercise.
- [ ] Confirm the dashboard shows the exercise as locked.
- [ ] Confirm its action is not clickable.
- [ ] Confirm it is absent from the Workshop navbar.
- [ ] Wait at least 60 seconds and confirm navbar background polling does not
      restore a clickable link.
- [ ] Re-enable one objective and confirm normal navigation returns.

### E. Verify independent hint and solution controls

For one representative objective, test this matrix:

| Hints | Solutions | Expected result |
|---|---|---|
| Off | Off | Neither disclosure is available |
| On | Off | Hints are available; solution is unavailable |
| Off | On | Solution is available; progressive hints remain absent |
| On | On | Both disclosures are available |

Additional checks:

- [ ] Open a solution, then disable hints.
- [ ] Confirm permitted solution content remains but progressive hints disappear.
- [ ] Perform the hints-off/solutions-on check in Supply Chain.
- [ ] Perform the same check in Sensitive Information.

### F. Verify mode persistence and isolation

- [ ] Open the same mode-enabled lab as Attendee A and Attendee B.
- [ ] Set Attendee A to vulnerable mode.
- [ ] Set Attendee B to secure/fixed mode.
- [ ] Refresh both sessions and confirm each mode remains unchanged.
- [ ] Perform the same action in both sessions and confirm mode-specific behavior.
- [ ] Change Attendee A's mode and confirm Attendee B is unaffected.
- [ ] Log Attendee A out and back in and confirm the stored mode returns.

### G. Verify cross-attendee isolation

- [ ] Complete an objective as Attendee A.
- [ ] Confirm Attendee B remains incomplete.
- [ ] Send a distinctive SQL or NoSQL chat message as Attendee A.
- [ ] Confirm it never appears in Attendee B's UI.
- [ ] Leave a draft as Attendee A and switch authenticated identity.
- [ ] Confirm the first render for Attendee B contains no prior chat or draft.
- [ ] Modify Sensitive Information simulator data as Attendee A.
- [ ] Confirm Attendee B retains independent simulator state.
- [ ] Make an administrator visibility change and confirm it reaches both users.

### H. Verify attendee reset ownership

- [ ] Give Attendee A and Attendee B different progress.
- [ ] Generate workshop-specific state for Attendee A.
- [ ] Reset only Attendee A.
- [ ] Refresh both sessions.
- [ ] Confirm Attendee A's progress and workshop-owned state are cleared.
- [ ] Confirm Attendee B's progress and state remain intact.
- [ ] Repeat for Supply Chain, Sensitive Information, MCP, Indirect Prompt
      Injection, and CSRF.
- [ ] For Excessive Agency, confirm the dashboard directs the attendee to the
      in-lab reset rather than reporting a false server-side reset.

### I. Verify stale-response protection

- [ ] Use Developer Tools to throttle the network.
- [ ] Begin opening one objective's solution.
- [ ] Switch objectives before the request completes.
- [ ] Confirm the old solution does not appear under the new objective.
- [ ] Begin opening a solution and disable it as administrator while loading.
- [ ] Confirm loading clears and the late response does not reopen the modal.
- [ ] Re-enable the disclosure and confirm normal same-objective behavior still
      works.

### J. Verify CSRF and MCP server enforcement

#### CSRF

- [ ] Disable an objective and repeat its previously valid payload.
- [ ] Confirm the hidden objective is not credited.
- [ ] Disable solutions and confirm the working payload solution is unavailable.
- [ ] Use **Reset tab**, refresh, and confirm canonical completion stays reset.

#### MCP

- [ ] Disable an objective and repeat its scoring or recon action.
- [ ] Confirm the hidden objective is not credited.
- [ ] Confirm progress totals exclude the hidden objective.
- [ ] Reset Attendee A and confirm Attendee B's MCP activity remains intact.

Real MCP tool-effect checks require the optional MCP sidecars to be running.

### K. Verify Excessive Agency and User Activity filtering

- [ ] Complete an Excessive Agency objective.
- [ ] Disable that objective as administrator.
- [ ] Confirm it no longer appears or counts after polling/refresh.
- [ ] Open `/workshop/user-activity`.
- [ ] Confirm the disabled completion is absent.
- [ ] Complete a visible MCP objective and confirm its activity appears normally.

## Automated verification

### Frontend tests and production build

```bash
cd client
npm test -- --watchAll=false --runInBand
npm run build
```

Expected frontend result:

```text
Test Suites: 20 passed, 20 total
Tests:       180 passed, 180 total
```

The production build should complete successfully. Existing repository lint and
Browserslist warnings are not release blockers for this Workshop change.

### Focused Workshop server tests

From the repository root:

```bash
node --test \
  tests/workshopObjectiveVisibilityConsumers.test.js \
  tests/workshopRouteVisibilityWiring.test.js \
  tests/adminWorkshopResetService.test.js \
  tests/frontendPollingCoverage.test.js \
  tests/noApplicationWebSocket.test.js \
  tests/noVisibilityWebSocket.test.js \
  tests/legacyWebSocketRetirement.test.js
```

Identity and Sensitive Information checks:

```bash
node --test tests/xssWorkshopIdentity.test.js
node --test tests/sensitiveInfoWorkshop.test.js
```

## Verification results recorded before merge

- Full frontend suite: 180/180.
- Sequential Workshop backend group: 242/242.
- Sensitive Information internal checks: 344 passed, 0 failed, 2 environment
  skips.
- XSS identity HTTP integration: 9/9.
- Objective visibility and route contract group: 13/13.
- Production React build: successful.
- Three independent blind devil's-advocate reviews found no remaining
  deterministic major ordinary-demo issue.

## Accepted recoverable or excluded conditions

- A transient polling failure retains the last confirmed UI and is recoverable
  by refresh or the next successful poll.
- Provider, LLM, AWS, network, or optional MCP sidecar outages are infrastructure
  conditions and were not treated as Workshop application regressions.
- Existing React development warnings and stale Browserslist metadata are
  outside this change's major-demo threshold.
- Minor UI residue recoverable by refresh or a normal administrator toggle was
  intentionally not expanded into broad refactoring.
- Conditions requiring more than four hours to reproduce were outside the
  agreed release gate.
- Secure Shop was explicitly excluded.

## Supporting documentation

- `docs/code-map/README.md` — modular documentation index.
- `docs/code-map/03-workshops-and-ctf.md` — Workshop module relationships.
- `docs/code-map/12-sensitive-info-state-isolation.md` — Sensitive state model.
- `docs/code-map/13-xss-workshop-identity.md` — XSS identity ownership.
- `docs/code-map/14-visibility-route-state.md` — route visibility behavior.
- `docs/code-map/15-sql-nosql-progress-cache.md` — SQL/NoSQL attendee ownership.
- `docs/code-map/16-polling-load-safeguards.md` — polling safeguards.
- `docs/code-map/17-student-dashboard-reset-ownership.md` — reset ownership.
- `docs/code-map/18-workshop-reliability-change-ledger.md` — complete change and
  verification ledger.
