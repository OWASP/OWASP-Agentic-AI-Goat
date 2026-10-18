# Frontend: Workshop Platform

## Composition root

`client/src/index.js` renders `App` in React strict mode. `App.js` provides the
workshop `AuthProvider`, browser router, and error boundary. `AppContent`
branches by URL:

- paths beginning `/secureshop` render the SecureShop application;
- all other paths render `WorkshopApp`.

Routes are lazy-loaded except the landing/auth shell and structural providers.
Changing `location.pathname` increments a key that remounts the selected app;
state stored only inside page components is therefore navigation-sensitive.

## Workshop route families

| UI path | Component | Guard/notes |
|---|---|---|
| `/` | `LandingPage` or dashboard redirect | public; reads public feature flags |
| `/workshop/login`, `/workshop/signup` | auth pages | public; legacy aliases redirect here |
| `/workshop-dashboard` | `WorkshopDashboard` | authenticated overview and time totals |
| `/workshop/challenges` | `WorkshopChallenges` | authenticated per-exercise/objective detail |
| `/workshop/profile`, `/workshop/edit-profile`, `/workshop/user-activity` | profile/activity pages | authenticated |
| `/workshop/sql`, `/workshop/nosql` | ARIA/NOVA labs | authenticated |
| `/workshop/sensitive-info`, `/workshop/supply-chain` | modern workshops | authenticated; supply-chain visibility-gated |
| `/vulnerabilities/*` | six challenge pages | authenticated and `VisibilityProtectedRoute` guarded |
| `/ctf`, `/ctf/challenge`, `/ctf/leaderboard` | CTF pages | authenticated; CTF has its own config/status model |
| `/admin/*` | `ComprehensiveAdminDashboard` | admin role/level checked client-side and server-side |
| `/ecommerce/*` | legacy AI assistant and inline challenge placeholders | authenticated |

`/workshop/progress` now redirects to `/workshop-dashboard`. Progress overview
and detailed objectives were consolidated in the August 2026 refresh.

## Shared state and cross-cutting components

| File | Responsibility |
|---|---|
| `context/AuthContext.js` | localStorage token/user, status hydration, login/register/logout, token expiry |
| `context/ShopAuthContext.js` | legacy SecureShop auth context retained around the new SecureShop branch |
| `components/ErrorBoundary.js` | catches rendering failures and offers reset/reload diagnostics |
| `components/WorkshopNavbar.js` | user/admin navigation, visible exercise list, CTF config, logout |
| `components/VisibilityProtectedRoute.js` | checks the server-provided challenge catalog before rendering |
| `components/VulnerabilityTemplate.js` | common workshop layout, objectives, hints, completion controls |
| `components/HintPanel.js` | requests a specific visible hint and expands/collapses it |
| `components/SolutionPanel.js` | requests a specific visible solution and expands/collapses it |
| `hooks/useChangePolling.js` | authenticated revision polling with one baseline reconciliation, then refetch only on relevant change |
| `services/revisionPoller.js` | receiver-safe browser timers, canonical snapshot comparison, 15-second cadence, jitter, inactive-tab deferral, bounded failure backoff |
| `hooks/useWorkshopHeartbeat.js` | sends activity heartbeats only while the user is active |

`VisibilityProtectedRoute` and `VulnerabilityTemplate` both fetch
`/api/workshop/challenges`; keep their assumptions aligned with the canonical
catalog returned by `server/routes/workshop.js`.

Open Direct PI, Indirect PI, XSS, CSRF, MCP, Excessive Agency, SQL, NoSQL,
Sensitive Info, and Supply Chain lab tabs subscribe to their own workshop
revision. Their polling callbacks reconcile persisted mode and/or
admin-controlled hint and solution visibility without reloading unrelated lab
data.

## Main platform pages

| File | Reads/writes | Functionality |
|---|---|---|
| `LandingPage.js` | `/api/auth/feature-flags` | marketing landing and SecureShop visibility toggle |
| `WorkshopLogin.js` | AuthContext, captcha/signup config | combined sign-in/registration surface |
| `WorkshopSignup.js` | register/captcha/signup config | standalone validated registration form |
| `WorkshopDashboard.js` | workshop challenges, reset, time summary, scoped polling | overview cards, completion, elapsed time, reset |
| `WorkshopChallenges.js` | workshop challenges, per-challenge hint status | detailed cards, objectives, hints/solutions |
| `UserProfile.js` | auth profile | profile/stat display and update |
| `EditProfile.js` | auth profile | edit form; username remains immutable server-side |
| `UserActivity.js` | workshop progress/activity, scoped polling | activity timeline and progress |

## Admin frontend

`ComprehensiveAdminDashboard.js` is a 7.2k-line integration component. It owns
navigation state, data loading, mutations, modal state, and most rendering for:

- dashboard KPIs;
- students, locked users, account/password operations;
- exercise, objective, hint, and solution visibility/content;
- activity and progress analytics;
- security/system settings and DB reset/initialize;
- LLM health;
- delegated CTF, provider, logs, and student-workshop panels.

Route-to-section selection is derived from pathname inside
`getActiveSectionFromPath`; the same component renders for most `/admin/*`
paths. Important extracted children are:

| File | Scope |
|---|---|
| `components/admin/AIProviderManagement.js` | provider inventory, configuration, switching, connection tests, stats |
| `components/admin/ServerLogs.js` | application/LLM logs, filters, stats, download |
| `components/admin/StudentWorkshopView.js` | per-student workshop/progress drill-down and reset |
| `pages/admin/CTFAdminPanel.js` | CTF config, stages, solutions, attempts, participants, blocklists, reset |
| `pages/admin/ProgressAnalyticsPanel.js` | overview/challenge/student/time/difficulty analytics |

Best future split: a route/section shell, one query/mutation hook per admin
domain, one view component per domain, and a small modal package. Do not split
only by JSX chunks while leaving one shared state object; that retains the same
coupling.

## Workshop page modules

The detailed backend/service relationships live in
`03-workshops-and-ctf.md`. Frontend ownership is:

| Page | UX model |
|---|---|
| `DirectPromptInjectionChallenge.js` | objective-guided chat, conversation reset, hint/solution panels |
| `IndirectPromptInjectionChallenge.js` | RAG upload/query plus email-agent/SharkLasers flows |
| `XSSWorkshop.js` | reflected, stored/profile, LLM-generated, and email XSS tabs |
| `CSRFWorkshop.js` | victim sandbox, payload builder, email/RAG vectors, defenses |
| `MCPWorkshop.js` | tool catalog, JSON-RPC inspector, chat, activity/exfil views |
| `ExcessiveAgencyBolaLab.js` | lab login, vulnerable/fixed mode, tool/chat/audit/progress |
| `SQLWorkshop.js` | ARIA chat, vulnerable/fixed query mode, objectives |
| `NoSQLWorkshop.js` | NOVA chat, operator-injection mode, objectives |
| `SensitiveInfoWorkshop.js` | FinFlow chat and structured tool-result cards |
| `SupplyChainWorkshop.js` | CodeBot tool toggles, chat, solution/hint controls |
| `CTFDashboard.js` | enrollment, stage locks, aggregate progress |
| `CTFChallenge.js` | stage start/attempt/hint conversation |
| `CTFLeaderboard.js` | visibility-aware 30-second HTTP polling leaderboard and podium |
| `labs/AIAssistant.js` | legacy natural-language e-commerce vulnerability demo |

All five interactive vulnerable/fixed lab pages subscribe to their workshop
and the authenticated attendee's private mode revision. A second tab for the
same attendee reconciles automatically; another attendee's toggle is filtered
out by the revision API. Chat responses also correct the local badge from the
server's authoritative execution mode.
For ARIA, NOVA, Excessive Agency, FinFlow, and CodeBot, that same scoped
callback reloads the lab's admin-controlled solution status; CodeBot also
reloads its separately gated hint status. An active lab therefore does not
consume a visibility revision while leaving its controls stale.

## API conventions

- Most platform requests use Axios and relative `/api` URLs, relying on the CRA
  proxy locally and same-origin Express static hosting in production.
- AuthContext sends a bearer token and retains a user object in localStorage.
- Several pages independently build auth headers from localStorage; changing
  token shape requires a repository-wide search, not only AuthContext changes.
- Long-running LLM calls must honor the proxy timeouts and loading/reset UX.
- Workshop pages frequently perform optimistic local progress updates followed
  by authoritative refresh; preserve idempotent completion APIs.

## Styling

The workshop application mainly uses `styled-components`, inline styles,
Framer Motion, Lucide/React Icons, and global `index.css`. SecureShop has its
own `theme.css` and component primitives. Avoid leaking SecureShop CSS tokens
into the workshop shell without verifying global selectors.

## Frontend change checklist

For any new/renamed workshop route, update together:

1. `App.js` lazy import and route.
2. `WorkshopNavbar.js` and server-visible challenge metadata.
3. `WorkshopDashboard.js` / `WorkshopChallenges.js` assumptions.
4. `VisibilityProtectedRoute` challenge key.
5. backend route mount and solution/hint endpoints.
6. admin exercise/objective/solution mappings.
7. frontend and API tests.
